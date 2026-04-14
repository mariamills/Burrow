// Package ui provides the server-rendered web interface for Burrow using Go
// templates and HTMX for dynamic interactions.
//
// All UI routes are under /ui/ and return HTML. API routes under /v1/ return JSON.
// The UI authenticates via session cookies (set during login).
package ui

import (
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"html/template"
	"io/fs"
	"net/http"

	"github.com/mariamills/burrow/internal/domain"
	"github.com/mariamills/burrow/internal/middleware"
	"github.com/mariamills/burrow/internal/session"
	"github.com/mariamills/burrow/internal/user"
	"github.com/mariamills/burrow/pkg/logger"
)

//go:embed templates/* static/*
var content embed.FS

// Handler serves the web UI.
type Handler struct {
	templates *template.Template
	store     UIStore
	users     *user.Service
	sessions  *session.Service
}

// UIStore combines the store interfaces needed by the UI
type UIStore interface {
	domain.SecretStore
	domain.AuditStore
	domain.TokenStore
	domain.UserStore
	domain.GroupStore
}

// New creates a new UI Handler and parses all templates
func New(store UIStore, users *user.Service, sessions *session.Service) (*Handler, error) {
	tmpl, err := template.ParseFS(content, "templates/layout.html", "templates/pages/*.html")
	if err != nil {
		return nil, err
	}
	return &Handler{
		templates: tmpl,
		store:     store,
		users:     users,
		sessions:  sessions,
	}, nil
}

// RegisterRoutes adds all UI routes to the given mux
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	// Static assets (CSS, JS) - no auth required.
	staticFS, _ := fs.Sub(content, "static")
	mux.Handle("GET /ui/static/", http.StripPrefix("/ui/static/", http.FileServer(http.FS(staticFS))))

	// Landing page at root.
	mux.HandleFunc("GET /", h.landingPage)

	// Login page - no auth required
	mux.HandleFunc("GET /ui/login", h.loginPage)
	mux.HandleFunc("POST /ui/login", h.loginSubmit)
	mux.HandleFunc("POST /ui/logout", h.logout)

	// Protected pages - require session cookie.
	mux.HandleFunc("GET /ui/dashboard", h.requireAuth(h.dashboardPage))
	mux.HandleFunc("GET /ui/secrets", h.requireAuth(h.secretsPage))
	mux.HandleFunc("GET /ui/secrets/{namespace}", h.requireAuth(h.secretsPage))
	mux.HandleFunc("GET /ui/secrets/{namespace}/search", h.requireAuth(h.secretsSearch))
	mux.HandleFunc("GET /ui/audit", h.requireAuth(h.auditPage))

	// Redirect /ui/ to /ui/dashboard
	mux.HandleFunc("GET /ui/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/ui/dashboard", http.StatusFound)
	})
	mux.HandleFunc("GET /ui", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/ui/dashboard", http.StatusFound)
	})
}

// requireAuth wraps a handler to require a valid session cookie
func (h *Handler) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("burrow_session")
		if err != nil || cookie.Value == "" {
			http.Redirect(w, r, "/ui/login", http.StatusFound)
			return
		}

		sess, err := h.sessions.Validate(cookie.Value)
		if err != nil || sess == nil {
			http.SetCookie(w, &http.Cookie{Name: "burrow_session", MaxAge: -1, Path: "/"})
			http.Redirect(w, r, "/ui/login", http.StatusFound)
			return
		}

		// Set CSRF cookie for authenticated pages (used by logout form)
		csrfToken := generateCSRFToken()
		isSecure := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
		http.SetCookie(w, &http.Cookie{
			Name: "burrow_csrf", Value: csrfToken, Path: "/ui/",
			HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: isSecure,
		})

		// Store CSRF token for template rendering
		r.Header.Set("X-Burrow-CSRF", csrfToken)

		next(w, r)
	}
}

// csrfFromRequest extracts the CSRF token set by requireAuth
func csrfFromRequest(r *http.Request) string {
	return r.Header.Get("X-Burrow-CSRF")
}

// render executes a template with the layout.
func (h *Handler) render(w http.ResponseWriter, name string, data map[string]interface{}) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.templates.ExecuteTemplate(w, name, data); err != nil {
		logger.Error("template render failed", "template", name, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// ── PAGE HANDLERS ────────────────────────────────────────────────────────────

func (h *Handler) landingPage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	h.render(w, "landing.html", nil)
}

func (h *Handler) loginPage(w http.ResponseWriter, r *http.Request) {
	csrfToken := generateCSRFToken()
	isSecure := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
	http.SetCookie(w, &http.Cookie{
		Name: "burrow_csrf", Value: csrfToken, Path: "/ui/",
		HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: isSecure,
	})
	h.render(w, "login.html", map[string]interface{}{"CSRFToken": csrfToken})
}

func generateCSRFToken() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func (h *Handler) loginSubmit(w http.ResponseWriter, r *http.Request) {
	// Validate CSRF token (double-submit cookie pattern)
	// Generate a fresh CSRF token for any re-render.
	newCSRF := generateCSRFToken()
	isSecure := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
	http.SetCookie(w, &http.Cookie{
		Name: "burrow_csrf", Value: newCSRF, Path: "/ui/",
		HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: isSecure,
	})

	csrfCookie, err := r.Cookie("burrow_csrf")
	csrfForm := r.FormValue("csrf_token")
	if err != nil || csrfCookie.Value == "" || subtle.ConstantTimeCompare([]byte(csrfCookie.Value), []byte(csrfForm)) != 1 {
		h.render(w, "login.html", map[string]interface{}{"Error": "Invalid request. Please try again.", "CSRFToken": newCSRF})
		return
	}

	email := r.FormValue("email")
	password := r.FormValue("password")

	u, err := h.users.Authenticate(email, password)
	if err != nil || u == nil {
		h.render(w, "login.html", map[string]interface{}{
			"Error":     "Invalid email or password",
			"CSRFToken": newCSRF,
		})
		return
	}

	resp, err := h.sessions.Create(u.ID, middleware.RealIP(r), r.UserAgent())
	if err != nil {
		h.render(w, "login.html", map[string]interface{}{
			"Error":     "Failed to create session",
			"CSRFToken": newCSRF,
		})
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "burrow_session",
		Value:    resp.Token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   isSecure,
	})

	http.Redirect(w, r, "/ui/dashboard", http.StatusFound)
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	// Validate CSRF token.
	csrfCookie, csrfErr := r.Cookie("burrow_csrf")
	csrfForm := r.FormValue("csrf_token")
	if csrfErr != nil || csrfCookie.Value == "" || subtle.ConstantTimeCompare([]byte(csrfCookie.Value), []byte(csrfForm)) != 1 {
		http.Redirect(w, r, "/ui/login", http.StatusFound)
		return
	}

	cookie, err := r.Cookie("burrow_session")
	if err == nil && cookie.Value != "" {
		sess, _ := h.sessions.Validate(cookie.Value)
		if sess != nil {
			h.sessions.Destroy(sess.ID)
		}
	}
	http.SetCookie(w, &http.Cookie{Name: "burrow_session", MaxAge: -1, Path: "/"})
	http.Redirect(w, r, "/ui/login", http.StatusFound)
}

func (h *Handler) dashboardPage(w http.ResponseWriter, r *http.Request) {
	namespaces, _ := h.store.ListNamespaces()
	tokens, _ := h.store.ListTokens()
	users, _ := h.store.ListUsers()
	groups, _ := h.store.ListGroups()
	audit, _ := h.store.GetAuditLog("", 10)

	nsCount := 0
	if namespaces != nil {
		nsCount = len(namespaces)
	}
	tokenCount := 0
	if tokens != nil {
		tokenCount = len(tokens)
	}
	userCount := 0
	if users != nil {
		userCount = len(users)
	}
	groupCount := 0
	if groups != nil {
		groupCount = len(groups)
	}

	h.render(w, "layout.html", map[string]interface{}{
		"Title":          "Dashboard",
		"Active":         "dashboard",
		"CSRFToken":      csrfFromRequest(r),
		"NamespaceCount": nsCount,
		"TokenCount":     tokenCount,
		"UserCount":      userCount,
		"GroupCount":     groupCount,
		"RecentAudit":    audit,
	})
}

func (h *Handler) secretsPage(w http.ResponseWriter, r *http.Request) {
	namespace := r.PathValue("namespace")

	data := map[string]interface{}{
		"Title":     "Secrets",
		"Active":    "secrets",
		"CSRFToken": csrfFromRequest(r),
	}

	if namespace == "" {
		namespaces, _ := h.store.ListNamespaces()
		if namespaces == nil {
			namespaces = []string{}
		}
		data["Namespaces"] = namespaces
	} else {
		data["Namespace"] = namespace
		secrets, _ := h.store.ListSecrets(namespace)
		data["Secrets"] = secrets
	}

	h.render(w, "layout.html", data)
}

func (h *Handler) secretsSearch(w http.ResponseWriter, r *http.Request) {
	namespace := r.PathValue("namespace")
	q := r.URL.Query().Get("q")

	var results interface{}
	if q != "" {
		results, _ = h.store.SearchSecrets(namespace, q)
	} else {
		results, _ = h.store.ListSecrets(namespace)
	}

	// Return partial HTML for HTMX swap.
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if results == nil {
		w.Write([]byte(`<tr><td colspan="4" class="text-muted">No results</td></tr>`))
		return
	}

	// Render rows inline - namespace is passed as data, never concatenated into template source
	tmpl := `{{range .Secrets}}<tr>
		<td class="mono"><a href="/ui/secrets/{{$.Namespace}}/{{.Key}}">{{.Key}}</a></td>
		<td>{{.Description}}</td>
		<td>{{if .ExpiresAt}}{{.ExpiresAt.Format "2006-01-02"}}{{else}}<span class="text-muted">-</span>{{end}}</td>
		<td class="mono">{{.UpdatedAt.Format "2006-01-02 15:04"}}</td>
	</tr>{{else}}<tr><td colspan="4" class="text-muted">No results</td></tr>{{end}}`

	t, err := template.New("rows").Parse(tmpl)
	if err != nil {
		w.Write([]byte(`<tr><td colspan="4" class="text-muted">Render error</td></tr>`))
		return
	}
	t.Execute(w, map[string]interface{}{
		"Namespace": namespace,
		"Secrets":   results,
	})
}

func (h *Handler) auditPage(w http.ResponseWriter, r *http.Request) {
	events, _ := h.store.GetAuditLog("", 100)
	h.render(w, "layout.html", map[string]interface{}{
		"Title":     "Audit Log",
		"CSRFToken": csrfFromRequest(r),
		"Active":    "audit",
		"Events":    events,
	})
}
