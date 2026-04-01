package ui

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/mariamills/burrow/internal/model"
	"github.com/mariamills/burrow/internal/session"
	"github.com/mariamills/burrow/internal/store"
	"github.com/mariamills/burrow/internal/user"
)

func setup(t *testing.T) (*Handler, *user.Service, *session.Service) {
	t.Helper()
	db, err := store.New(":memory:")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	userSvc := user.New(db, db)
	sessionSvc := session.New(db, db)

	h, err := New(db, userSvc, sessionSvc)
	if err != nil {
		t.Fatalf("ui.New: %v", err)
	}
	return h, userSvc, sessionSvc
}

func TestLoginPage_Renders(t *testing.T) {
	h, _, _ := setup(t)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest("GET", "/ui/login", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Errorf("status = %d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Burrow") {
		t.Error("login page should contain 'Burrow'")
	}
	if !strings.Contains(w.Body.String(), "Sign In") {
		t.Error("login page should contain 'Sign In'")
	}
}

func TestLoginSubmit_Success(t *testing.T) {
	h, userSvc, _ := setup(t)

	// Create a user to login with.
	userSvc.Register(&model.RegisterRequest{
		Email: "alice@example.com", Password: "strongpassword123",
	})

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	// First, GET the login page to get a CSRF token.
	getReq := httptest.NewRequest("GET", "/ui/login", nil)
	getW := httptest.NewRecorder()
	mux.ServeHTTP(getW, getReq)

	// Extract CSRF token from cookie.
	var csrfToken string
	for _, c := range getW.Result().Cookies() {
		if c.Name == "burrow_csrf" {
			csrfToken = c.Value
		}
	}

	form := url.Values{}
	form.Set("email", "alice@example.com")
	form.Set("password", "strongpassword123")
	form.Set("csrf_token", csrfToken)

	req := httptest.NewRequest("POST", "/ui/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "burrow_csrf", Value: csrfToken})
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	// Should redirect to dashboard.
	if w.Code != 302 {
		t.Errorf("status = %d, want 302 redirect", w.Code)
	}
	loc := w.Header().Get("Location")
	if loc != "/ui/dashboard" {
		t.Errorf("redirect location = %q, want /ui/dashboard", loc)
	}

	// Should set session cookie.
	cookies := w.Result().Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == "burrow_session" && c.Value != "" {
			found = true
			if !c.HttpOnly {
				t.Error("session cookie should be HttpOnly")
			}
		}
	}
	if !found {
		t.Error("session cookie should be set")
	}
}

func TestLoginSubmit_InvalidCredentials(t *testing.T) {
	h, _, _ := setup(t)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	form := url.Values{}
	form.Set("email", "nobody@example.com")
	form.Set("password", "wrongpassword")

	req := httptest.NewRequest("POST", "/ui/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Errorf("status = %d, want 200 (re-render login with error)", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Invalid") {
		t.Error("should show error message")
	}
}

func TestDashboard_RequiresAuth(t *testing.T) {
	h, _, _ := setup(t)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest("GET", "/ui/dashboard", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	// Should redirect to login.
	if w.Code != 302 {
		t.Errorf("status = %d, want 302 redirect to login", w.Code)
	}
	loc := w.Header().Get("Location")
	if loc != "/ui/login" {
		t.Errorf("redirect = %q, want /ui/login", loc)
	}
}

func TestStaticAssets_Served(t *testing.T) {
	h, _, _ := setup(t)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest("GET", "/ui/static/css/style.css", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Errorf("status = %d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), "--bg:") {
		t.Error("should serve CSS content")
	}
}
