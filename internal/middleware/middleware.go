// Package middleware provides HTTP middleware
package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mariamills/burrow/internal/domain"
	"github.com/mariamills/burrow/internal/model"
	"github.com/mariamills/burrow/pkg/logger"
)

type contextKey string

const (
	TokenContextKey   contextKey = "burrow_token"
	SessionContextKey contextKey = "burrow_session"
	UserIDContextKey  contextKey = "burrow_user_id"
)

// permResolverVal holds the optional permission resolver (set once at startup)
var permResolverVal atomic.Pointer[GroupPermissionResolver]

// SetPermissionResolver configures the group permission resolver for middleware
func SetPermissionResolver(r *GroupPermissionResolver) {
	permResolverVal.Store(r)
}

// getPermResolver returns the current permission resolver (may be nil)
func getPermResolver() *GroupPermissionResolver {
	return permResolverVal.Load()
}

// AUTH MIDDLEWARE

// Auth validates the Bearer token on every request and injects the
// authenticated Token into the request context
//
// Returns 401 if no token is present or invalid.
// Returns 403 if the token doesn't have access to the requested namespace.
func Auth(authSvc domain.Authenticator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rawToken := r.Header.Get("Authorization")
			if rawToken == "" {
				writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Authorization header is required")
				return
			}

			token, err := authSvc.ValidateToken(rawToken)
			if err != nil {
				logger.Warn("auth failure", "ip", realIP(r), "error", err.Error())
				writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Invalid or expired token")
				return
			}

			// Inject the authenticated token and user ID into the request context
			ctx := context.WithValue(r.Context(), TokenContextKey, token)
			if token.ID != "" {
				ctx = context.WithValue(ctx, UserIDContextKey, token.ID)
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequirePermission checks that the authenticated token has the given permission
func RequirePermission(perm string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := TokenFromContext(r.Context())
			if token == nil {
				writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Not authenticated")
				return
			}
			userID, _ := r.Context().Value(UserIDContextKey).(string)
			allowed := false
			if r := getPermResolver(); r != nil {
				allowed = r.HasPermission(token, userID, perm)
			} else {
				allowed = token.HasPermission(perm)
			}
			if !allowed {
				writeError(w, http.StatusForbidden, "FORBIDDEN",
					fmt.Sprintf("Token does not have '%s' permission", perm))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireNamespace checks that the authenticated token (or user's groups) can access
// the namespace extracted from the URL path segment at the given position.
func RequireNamespace(pathPos int) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := TokenFromContext(r.Context())
			if token == nil {
				writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Not authenticated")
				return
			}

			parts := strings.Split(r.URL.Path, "/")
			if len(parts) <= pathPos {
				writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Namespace missing from path")
				return
			}
			namespace := parts[pathPos]

			userID, _ := r.Context().Value(UserIDContextKey).(string)
			allowed := false
			if r := getPermResolver(); r != nil {
				allowed = r.CanAccessNamespace(token, userID, namespace)
			} else {
				allowed = token.CanAccessNamespace(namespace)
			}
			if !allowed {
				writeError(w, http.StatusForbidden, "FORBIDDEN",
					fmt.Sprintf("Token does not have access to namespace '%s'", namespace))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// SessionAuth validates a session token from the X-Session-Token header
// and injects the Session into the request context.
// Returns 401 if no session token is present or invalid
func SessionAuth(sessionSvc domain.SessionValidator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rawToken := r.Header.Get("X-Session-Token")
			if rawToken == "" {
				writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "X-Session-Token header is required")
				return
			}

			sess, err := sessionSvc.Validate(rawToken)
			if err != nil {
				logger.Warn("session auth failure", "ip", realIP(r), "error", err.Error())
				writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Invalid or expired session")
				return
			}

			ctx := context.WithValue(r.Context(), SessionContextKey, sess)
			ctx = context.WithValue(ctx, UserIDContextKey, sess.UserID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// TokenFromContext retrieves the authenticated Token from the request context
func TokenFromContext(ctx context.Context) *model.Token {
	t, _ := ctx.Value(TokenContextKey).(*model.Token)
	return t
}

// SessionFromContext retrieves the authenticated Session from the request context
func SessionFromContext(ctx context.Context) *model.Session {
	s, _ := ctx.Value(SessionContextKey).(*model.Session)
	return s
}

// RealIP extracts the real client IP from a request (exported for use by handlers)
func RealIP(r *http.Request) string {
	return realIP(r)
}

// AUDIT MIDDLEWARE

// Audit logs every request to the audit log table
// It runs after the handler to capture the actual response status code
func Audit(s domain.AuditStore, enabled bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !enabled {
				next.ServeHTTP(w, r)
				return
			}

			// Wrap the ResponseWriter to capture the status code
			rw := &responseWriter{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rw, r)

			// Build the audit event asynchronously.
			token := TokenFromContext(r.Context())
			tokenID, tokenName := "", ""
			if token != nil {
				tokenID = token.ID
				tokenName = token.Name
			}

			// Extract namespace and key from the URL path
			// Split without trimming: ["", "v1", "secrets", "{namespace}", "{key}"]
			parts := strings.Split(r.URL.Path, "/")
			ns, key := "", ""
			if len(parts) > 3 {
				ns = parts[3]
			}
			if len(parts) > 4 {
				key = parts[4]
			}

			action := methodToAction(r.Method, r.URL.Path)

			go func() {
				event := &model.AuditEvent{
					TokenID:    tokenID,
					TokenName:  tokenName,
					Action:     action,
					Namespace:  ns,
					SecretKey:  key,
					StatusCode: rw.status,
					IPAddress:  realIP(r),
					UserAgent:  r.UserAgent(),
					Timestamp:  time.Now(),
				}
				if err := s.WriteAuditEvent(event); err != nil {
					logger.Error("audit write failed", "error", err)
				}
			}()
		})
	}
}

// RATE LIMITER

type rateLimiter struct {
	mu      sync.Mutex
	clients map[string]*clientState
	limit   int
}

type clientState struct {
	count    int
	windowAt time.Time
}

// RateLimit limits requests per IP to limit/minute.
func RateLimit(perMinute int) func(http.Handler) http.Handler {
	rl := &rateLimiter{
		clients: make(map[string]*clientState),
		limit:   perMinute,
	}

	// Cleanup old entries every 5 minutes.
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			rl.mu.Lock()
			cutoff := time.Now().Add(-time.Minute)
			for ip, c := range rl.clients {
				if c.windowAt.Before(cutoff) {
					delete(rl.clients, ip)
				}
			}
			rl.mu.Unlock()
		}
	}()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := realIP(r)
			rl.mu.Lock()
			c, ok := rl.clients[ip]
			now := time.Now()
			if !ok || now.Sub(c.windowAt) > time.Minute {
				rl.clients[ip] = &clientState{count: 1, windowAt: now}
				rl.mu.Unlock()
				next.ServeHTTP(w, r)
				return
			}
			c.count++
			if c.count > rl.limit {
				rl.mu.Unlock()
				w.Header().Set("Retry-After", "60")
				writeError(w, http.StatusTooManyRequests, "RATE_LIMITED",
					fmt.Sprintf("Rate limit exceeded: %d requests/minute allowed", rl.limit))
				return
			}
			rl.mu.Unlock()
			next.ServeHTTP(w, r)
		})
	}
}

// SECURITY HEADERS

// SecureHeaders adds security-relevant HTTP response headers.
func SecureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")

		// UI routes need a permissive CSP for CSS/JS. API routes use strict CSP.
		if strings.HasPrefix(r.URL.Path, "/ui/") || r.URL.Path == "/" {
			w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'")
		} else {
			w.Header().Set("Cache-Control", "no-store") // never cache API responses
			w.Header().Set("Content-Security-Policy", "default-src 'none'")
		}

		next.ServeHTTP(w, r)
	})
}

// CORS

// CORS adds CORS headers for API use.
// Pass an empty string to disable CORS headers entirely (API-only mode).
// Set BURROW_ALLOWED_ORIGINS to a comma-separated list or "*" for browser access.
func CORS(allowedOrigins string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if allowedOrigins != "" {
				origin := allowedOrigins
				// When wildcard is configured, validate the request Origin
				// against it rather than blindly echoing "*" with credentials.
				if allowedOrigins == "*" {
					if reqOrigin := r.Header.Get("Origin"); reqOrigin != "" {
						origin = reqOrigin
					}
				}
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Session-Token")
				w.Header().Set("Access-Control-Max-Age", "86400")
				w.Header().Set("Vary", "Origin")
			}

			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// LOGGING MIDDLEWARE

// Logger logs each incoming request with method, path, status, and duration
func Logger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &responseWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rw, r)
		duration := time.Since(start)

		logger.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rw.status,
			"duration_ms", duration.Milliseconds(),
			"ip", realIP(r),
		)
	})
}

// HELPERS

// responseWriter wraps http.ResponseWriter to capture the status code
type responseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

// trustProxy controls whether X-Forwarded-For and X-Real-IP headers are trusted.
// When false (default), only RemoteAddr is used, preventing IP spoofing for rate limiting.
// Set to true only when running behind a trusted reverse proxy (e.g., Traefik, Nginx).
// Uses atomic.Bool for safe concurrent access from HTTP handler goroutines.
var trustProxy atomic.Bool

// SetTrustProxy configures whether proxy headers are trusted for IP extraction.
func SetTrustProxy(trust bool) {
	trustProxy.Store(trust)
}

// realIP extracts the real client IP.
// Only trusts X-Forwarded-For/X-Real-IP when running behind a configured trusted proxy.
func realIP(r *http.Request) string {
	if trustProxy.Load() {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			return strings.TrimSpace(parts[0])
		}
		if xri := r.Header.Get("X-Real-IP"); xri != "" {
			return xri
		}
	}
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	return ip
}

// methodToAction maps an HTTP method + path to a semantic action name
func methodToAction(method, path string) string {
	switch method {
	case http.MethodGet:
		if strings.Contains(path, "/audit") {
			return "audit_read"
		}
		if strings.Contains(path, "/tokens") {
			return "token_list"
		}
		return "read"
	case http.MethodPost:
		if strings.Contains(path, "/tokens") {
			return "token_create"
		}
		return "write"
	case http.MethodDelete:
		if strings.Contains(path, "/tokens") {
			return "token_revoke"
		}
		return "delete"
	default:
		return strings.ToLower(method)
	}
}

// writeError writes a JSON error response
func writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(model.APIError{
		Error: message,
		Code:  code,
	})
}
