package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mariamills/burrow/internal/model"
)

func TestTokenFromContext_Present(t *testing.T) {
	tok := &model.Token{ID: "t1", Name: "test"}
	ctx := context.WithValue(context.Background(), TokenContextKey, tok)
	got := TokenFromContext(ctx)
	if got == nil {
		t.Fatal("TokenFromContext returned nil")
	}
	if got.ID != "t1" {
		t.Errorf("ID = %q, want 't1'", got.ID)
	}
}

func TestTokenFromContext_Missing(t *testing.T) {
	got := TokenFromContext(context.Background())
	if got != nil {
		t.Error("TokenFromContext should return nil when no token in context")
	}
}

func TestRequirePermission_Allowed(t *testing.T) {
	tok := &model.Token{Permissions: []string{"read", "write"}}
	mw := RequirePermission("read")
	called := false
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))

	req := httptest.NewRequest("GET", "/", nil)
	ctx := context.WithValue(req.Context(), TokenContextKey, tok)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if !called {
		t.Error("handler should have been called")
	}
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

func TestRequirePermission_Denied(t *testing.T) {
	tok := &model.Token{Permissions: []string{"read"}}
	mw := RequirePermission("admin")
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should NOT have been called")
	}))

	req := httptest.NewRequest("GET", "/", nil)
	ctx := context.WithValue(req.Context(), TokenContextKey, tok)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

func TestRequirePermission_NoToken(t *testing.T) {
	mw := RequirePermission("read")
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should NOT have been called")
	}))

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestRequireNamespace_Allowed(t *testing.T) {
	tok := &model.Token{Namespaces: []string{"production"}}
	mw := RequireNamespace(3) // /v1/secrets/production/... → ["", "v1", "secrets", "production", ...]
	called := false
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))

	req := httptest.NewRequest("GET", "/v1/secrets/production/KEY", nil)
	ctx := context.WithValue(req.Context(), TokenContextKey, tok)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if !called {
		t.Error("handler should have been called")
	}
}

func TestRequireNamespace_Denied(t *testing.T) {
	tok := &model.Token{Namespaces: []string{"staging"}}
	mw := RequireNamespace(3)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should NOT have been called")
	}))

	req := httptest.NewRequest("GET", "/v1/secrets/production/KEY", nil)
	ctx := context.WithValue(req.Context(), TokenContextKey, tok)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

func TestRequireNamespace_Wildcard(t *testing.T) {
	tok := &model.Token{Namespaces: []string{"*"}}
	mw := RequireNamespace(3)
	called := false
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))

	req := httptest.NewRequest("GET", "/v1/secrets/anything/KEY", nil)
	ctx := context.WithValue(req.Context(), TokenContextKey, tok)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if !called {
		t.Error("wildcard namespace token should have access to any namespace")
	}
}

func TestSecureHeaders(t *testing.T) {
	handler := SecureHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/v1/health", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	expected := map[string]string{
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY",
		"Cache-Control":             "no-store",
		"Referrer-Policy":           "no-referrer",
		"Content-Security-Policy":   "default-src 'none'",
		"Strict-Transport-Security": "max-age=63072000; includeSubDomains",
	}

	for header, want := range expected {
		if got := w.Header().Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
}

func TestCORS_WithOrigin(t *testing.T) {
	handler := CORS("https://example.com")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "https://example.com" {
		t.Errorf("CORS origin = %q, want 'https://example.com'", got)
	}
}

func TestCORS_Empty(t *testing.T) {
	handler := CORS("")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("CORS origin should be empty when disabled, got %q", got)
	}
}

func TestCORS_Preflight(t *testing.T) {
	handler := CORS("*")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should NOT be called on preflight")
	}))

	req := httptest.NewRequest("OPTIONS", "/v1/secrets/prod/KEY", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("preflight status = %d, want 204", w.Code)
	}
}

func TestRateLimit(t *testing.T) {
	limit := 3
	mw := RateLimit(limit)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// First 3 requests should succeed.
	for i := 0; i < limit; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "1.2.3.4:1234"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d, want 200", i+1, w.Code)
		}
	}

	// 4th request should be rate limited.
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("request 4: status = %d, want 429", w.Code)
	}
}

func TestRateLimit_DifferentIPs(t *testing.T) {
	mw := RateLimit(1)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// IP 1 should succeed
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "1.1.1.1:1234"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("IP1 status = %d, want 200", w.Code)
	}

	// IP 2 should also succeed (independent limit)
	req = httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "2.2.2.2:1234"
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("IP2 status = %d, want 200", w.Code)
	}
}

func TestRealIP_NoProxy(t *testing.T) {
	// Ensure proxy headers are NOT trusted by default.
	SetTrustProxy(false)

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	req.Header.Set("X-Forwarded-For", "1.2.3.4")

	got := realIP(req)
	if got != "10.0.0.1" {
		t.Errorf("realIP() = %q, want '10.0.0.1' (should ignore X-Forwarded-For)", got)
	}
}

func TestRealIP_WithProxy(t *testing.T) {
	SetTrustProxy(true)
	defer SetTrustProxy(false)

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	req.Header.Set("X-Forwarded-For", "1.2.3.4, 10.0.0.1")

	got := realIP(req)
	if got != "1.2.3.4" {
		t.Errorf("realIP() = %q, want '1.2.3.4' (trusted proxy)", got)
	}
}

func TestMethodToAction(t *testing.T) {
	tests := []struct {
		method string
		path   string
		want   string
	}{
		{"GET", "/v1/secrets/prod/KEY", "read"},
		{"POST", "/v1/secrets/prod/KEY", "write"},
		{"DELETE", "/v1/secrets/prod/KEY", "delete"},
		{"GET", "/v1/audit", "audit_read"},
		{"POST", "/v1/tokens", "token_create"},
		{"GET", "/v1/tokens", "token_list"},
		{"DELETE", "/v1/tokens/abc", "token_revoke"},
	}

	for _, tt := range tests {
		if got := methodToAction(tt.method, tt.path); got != tt.want {
			t.Errorf("methodToAction(%q, %q) = %q, want %q", tt.method, tt.path, got, tt.want)
		}
	}
}
