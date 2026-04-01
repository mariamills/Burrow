package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mariamills/burrow/internal/auth"
	"github.com/mariamills/burrow/internal/crypto"
	"github.com/mariamills/burrow/internal/middleware"
	"github.com/mariamills/burrow/internal/model"
	"github.com/mariamills/burrow/internal/store"
)

const testRootToken = "test-root-token-with-32-chars!!!"

// testSetup creates all dependencies for handler tests using an in-memory DB.
func testSetup(t *testing.T) (*Handler, *auth.Service, *store.Store) {
	t.Helper()

	s, err := store.New(":memory:")
	if err != nil {
		t.Fatalf("store.New() error: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	enc, err := crypto.New([]byte("test-master-key-with-32-chars!!!"))
	if err != nil {
		t.Fatalf("crypto.New() error: %v", err)
	}

	authSvc, err := auth.New(s, testRootToken)
	if err != nil {
		t.Fatalf("auth.New() error: %v", err)
	}

	h := New(s, authSvc, enc, "1.0.0-test")
	return h, authSvc, s
}

// withToken injects an authenticated token into the request context.
func withToken(r *http.Request, tok *model.Token) *http.Request {
	ctx := context.WithValue(r.Context(), middleware.TokenContextKey, tok)
	return r.WithContext(ctx)
}

func adminToken() *model.Token {
	return &model.Token{
		ID: "root", Name: "Root Token",
		Namespaces: []string{"*"}, Permissions: []string{"admin"},
		Active: true,
	}
}

func readOnlyToken(namespaces ...string) *model.Token {
	return &model.Token{
		ID: "reader", Name: "Read Token",
		Namespaces: namespaces, Permissions: []string{"read"},
		Active: true,
	}
}

// ── HEALTH ────────────────────────────────────────────────────────────────

func TestHealth(t *testing.T) {
	h, _, _ := testSetup(t)

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	h.Health(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Health() status = %d, want 200", w.Code)
	}

	var resp model.HealthResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Status != "ok" {
		t.Errorf("status = %q, want 'ok'", resp.Status)
	}
	if resp.DBStatus != "ok" {
		t.Errorf("db_status = %q, want 'ok'", resp.DBStatus)
	}
}

// ── UPSERT SECRET ─────────────────────────────────────────────────────────

func TestUpsertSecret_Create(t *testing.T) {
	h, _, _ := testSetup(t)

	body := `{"value":"super-secret","description":"test"}`
	req := httptest.NewRequest("POST", "/v1/secrets/prod/DB_PASS", bytes.NewBufferString(body))
	req = withToken(req, adminToken())
	w := httptest.NewRecorder()

	h.UpsertSecret(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("UpsertSecret() status = %d, want 201. Body: %s", w.Code, w.Body.String())
	}
}

func TestUpsertSecret_Update(t *testing.T) {
	h, _, _ := testSetup(t)

	// Create first.
	body := `{"value":"v1"}`
	req := httptest.NewRequest("POST", "/v1/secrets/prod/KEY", bytes.NewBufferString(body))
	req = withToken(req, adminToken())
	w := httptest.NewRecorder()
	h.UpsertSecret(w, req)

	// Update.
	body = `{"value":"v2"}`
	req = httptest.NewRequest("POST", "/v1/secrets/prod/KEY", bytes.NewBufferString(body))
	req = withToken(req, adminToken())
	w = httptest.NewRecorder()
	h.UpsertSecret(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("UpsertSecret(update) status = %d, want 200", w.Code)
	}
}

func TestUpsertSecret_EmptyValue(t *testing.T) {
	h, _, _ := testSetup(t)

	body := `{"value":""}`
	req := httptest.NewRequest("POST", "/v1/secrets/prod/KEY", bytes.NewBufferString(body))
	req = withToken(req, adminToken())
	w := httptest.NewRecorder()
	h.UpsertSecret(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestUpsertSecret_InvalidIdentifier(t *testing.T) {
	h, _, _ := testSetup(t)

	body := `{"value":"v"}`
	// SQL injection / special chars attempt.
	req := httptest.NewRequest("POST", "/v1/secrets/prod/key%27%3BDROP", bytes.NewBufferString(body))
	req = withToken(req, adminToken())
	w := httptest.NewRecorder()
	h.UpsertSecret(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for invalid identifier", w.Code)
	}
}

func TestUpsertSecret_InvalidJSON(t *testing.T) {
	h, _, _ := testSetup(t)

	req := httptest.NewRequest("POST", "/v1/secrets/prod/KEY", bytes.NewBufferString("not json"))
	req = withToken(req, adminToken())
	w := httptest.NewRecorder()
	h.UpsertSecret(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

// ── GET SECRET ────────────────────────────────────────────────────────────

func TestGetSecret(t *testing.T) {
	h, _, _ := testSetup(t)

	// Create a secret first.
	body := `{"value":"my-secret-value"}`
	req := httptest.NewRequest("POST", "/v1/secrets/prod/KEY", bytes.NewBufferString(body))
	req = withToken(req, adminToken())
	w := httptest.NewRecorder()
	h.UpsertSecret(w, req)

	// Read it back.
	req = httptest.NewRequest("GET", "/v1/secrets/prod/KEY", nil)
	req = withToken(req, adminToken())
	w = httptest.NewRecorder()
	h.GetSecret(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("GetSecret() status = %d, want 200. Body: %s", w.Code, w.Body.String())
	}

	var resp model.APIResponse
	json.NewDecoder(w.Body).Decode(&resp)
	data := resp.Data.(map[string]interface{})
	if data["value"] != "my-secret-value" {
		t.Errorf("value = %q, want 'my-secret-value'", data["value"])
	}
}

func TestGetSecret_NotFound(t *testing.T) {
	h, _, _ := testSetup(t)

	req := httptest.NewRequest("GET", "/v1/secrets/prod/NOPE", nil)
	req = withToken(req, adminToken())
	w := httptest.NewRecorder()
	h.GetSecret(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
}

func TestGetSecret_InvalidIdentifier(t *testing.T) {
	h, _, _ := testSetup(t)

	// Use URL-encoded space (%20) — httptest.NewRequest panics on literal spaces.
	req := httptest.NewRequest("GET", "/v1/secrets/prod/key%20with%20spaces", nil)
	req = withToken(req, adminToken())
	w := httptest.NewRecorder()
	h.GetSecret(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

// ── LIST SECRETS ──────────────────────────────────────────────────────────

func TestListSecrets(t *testing.T) {
	h, _, _ := testSetup(t)

	// Create two secrets.
	for _, key := range []string{"A", "B"} {
		body := `{"value":"v"}`
		req := httptest.NewRequest("POST", "/v1/secrets/prod/"+key, bytes.NewBufferString(body))
		req = withToken(req, adminToken())
		w := httptest.NewRecorder()
		h.UpsertSecret(w, req)
	}

	req := httptest.NewRequest("GET", "/v1/secrets/prod", nil)
	req = withToken(req, adminToken())
	w := httptest.NewRecorder()
	h.ListSecrets(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var resp model.APIResponse
	json.NewDecoder(w.Body).Decode(&resp)
	data := resp.Data.([]interface{})
	if len(data) != 2 {
		t.Errorf("len(data) = %d, want 2", len(data))
	}
}

func TestListSecrets_EmptyNamespace(t *testing.T) {
	h, _, _ := testSetup(t)

	req := httptest.NewRequest("GET", "/v1/secrets/empty", nil)
	req = withToken(req, adminToken())
	w := httptest.NewRecorder()
	h.ListSecrets(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
}

// ── DELETE SECRET ─────────────────────────────────────────────────────────

func TestDeleteSecret(t *testing.T) {
	h, _, _ := testSetup(t)

	// Create then delete.
	body := `{"value":"v"}`
	req := httptest.NewRequest("POST", "/v1/secrets/prod/DEL", bytes.NewBufferString(body))
	req = withToken(req, adminToken())
	w := httptest.NewRecorder()
	h.UpsertSecret(w, req)

	req = httptest.NewRequest("DELETE", "/v1/secrets/prod/DEL", nil)
	req = withToken(req, adminToken())
	w = httptest.NewRecorder()
	h.DeleteSecret(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
}

func TestDeleteSecret_NotFound(t *testing.T) {
	h, _, _ := testSetup(t)

	req := httptest.NewRequest("DELETE", "/v1/secrets/prod/NOPE", nil)
	req = withToken(req, adminToken())
	w := httptest.NewRecorder()
	h.DeleteSecret(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
}

// ── DELETE NAMESPACE ──────────────────────────────────────────────────────

func TestDeleteNamespace(t *testing.T) {
	h, _, _ := testSetup(t)

	body := `{"value":"v"}`
	for _, key := range []string{"A", "B"} {
		req := httptest.NewRequest("POST", "/v1/secrets/prod/"+key, bytes.NewBufferString(body))
		req = withToken(req, adminToken())
		w := httptest.NewRecorder()
		h.UpsertSecret(w, req)
	}

	req := httptest.NewRequest("DELETE", "/v1/secrets/prod", nil)
	req = withToken(req, adminToken())
	w := httptest.NewRecorder()
	h.DeleteNamespace(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
}

// ── CREATE TOKEN ──────────────────────────────────────────────────────────

func TestCreateToken(t *testing.T) {
	h, _, _ := testSetup(t)

	body := `{"name":"ci-token","namespaces":["staging"],"permissions":["read"]}`
	req := httptest.NewRequest("POST", "/v1/tokens", bytes.NewBufferString(body))
	req = withToken(req, adminToken())
	w := httptest.NewRecorder()
	h.CreateToken(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201. Body: %s", w.Code, w.Body.String())
	}

	var resp model.APIResponse
	json.NewDecoder(w.Body).Decode(&resp)
	data := resp.Data.(map[string]interface{})
	token := data["token"].(string)
	if !strings.HasPrefix(token, "vlt_") {
		t.Errorf("token should start with 'vlt_', got: %q", token[:10])
	}
}

func TestCreateToken_MissingName(t *testing.T) {
	h, _, _ := testSetup(t)

	body := `{"namespaces":["prod"],"permissions":["read"]}`
	req := httptest.NewRequest("POST", "/v1/tokens", bytes.NewBufferString(body))
	req = withToken(req, adminToken())
	w := httptest.NewRecorder()
	h.CreateToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestCreateToken_InvalidPermission(t *testing.T) {
	h, _, _ := testSetup(t)

	body := `{"name":"bad","namespaces":["prod"],"permissions":["superadmin"]}`
	req := httptest.NewRequest("POST", "/v1/tokens", bytes.NewBufferString(body))
	req = withToken(req, adminToken())
	w := httptest.NewRecorder()
	h.CreateToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for invalid permission", w.Code)
	}
}

func TestCreateToken_InvalidNamespace(t *testing.T) {
	h, _, _ := testSetup(t)

	body := `{"name":"bad","namespaces":["ns with spaces"],"permissions":["read"]}`
	req := httptest.NewRequest("POST", "/v1/tokens", bytes.NewBufferString(body))
	req = withToken(req, adminToken())
	w := httptest.NewRecorder()
	h.CreateToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for invalid namespace", w.Code)
	}
}

func TestCreateToken_WildcardNamespace(t *testing.T) {
	h, _, _ := testSetup(t)

	body := `{"name":"admin","namespaces":["*"],"permissions":["admin"]}`
	req := httptest.NewRequest("POST", "/v1/tokens", bytes.NewBufferString(body))
	req = withToken(req, adminToken())
	w := httptest.NewRecorder()
	h.CreateToken(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (wildcard namespace should be valid)", w.Code)
	}
}

// ── REVOKE TOKEN ──────────────────────────────────────────────────────────

func TestRevokeToken_Root(t *testing.T) {
	h, _, _ := testSetup(t)

	req := httptest.NewRequest("DELETE", "/v1/tokens/root", nil)
	req = withToken(req, adminToken())
	w := httptest.NewRecorder()
	h.RevokeToken(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for root revocation", w.Code)
	}
}

// ── AUDIT LOG ─────────────────────────────────────────────────────────────

func TestGetAuditLog(t *testing.T) {
	h, _, _ := testSetup(t)

	req := httptest.NewRequest("GET", "/v1/audit", nil)
	req = withToken(req, adminToken())
	w := httptest.NewRecorder()
	h.GetAuditLog(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
}

func TestGetAuditLog_WithLimit(t *testing.T) {
	h, _, _ := testSetup(t)

	req := httptest.NewRequest("GET", "/v1/audit?limit=5", nil)
	req = withToken(req, adminToken())
	w := httptest.NewRecorder()
	h.GetAuditLog(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
}

// ── VALIDATION HELPERS ───────────────────────────────────────────────────

func TestIsValidIdentifier(t *testing.T) {
	tests := []struct {
		input string
		valid bool
	}{
		{"production", true},
		{"my-app", true},
		{"my_app", true},
		{"v1.0", true},
		{"DB_PASSWORD", true},
		{"", false},
		{"has space", false},
		{"path/../traversal", false},
		{"sql'; DROP TABLE--", false},
		{strings.Repeat("a", 129), false},
		{strings.Repeat("a", 128), true},
	}

	for _, tt := range tests {
		if got := isValidIdentifier(tt.input); got != tt.valid {
			t.Errorf("isValidIdentifier(%q) = %v, want %v", tt.input, got, tt.valid)
		}
	}
}

func TestPathSegment(t *testing.T) {
	// After fix: Split without Trim, so leading "/" gives empty element at index 0.
	// /v1/secrets/prod/KEY → ["", "v1", "secrets", "prod", "KEY"]
	tests := []struct {
		path  string
		index int
		want  string
	}{
		{"/v1/secrets/prod/KEY", 0, ""}, // leading empty
		{"/v1/secrets/prod/KEY", 1, "v1"},
		{"/v1/secrets/prod/KEY", 2, "secrets"},
		{"/v1/secrets/prod/KEY", 3, "prod"},
		{"/v1/secrets/prod/KEY", 4, "KEY"},
		{"/v1/secrets/prod/KEY", 5, ""},
		{"/v1/audit", 3, ""},
		{"/v1/audit/myns", 3, "myns"},
	}

	for _, tt := range tests {
		if got := pathSegment(tt.path, tt.index); got != tt.want {
			t.Errorf("pathSegment(%q, %d) = %q, want %q", tt.path, tt.index, got, tt.want)
		}
	}
}
