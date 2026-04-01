package auth

import (
	"strings"
	"testing"
	"time"

	"github.com/mariamills/burrow/internal/model"
	"github.com/mariamills/burrow/internal/store"
)

const testRootToken = "test-root-token-with-32-chars!!!"

func newTestAuth(t *testing.T) *Service {
	t.Helper()
	s, err := store.New(":memory:")
	if err != nil {
		t.Fatalf("store.New() error: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	svc, err := New(s, testRootToken)
	if err != nil {
		t.Fatalf("auth.New() error: %v", err)
	}
	return svc
}

func TestNew_SeedsRootToken(t *testing.T) {
	svc := newTestAuth(t)
	svc.mu.RLock()
	defer svc.mu.RUnlock()
	if _, ok := svc.tokenCache["root"]; !ok {
		t.Error("root token should be in cache after New()")
	}
}

func TestValidateToken_RootToken(t *testing.T) {
	svc := newTestAuth(t)
	tok, err := svc.ValidateToken("Bearer " + testRootToken)
	if err != nil {
		t.Fatalf("ValidateToken(root) error: %v", err)
	}
	if tok.ID != "root" {
		t.Errorf("token ID = %q, want 'root'", tok.ID)
	}
	if !tok.HasPermission("admin") {
		t.Error("root token should have admin permission")
	}
}

func TestValidateToken_Empty(t *testing.T) {
	svc := newTestAuth(t)
	_, err := svc.ValidateToken("")
	if err == nil {
		t.Fatal("ValidateToken('') should fail")
	}
}

func TestValidateToken_InvalidFormat(t *testing.T) {
	svc := newTestAuth(t)
	_, err := svc.ValidateToken("Bearer not-a-valid-token")
	if err == nil {
		t.Fatal("ValidateToken(invalid) should fail")
	}
}

func TestValidateToken_WrongToken(t *testing.T) {
	svc := newTestAuth(t)
	_, err := svc.ValidateToken("Bearer vlt_totally-wrong-token-value!!")
	if err == nil {
		t.Fatal("ValidateToken(wrong) should fail")
	}
}

func TestCreateToken_And_Validate(t *testing.T) {
	svc := newTestAuth(t)

	resp, err := svc.CreateToken(&model.CreateTokenRequest{
		Name:        "test-token",
		Namespaces:  []string{"prod"},
		Permissions: []string{"read"},
	})
	if err != nil {
		t.Fatalf("CreateToken() error: %v", err)
	}

	if !strings.HasPrefix(resp.Token, "vlt_") {
		t.Errorf("token should start with 'vlt_', got %q", resp.Token[:10])
	}

	// Validate the newly created token.
	tok, err := svc.ValidateToken("Bearer " + resp.Token)
	if err != nil {
		t.Fatalf("ValidateToken(new token) error: %v", err)
	}
	if tok.Name != "test-token" {
		t.Errorf("Name = %q, want 'test-token'", tok.Name)
	}
}

func TestCreateToken_WithExpiry(t *testing.T) {
	svc := newTestAuth(t)

	// Create a token that already expired.
	past := time.Now().Add(-time.Hour)
	resp, err := svc.CreateToken(&model.CreateTokenRequest{
		Name:        "expired-token",
		Namespaces:  []string{"prod"},
		Permissions: []string{"read"},
		ExpiresAt:   &past,
	})
	if err != nil {
		t.Fatalf("CreateToken() error: %v", err)
	}

	// Should fail validation because it's expired.
	_, err = svc.ValidateToken("Bearer " + resp.Token)
	if err == nil {
		t.Fatal("ValidateToken(expired token) should fail")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected expiry error, got: %v", err)
	}
}

func TestRevokeToken(t *testing.T) {
	svc := newTestAuth(t)

	resp, _ := svc.CreateToken(&model.CreateTokenRequest{
		Name:        "revoke-me",
		Namespaces:  []string{"prod"},
		Permissions: []string{"read"},
	})

	revoked, err := svc.RevokeToken(resp.TokenID)
	if err != nil {
		t.Fatalf("RevokeToken() error: %v", err)
	}
	if !revoked {
		t.Error("RevokeToken() should return true")
	}

	// Token should now fail validation.
	_, err = svc.ValidateToken("Bearer " + resp.Token)
	if err == nil {
		t.Fatal("ValidateToken(revoked token) should fail")
	}
}

func TestRevokeToken_NotFound(t *testing.T) {
	svc := newTestAuth(t)
	revoked, err := svc.RevokeToken("nonexistent-id")
	if err != nil {
		t.Fatalf("RevokeToken() error: %v", err)
	}
	if revoked {
		t.Error("RevokeToken(nonexistent) should return false")
	}
}

func TestListTokens(t *testing.T) {
	svc := newTestAuth(t)

	svc.CreateToken(&model.CreateTokenRequest{
		Name: "t1", Namespaces: []string{"prod"}, Permissions: []string{"read"},
	})

	tokens, err := svc.ListTokens()
	if err != nil {
		t.Fatalf("ListTokens() error: %v", err)
	}
	// Should have at least root + the new token.
	if len(tokens) < 2 {
		t.Errorf("len(tokens) = %d, want >= 2", len(tokens))
	}
}

func TestIsRootToken(t *testing.T) {
	svc := newTestAuth(t)

	if !svc.isRootToken(testRootToken) {
		t.Error("isRootToken() should return true for the configured root token")
	}
	if svc.isRootToken("wrong-token") {
		t.Error("isRootToken() should return false for wrong token")
	}
}

func TestGetRootTokenModel(t *testing.T) {
	svc := newTestAuth(t)

	tok := svc.getRootTokenModel()
	if tok == nil {
		t.Fatal("getRootTokenModel() returned nil")
	}
	if tok.ID != "root" {
		t.Errorf("ID = %q, want 'root'", tok.ID)
	}
	if !tok.CanAccessNamespace("anything") {
		t.Error("root token should have wildcard namespace access")
	}
}
