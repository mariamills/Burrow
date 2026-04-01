package store

import (
	"testing"
	"time"

	"github.com/mariamills/burrow/internal/model"
)

// newTestStore creates an in-memory SQLite store for testing.
func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := New(":memory:")
	if err != nil {
		t.Fatalf("New(:memory:) error: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// ── SECRET TESTS ────────────────────────────────────────────────────────────

func TestUpsertSecret_Create(t *testing.T) {
	s := newTestStore(t)

	secret := &model.Secret{
		ID: "s1", Namespace: "prod", Key: "DB_PASS",
		Value: "encrypted-value", Description: "test",
		CreatedAt: time.Now(), UpdatedAt: time.Now(), CreatedBy: "root",
	}
	if err := s.UpsertSecret(secret); err != nil {
		t.Fatalf("UpsertSecret() error: %v", err)
	}

	got, err := s.GetSecret("prod", "DB_PASS")
	if err != nil {
		t.Fatalf("GetSecret() error: %v", err)
	}
	if got == nil {
		t.Fatal("GetSecret() returned nil")
	}
	if got.Value != "encrypted-value" {
		t.Errorf("Value = %q, want 'encrypted-value'", got.Value)
	}
}

func TestUpsertSecret_Update(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()

	s.UpsertSecret(&model.Secret{
		ID: "s1", Namespace: "prod", Key: "DB_PASS",
		Value: "old", CreatedAt: now, UpdatedAt: now,
	})

	s.UpsertSecret(&model.Secret{
		ID: "s2", Namespace: "prod", Key: "DB_PASS",
		Value: "new", Description: "updated", CreatedAt: now, UpdatedAt: now.Add(time.Second),
	})

	got, _ := s.GetSecret("prod", "DB_PASS")
	if got.Value != "new" {
		t.Errorf("Value = %q, want 'new'", got.Value)
	}
	if got.Description != "updated" {
		t.Errorf("Description = %q, want 'updated'", got.Description)
	}
}

func TestGetSecret_NotFound(t *testing.T) {
	s := newTestStore(t)
	got, err := s.GetSecret("prod", "NONEXISTENT")
	if err != nil {
		t.Fatalf("GetSecret() error: %v", err)
	}
	if got != nil {
		t.Error("GetSecret() should return nil for missing secret")
	}
}

func TestListSecrets(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()

	s.UpsertSecret(&model.Secret{ID: "s1", Namespace: "prod", Key: "A", Value: "v", CreatedAt: now, UpdatedAt: now})
	s.UpsertSecret(&model.Secret{ID: "s2", Namespace: "prod", Key: "B", Value: "v", CreatedAt: now, UpdatedAt: now})
	s.UpsertSecret(&model.Secret{ID: "s3", Namespace: "staging", Key: "C", Value: "v", CreatedAt: now, UpdatedAt: now})

	list, err := s.ListSecrets("prod")
	if err != nil {
		t.Fatalf("ListSecrets() error: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("len(list) = %d, want 2", len(list))
	}
	// Should be sorted by key.
	if list[0].Key != "A" || list[1].Key != "B" {
		t.Error("ListSecrets() not sorted by key")
	}
}

func TestListSecrets_Empty(t *testing.T) {
	s := newTestStore(t)
	list, err := s.ListSecrets("nonexistent")
	if err != nil {
		t.Fatalf("ListSecrets() error: %v", err)
	}
	if list != nil && len(list) != 0 {
		t.Error("ListSecrets() should return empty for missing namespace")
	}
}

func TestDeleteSecret(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	s.UpsertSecret(&model.Secret{ID: "s1", Namespace: "prod", Key: "X", Value: "v", CreatedAt: now, UpdatedAt: now})

	deleted, err := s.DeleteSecret("prod", "X")
	if err != nil {
		t.Fatalf("DeleteSecret() error: %v", err)
	}
	if !deleted {
		t.Error("DeleteSecret() should return true")
	}

	got, _ := s.GetSecret("prod", "X")
	if got != nil {
		t.Error("secret should be gone after delete")
	}
}

func TestDeleteSecret_NotFound(t *testing.T) {
	s := newTestStore(t)
	deleted, err := s.DeleteSecret("prod", "NOPE")
	if err != nil {
		t.Fatalf("DeleteSecret() error: %v", err)
	}
	if deleted {
		t.Error("DeleteSecret() should return false for missing secret")
	}
}

func TestDeleteNamespace(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	s.UpsertSecret(&model.Secret{ID: "s1", Namespace: "prod", Key: "A", Value: "v", CreatedAt: now, UpdatedAt: now})
	s.UpsertSecret(&model.Secret{ID: "s2", Namespace: "prod", Key: "B", Value: "v", CreatedAt: now, UpdatedAt: now})
	s.UpsertSecret(&model.Secret{ID: "s3", Namespace: "staging", Key: "C", Value: "v", CreatedAt: now, UpdatedAt: now})

	count, err := s.DeleteNamespace("prod")
	if err != nil {
		t.Fatalf("DeleteNamespace() error: %v", err)
	}
	if count != 2 {
		t.Errorf("DeleteNamespace() deleted %d, want 2", count)
	}

	// staging should still exist.
	got, _ := s.GetSecret("staging", "C")
	if got == nil {
		t.Error("staging secret should still exist")
	}
}

func TestListNamespaces(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	s.UpsertSecret(&model.Secret{ID: "s1", Namespace: "prod", Key: "A", Value: "v", CreatedAt: now, UpdatedAt: now})
	s.UpsertSecret(&model.Secret{ID: "s2", Namespace: "staging", Key: "B", Value: "v", CreatedAt: now, UpdatedAt: now})

	namespaces, err := s.ListNamespaces()
	if err != nil {
		t.Fatalf("ListNamespaces() error: %v", err)
	}
	if len(namespaces) != 2 {
		t.Fatalf("len(namespaces) = %d, want 2", len(namespaces))
	}
}

func TestSearchSecrets(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	s.UpsertSecret(&model.Secret{ID: "s1", Namespace: "prod", Key: "DB_PASSWORD", Value: "v", CreatedAt: now, UpdatedAt: now})
	s.UpsertSecret(&model.Secret{ID: "s2", Namespace: "prod", Key: "DB_HOST", Value: "v", CreatedAt: now, UpdatedAt: now})
	s.UpsertSecret(&model.Secret{ID: "s3", Namespace: "prod", Key: "API_KEY", Value: "v", CreatedAt: now, UpdatedAt: now})

	results, err := s.SearchSecrets("prod", "DB_")
	if err != nil {
		t.Fatalf("SearchSecrets() error: %v", err)
	}
	if len(results) != 2 {
		t.Errorf("SearchSecrets('DB_') found %d, want 2", len(results))
	}
}

func TestSearchSecrets_EscapesWildcards(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	s.UpsertSecret(&model.Secret{ID: "s1", Namespace: "prod", Key: "test_key", Value: "v", CreatedAt: now, UpdatedAt: now})
	s.UpsertSecret(&model.Secret{ID: "s2", Namespace: "prod", Key: "testXkey", Value: "v", CreatedAt: now, UpdatedAt: now})

	// Searching for literal "_" should not match "X" via LIKE wildcard.
	results, err := s.SearchSecrets("prod", "_")
	if err != nil {
		t.Fatalf("SearchSecrets() error: %v", err)
	}
	// Only "test_key" should match (contains literal underscore).
	if len(results) != 1 {
		t.Errorf("SearchSecrets('_') found %d, want 1 (underscore should be escaped)", len(results))
	}
}

// ── TOKEN TESTS ────────────────────────────────────────────────────────────

func TestCreateToken_And_GetActive(t *testing.T) {
	s := newTestStore(t)

	tok := &model.Token{
		ID: "t1", Name: "test-token", Hash: "fakehash",
		Namespaces: []string{"prod"}, Permissions: []string{"read"},
		CreatedAt: time.Now(), Active: true,
	}
	if err := s.CreateToken(tok); err != nil {
		t.Fatalf("CreateToken() error: %v", err)
	}

	tokens, err := s.GetAllActiveTokens()
	if err != nil {
		t.Fatalf("GetAllActiveTokens() error: %v", err)
	}
	if len(tokens) != 1 {
		t.Fatalf("len(tokens) = %d, want 1", len(tokens))
	}
	if tokens[0].Name != "test-token" {
		t.Errorf("Name = %q, want 'test-token'", tokens[0].Name)
	}
}

func TestRevokeToken(t *testing.T) {
	s := newTestStore(t)
	s.CreateToken(&model.Token{
		ID: "t1", Name: "test", Hash: "h",
		Namespaces: []string{"*"}, Permissions: []string{"admin"},
		CreatedAt: time.Now(), Active: true,
	})

	revoked, err := s.RevokeToken("t1")
	if err != nil {
		t.Fatalf("RevokeToken() error: %v", err)
	}
	if !revoked {
		t.Error("RevokeToken() should return true")
	}

	// Should not appear in active tokens.
	active, _ := s.GetAllActiveTokens()
	if len(active) != 0 {
		t.Error("revoked token should not appear in active list")
	}
}

func TestRevokeToken_NotFound(t *testing.T) {
	s := newTestStore(t)
	revoked, err := s.RevokeToken("nonexistent")
	if err != nil {
		t.Fatalf("RevokeToken() error: %v", err)
	}
	if revoked {
		t.Error("RevokeToken() should return false for missing token")
	}
}

func TestListTokens_ExcludesHashes(t *testing.T) {
	s := newTestStore(t)
	s.CreateToken(&model.Token{
		ID: "t1", Name: "test", Hash: "secret-hash",
		Namespaces: []string{"*"}, Permissions: []string{"admin"},
		CreatedAt: time.Now(), Active: true,
	})

	tokens, err := s.ListTokens()
	if err != nil {
		t.Fatalf("ListTokens() error: %v", err)
	}
	if len(tokens) != 1 {
		t.Fatalf("len(tokens) = %d, want 1", len(tokens))
	}
	if tokens[0].Hash != "" {
		t.Error("ListTokens() should not return hashes")
	}
}

func TestGetTokenByID(t *testing.T) {
	s := newTestStore(t)
	s.CreateToken(&model.Token{
		ID: "t1", Name: "test", Hash: "h",
		Namespaces: []string{"prod"}, Permissions: []string{"read"},
		CreatedAt: time.Now(), Active: true,
	})

	tok, err := s.GetTokenByID("t1")
	if err != nil {
		t.Fatalf("GetTokenByID() error: %v", err)
	}
	if tok == nil {
		t.Fatal("GetTokenByID() returned nil")
	}
	if tok.Name != "test" {
		t.Errorf("Name = %q, want 'test'", tok.Name)
	}
}

func TestGetTokenByID_NotFound(t *testing.T) {
	s := newTestStore(t)
	tok, err := s.GetTokenByID("nonexistent")
	if err != nil {
		t.Fatalf("GetTokenByID() error: %v", err)
	}
	if tok != nil {
		t.Error("GetTokenByID() should return nil for missing token")
	}
}

func TestUpsertRootToken(t *testing.T) {
	s := newTestStore(t)

	root := &model.Token{
		ID: "root", Name: "Root Token", Hash: "hash1",
		Namespaces: []string{"*"}, Permissions: []string{"admin"},
		CreatedAt: time.Now(), Active: true,
	}
	if err := s.UpsertRootToken(root); err != nil {
		t.Fatalf("UpsertRootToken() error: %v", err)
	}

	// Upsert again with new hash (simulates key rotation).
	root.Hash = "hash2"
	if err := s.UpsertRootToken(root); err != nil {
		t.Fatalf("UpsertRootToken() second call error: %v", err)
	}

	tok, _ := s.GetTokenByID("root")
	if tok == nil {
		t.Fatal("root token not found after upsert")
	}
	if tok.Hash != "hash2" {
		t.Errorf("Hash = %q, want 'hash2'", tok.Hash)
	}
	if !tok.Active {
		t.Error("root token should be active after upsert")
	}
}

func TestTouchToken(t *testing.T) {
	s := newTestStore(t)
	s.CreateToken(&model.Token{
		ID: "t1", Name: "test", Hash: "h",
		Namespaces: []string{"*"}, Permissions: []string{"admin"},
		CreatedAt: time.Now(), Active: true,
	})

	if err := s.TouchToken("t1"); err != nil {
		t.Fatalf("TouchToken() error: %v", err)
	}

	tok, _ := s.GetTokenByID("t1")
	if tok.LastUsedAt == nil {
		t.Error("LastUsedAt should be set after TouchToken")
	}
}

// ── AUDIT LOG TESTS ────────────────────────────────────────────────────────

func TestWriteAndGetAuditLog(t *testing.T) {
	s := newTestStore(t)

	event := &model.AuditEvent{
		TokenID: "root", TokenName: "Root Token",
		Action: "read", Namespace: "prod", SecretKey: "DB_PASS",
		StatusCode: 200, IPAddress: "127.0.0.1",
		UserAgent: "test", Timestamp: time.Now(),
	}
	if err := s.WriteAuditEvent(event); err != nil {
		t.Fatalf("WriteAuditEvent() error: %v", err)
	}

	events, err := s.GetAuditLog("", 100)
	if err != nil {
		t.Fatalf("GetAuditLog() error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("len(events) = %d, want 1", len(events))
	}
	if events[0].Action != "read" {
		t.Errorf("Action = %q, want 'read'", events[0].Action)
	}
}

func TestGetAuditLog_FilterByNamespace(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()

	s.WriteAuditEvent(&model.AuditEvent{Action: "read", Namespace: "prod", StatusCode: 200, Timestamp: now})
	s.WriteAuditEvent(&model.AuditEvent{Action: "read", Namespace: "staging", StatusCode: 200, Timestamp: now})

	events, _ := s.GetAuditLog("prod", 100)
	if len(events) != 1 {
		t.Errorf("filtered events = %d, want 1", len(events))
	}
}

func TestGetAuditLog_Limit(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	for i := 0; i < 10; i++ {
		s.WriteAuditEvent(&model.AuditEvent{Action: "read", Namespace: "prod", StatusCode: 200, Timestamp: now})
	}

	events, _ := s.GetAuditLog("", 3)
	if len(events) != 3 {
		t.Errorf("limited events = %d, want 3", len(events))
	}
}

// ── PING TEST ────────────────────────────────────────────────────────────

func TestPing(t *testing.T) {
	s := newTestStore(t)
	if err := s.Ping(); err != nil {
		t.Fatalf("Ping() error: %v", err)
	}
}
