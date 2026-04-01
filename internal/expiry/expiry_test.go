package expiry

import (
	"testing"
	"time"

	"github.com/mariamills/burrow/internal/crypto"
	"github.com/mariamills/burrow/internal/model"
	"github.com/mariamills/burrow/internal/store"
)

func setup(t *testing.T) (*Worker, *store.Store) {
	t.Helper()
	db, err := store.New(":memory:")
	if err != nil {
		t.Fatalf("failed to create test store: %v", err)
	}
	cfg := DefaultConfig()
	cfg.CheckInterval = time.Hour // don't run in background during tests
	w := New(db, db, cfg)
	return w, db
}

func createSecret(t *testing.T, db *store.Store, ns, key string, expiresAt *time.Time) {
	t.Helper()
	enc, _ := crypto.New([]byte("this-is-a-test-key-at-least-32ch"))
	ciphertext, _ := enc.Encrypt("secret-value")
	id, _ := crypto.GenerateID()
	now := time.Now()
	s := &model.Secret{
		ID: id, Namespace: ns, Key: key, Value: ciphertext,
		ExpiresAt: expiresAt, CreatedAt: now, UpdatedAt: now,
	}
	if err := db.UpsertSecret(s); err != nil {
		t.Fatalf("failed to create secret: %v", err)
	}
}

func TestGetExpiringSecrets_NoneExpiring(t *testing.T) {
	w, _ := setup(t)

	secrets, err := w.GetExpiringSecrets(24 * time.Hour)
	if err != nil {
		t.Fatalf("GetExpiringSecrets failed: %v", err)
	}
	if len(secrets) != 0 {
		t.Errorf("got %d secrets, want 0", len(secrets))
	}
}

func TestGetExpiringSecrets_SomeExpiring(t *testing.T) {
	w, db := setup(t)

	// Secret expiring in 12 hours - should be returned for "within 24h"
	exp12h := time.Now().Add(12 * time.Hour)
	createSecret(t, db, "prod", "DB_PASS", &exp12h)

	// Secret expiring in 48 hours - should NOT be returned for "within 24h"
	exp48h := time.Now().Add(48 * time.Hour)
	createSecret(t, db, "prod", "API_KEY", &exp48h)

	// Secret with no expiry - should NOT be returned
	createSecret(t, db, "prod", "STATIC", nil)

	secrets, err := w.GetExpiringSecrets(24 * time.Hour)
	if err != nil {
		t.Fatalf("GetExpiringSecrets failed: %v", err)
	}
	if len(secrets) != 1 {
		t.Errorf("got %d secrets, want 1", len(secrets))
	}
	if len(secrets) > 0 && secrets[0].Key != "DB_PASS" {
		t.Errorf("key = %q, want DB_PASS", secrets[0].Key)
	}
}

func TestGetExpiringSecrets_AlreadyExpired(t *testing.T) {
	w, db := setup(t)

	// Already expired secret - should NOT appear in "expiring soon" (it's already gone)
	past := time.Now().Add(-1 * time.Hour)
	createSecret(t, db, "prod", "OLD_KEY", &past)

	secrets, err := w.GetExpiringSecrets(24 * time.Hour)
	if err != nil {
		t.Fatalf("GetExpiringSecrets failed: %v", err)
	}
	if len(secrets) != 0 {
		t.Errorf("got %d secrets, want 0 (already expired should not appear)", len(secrets))
	}
}

func TestParseDuration(t *testing.T) {
	tests := []struct {
		input string
		want  time.Duration
	}{
		{"5m", 5 * time.Minute},
		{"24h", 24 * time.Hour},
		{"7d", 7 * 24 * time.Hour},
		{"1d", 24 * time.Hour},
	}

	for _, tt := range tests {
		d, err := ParseDuration(tt.input)
		if err != nil {
			t.Errorf("ParseDuration(%q) error: %v", tt.input, err)
			continue
		}
		if d != tt.want {
			t.Errorf("ParseDuration(%q) = %v, want %v", tt.input, d, tt.want)
		}
	}
}
