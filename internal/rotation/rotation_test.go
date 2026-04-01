package rotation

import (
	"testing"
	"time"

	"github.com/mariamills/burrow/internal/crypto"
	"github.com/mariamills/burrow/internal/model"
	"github.com/mariamills/burrow/internal/store"
)

func setup(t *testing.T) (*Service, *store.Store, *crypto.Encryptor) {
	t.Helper()
	db, err := store.New(":memory:")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	enc, err := crypto.New([]byte("this-is-a-test-key-at-least-32ch"))
	if err != nil {
		t.Fatalf("crypto: %v", err)
	}
	svc := New(db, db, db, enc, db)
	return svc, db, enc
}

func createTestSecret(t *testing.T, db *store.Store, enc *crypto.Encryptor, ns, key, value string) {
	t.Helper()
	ciphertext, _ := enc.Encrypt(value)
	id, _ := crypto.GenerateID()
	now := time.Now()
	err := db.UpsertSecret(&model.Secret{
		ID: id, Namespace: ns, Key: key, Value: ciphertext,
		CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("create secret: %v", err)
	}
}

func TestRotate_CreatesVersion(t *testing.T) {
	svc, db, enc := setup(t)
	createTestSecret(t, db, enc, "prod", "DB_PASS", "old-password")

	meta, err := svc.Rotate("prod", "DB_PASS", "test-user")
	if err != nil {
		t.Fatalf("Rotate failed: %v", err)
	}
	if meta.Version != 1 {
		t.Errorf("version = %d, want 1", meta.Version)
	}

	// The old value should be archived as version 1.
	v, err := svc.GetVersion("prod", "DB_PASS", 1)
	if err != nil {
		t.Fatalf("GetVersion failed: %v", err)
	}
	if v == nil {
		t.Fatal("version 1 should exist")
	}
	if v.Value != "old-password" {
		t.Errorf("archived value = %q, want old-password", v.Value)
	}

	// The current secret should have a new (random) value.
	current, _ := db.GetSecret("prod", "DB_PASS")
	decrypted, _ := enc.Decrypt(current.Value)
	if decrypted == "old-password" {
		t.Error("current value should differ from old value after rotation")
	}
}

func TestRotate_MultipleVersions(t *testing.T) {
	svc, db, enc := setup(t)
	createTestSecret(t, db, enc, "prod", "API_KEY", "v0")

	// Rotate twice.
	_, _ = svc.Rotate("prod", "API_KEY", "user1")
	meta2, _ := svc.Rotate("prod", "API_KEY", "user2")

	if meta2.Version != 2 {
		t.Errorf("version = %d, want 2", meta2.Version)
	}

	versions, _ := svc.ListVersions("prod", "API_KEY")
	if len(versions) != 2 {
		t.Errorf("got %d versions, want 2", len(versions))
	}
}

func TestRotate_SecretNotFound(t *testing.T) {
	svc, _, _ := setup(t)

	_, err := svc.Rotate("prod", "NONEXISTENT", "user")
	if err == nil {
		t.Fatal("expected error for non-existent secret")
	}
}

func TestSetPolicy(t *testing.T) {
	svc, db, enc := setup(t)
	createTestSecret(t, db, enc, "prod", "DB_PASS", "secret")

	policy, err := svc.SetPolicy("prod", "DB_PASS", &model.SetRotationPolicyRequest{
		IntervalSecs: 3600,
	})
	if err != nil {
		t.Fatalf("SetPolicy failed: %v", err)
	}
	if policy.IntervalSecs != 3600 {
		t.Errorf("interval = %d, want 3600", policy.IntervalSecs)
	}
	if policy.NextRotation == nil {
		t.Error("next_rotation should be set")
	}
}

func TestSetPolicy_TooShortInterval(t *testing.T) {
	svc, db, enc := setup(t)
	createTestSecret(t, db, enc, "prod", "DB_PASS", "secret")

	_, err := svc.SetPolicy("prod", "DB_PASS", &model.SetRotationPolicyRequest{
		IntervalSecs: 30, // less than minimum 60
	})
	if err == nil {
		t.Fatal("expected error for too-short interval")
	}
}

func TestGetPolicy(t *testing.T) {
	svc, db, enc := setup(t)
	createTestSecret(t, db, enc, "prod", "DB_PASS", "secret")

	_, _ = svc.SetPolicy("prod", "DB_PASS", &model.SetRotationPolicyRequest{IntervalSecs: 3600})

	policy, err := svc.GetPolicy("prod", "DB_PASS")
	if err != nil {
		t.Fatalf("GetPolicy failed: %v", err)
	}
	if policy == nil {
		t.Fatal("policy should exist")
	}
	if policy.IntervalSecs != 3600 {
		t.Errorf("interval = %d, want 3600", policy.IntervalSecs)
	}
}
