package session

import (
	"testing"

	"github.com/mariamills/burrow/internal/model"
	"github.com/mariamills/burrow/internal/store"
	"github.com/mariamills/burrow/internal/user"
)

func setup(t *testing.T) (*Service, *user.Service, *model.User) {
	t.Helper()
	db, err := store.New(":memory:")
	if err != nil {
		t.Fatalf("failed to create test store: %v", err)
	}

	userSvc := user.New(db, db)
	u, err := userSvc.Register(&model.RegisterRequest{
		Email: "alice@example.com", Password: "strongpassword123", Name: "Alice",
	})
	if err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	sessSvc := &Service{
		store: db,
		users: db,
		ttl:   defaultTTL,
	}

	return sessSvc, userSvc, u
}

func TestCreate_And_Validate(t *testing.T) {
	svc, _, u := setup(t)

	resp, err := svc.Create(u.ID, "127.0.0.1", "test-agent")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	if resp.Token == "" {
		t.Error("Token should not be empty")
	}
	if resp.User == nil {
		t.Fatal("User should not be nil")
	}
	if resp.User.Email != "alice@example.com" {
		t.Errorf("User email = %q, want alice@example.com", resp.User.Email)
	}

	// Validate the token.
	sess, err := svc.Validate(resp.Token)
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	if sess.UserID != u.ID {
		t.Errorf("UserID = %q, want %q", sess.UserID, u.ID)
	}
}

func TestValidate_InvalidToken(t *testing.T) {
	svc, _, _ := setup(t)

	_, err := svc.Validate("invalid-token")
	if err == nil {
		t.Fatal("expected error for invalid token")
	}
}

func TestValidate_EmptyToken(t *testing.T) {
	svc, _, _ := setup(t)

	_, err := svc.Validate("")
	if err == nil {
		t.Fatal("expected error for empty token")
	}
}

func TestDestroy(t *testing.T) {
	svc, _, u := setup(t)

	resp, _ := svc.Create(u.ID, "127.0.0.1", "test-agent")

	// Validate works before destroy.
	sess, err := svc.Validate(resp.Token)
	if err != nil {
		t.Fatalf("Validate before destroy failed: %v", err)
	}

	// Destroy the session.
	if err := svc.Destroy(sess.ID); err != nil {
		t.Fatalf("Destroy failed: %v", err)
	}

	// Validate should fail after destroy.
	_, err = svc.Validate(resp.Token)
	if err == nil {
		t.Fatal("expected error after session destroyed")
	}
}

func TestMultipleSessions(t *testing.T) {
	svc, _, u := setup(t)

	resp1, _ := svc.Create(u.ID, "127.0.0.1", "agent-1")
	resp2, _ := svc.Create(u.ID, "127.0.0.1", "agent-2")

	// Both sessions should be valid.
	if _, err := svc.Validate(resp1.Token); err != nil {
		t.Fatalf("session 1 should be valid: %v", err)
	}
	if _, err := svc.Validate(resp2.Token); err != nil {
		t.Fatalf("session 2 should be valid: %v", err)
	}

	// Destroy one; other should still work.
	sess1, _ := svc.Validate(resp1.Token)
	svc.Destroy(sess1.ID)

	if _, err := svc.Validate(resp1.Token); err == nil {
		t.Fatal("session 1 should be invalid after destroy")
	}
	if _, err := svc.Validate(resp2.Token); err != nil {
		t.Fatalf("session 2 should still be valid: %v", err)
	}
}
