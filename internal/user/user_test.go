package user

import (
	"testing"

	"github.com/mariamills/burrow/internal/model"
	"github.com/mariamills/burrow/internal/store"
)

func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	db, err := store.New(":memory:")
	if err != nil {
		t.Fatalf("failed to create test store: %v", err)
	}
	return db
}

func TestRegister_Success(t *testing.T) {
	db := newTestStore(t)
	svc := New(db, db)

	u, err := svc.Register(&model.RegisterRequest{
		Email:    "alice@example.com",
		Password: "strongpassword123",
		Name:     "Alice",
	})
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}
	if u.Email != "alice@example.com" {
		t.Errorf("Email = %q, want alice@example.com", u.Email)
	}
	if u.Name != "Alice" {
		t.Errorf("Name = %q, want Alice", u.Name)
	}
	if u.Password != "" {
		t.Error("Password should be empty in response")
	}
	if u.ID == "" {
		t.Error("ID should not be empty")
	}
}

func TestRegister_DuplicateEmail(t *testing.T) {
	db := newTestStore(t)
	svc := New(db, db)

	_, err := svc.Register(&model.RegisterRequest{
		Email: "alice@example.com", Password: "strongpassword123",
	})
	if err != nil {
		t.Fatalf("first Register failed: %v", err)
	}

	_, err = svc.Register(&model.RegisterRequest{
		Email: "alice@example.com", Password: "anotherpassword123",
	})
	if err == nil {
		t.Fatal("expected error for duplicate email")
	}
}

func TestRegister_ShortPassword(t *testing.T) {
	db := newTestStore(t)
	svc := New(db, db)

	_, err := svc.Register(&model.RegisterRequest{
		Email: "bob@example.com", Password: "short",
	})
	if err == nil {
		t.Fatal("expected error for short password")
	}
}

func TestRegister_MissingEmail(t *testing.T) {
	db := newTestStore(t)
	svc := New(db, db)

	_, err := svc.Register(&model.RegisterRequest{
		Password: "strongpassword123",
	})
	if err == nil {
		t.Fatal("expected error for missing email")
	}
}

func TestAuthenticate_Success(t *testing.T) {
	db := newTestStore(t)
	svc := New(db, db)

	_, err := svc.Register(&model.RegisterRequest{
		Email: "alice@example.com", Password: "strongpassword123",
	})
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	u, err := svc.Authenticate("alice@example.com", "strongpassword123")
	if err != nil {
		t.Fatalf("Authenticate failed: %v", err)
	}
	if u.Email != "alice@example.com" {
		t.Errorf("Email = %q, want alice@example.com", u.Email)
	}
	if u.Password != "" {
		t.Error("Password should be empty in response")
	}
}

func TestAuthenticate_WrongPassword(t *testing.T) {
	db := newTestStore(t)
	svc := New(db, db)

	_, _ = svc.Register(&model.RegisterRequest{
		Email: "alice@example.com", Password: "strongpassword123",
	})

	_, err := svc.Authenticate("alice@example.com", "wrongpassword")
	if err == nil {
		t.Fatal("expected error for wrong password")
	}
}

func TestAuthenticate_NonExistentUser(t *testing.T) {
	db := newTestStore(t)
	svc := New(db, db)

	_, err := svc.Authenticate("nobody@example.com", "anypassword")
	if err == nil {
		t.Fatal("expected error for non-existent user")
	}
}

func TestAuthenticate_CaseInsensitiveEmail(t *testing.T) {
	db := newTestStore(t)
	svc := New(db, db)

	_, _ = svc.Register(&model.RegisterRequest{
		Email: "Alice@Example.COM", Password: "strongpassword123",
	})

	u, err := svc.Authenticate("alice@example.com", "strongpassword123")
	if err != nil {
		t.Fatalf("Authenticate failed: %v", err)
	}
	if u.Email != "alice@example.com" {
		t.Errorf("Email = %q, want alice@example.com", u.Email)
	}
}

func TestDeactivate(t *testing.T) {
	db := newTestStore(t)
	svc := New(db, db)

	u, _ := svc.Register(&model.RegisterRequest{
		Email: "alice@example.com", Password: "strongpassword123",
	})

	if err := svc.Deactivate(u.ID); err != nil {
		t.Fatalf("Deactivate failed: %v", err)
	}

	// Deactivated user cannot authenticate.
	_, err := svc.Authenticate("alice@example.com", "strongpassword123")
	if err == nil {
		t.Fatal("expected error for deactivated user")
	}
}

func TestListUsers(t *testing.T) {
	db := newTestStore(t)
	svc := New(db, db)

	_, _ = svc.Register(&model.RegisterRequest{
		Email: "alice@example.com", Password: "strongpassword123",
	})
	_, _ = svc.Register(&model.RegisterRequest{
		Email: "bob@example.com", Password: "strongpassword456",
	})

	users, err := svc.List()
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(users) != 2 {
		t.Errorf("got %d users, want 2", len(users))
	}
}
