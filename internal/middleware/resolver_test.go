package middleware

import (
	"testing"

	"github.com/mariamills/burrow/internal/group"
	"github.com/mariamills/burrow/internal/model"
	"github.com/mariamills/burrow/internal/store"
	"github.com/mariamills/burrow/internal/user"
)

func setupResolver(t *testing.T) (*GroupPermissionResolver, *model.User, *model.Group) {
	t.Helper()
	db, err := store.New(":memory:")
	if err != nil {
		t.Fatalf("failed to create test store: %v", err)
	}

	userSvc := user.New(db, db)
	groupSvc := group.New(db, db)

	u, err := userSvc.Register(&model.RegisterRequest{
		Email: "alice@example.com", Password: "strongpassword123", Name: "Alice",
	})
	if err != nil {
		t.Fatalf("register user: %v", err)
	}

	g, err := groupSvc.Create(&model.CreateGroupRequest{Name: "backend-team"})
	if err != nil {
		t.Fatalf("create group: %v", err)
	}

	_ = groupSvc.AddMember(g.ID, &model.AddMemberRequest{UserID: u.ID})
	_ = groupSvc.SetPermissions(g.ID, &model.SetGroupPermissionsRequest{
		Namespace: "production", Permissions: []string{"read", "write"},
	})

	resolver := NewPermissionResolver(db, db)
	return resolver, u, g
}

func TestResolver_TokenDirectPermission(t *testing.T) {
	resolver, _, _ := setupResolver(t)

	// Token with admin permission should pass regardless of groups.
	token := &model.Token{
		Permissions: []string{"admin"},
		Namespaces:  []string{"*"},
	}
	if !resolver.HasPermission(token, "", "read") {
		t.Error("admin token should have read permission")
	}
	if !resolver.CanAccessNamespace(token, "", "production") {
		t.Error("wildcard token should access production")
	}
}

func TestResolver_GroupGrantsPermission(t *testing.T) {
	resolver, u, _ := setupResolver(t)

	// Token with NO permissions, but user is in a group with read+write on production.
	token := &model.Token{
		Permissions: []string{},
		Namespaces:  []string{},
	}

	if !resolver.HasPermission(token, u.ID, "read") {
		t.Error("group should grant read permission")
	}
	if !resolver.HasPermission(token, u.ID, "write") {
		t.Error("group should grant write permission")
	}
	if resolver.HasPermission(token, u.ID, "delete") {
		t.Error("group should NOT grant delete permission")
	}
}

func TestResolver_GroupGrantsNamespace(t *testing.T) {
	resolver, u, _ := setupResolver(t)

	token := &model.Token{
		Permissions: []string{},
		Namespaces:  []string{},
	}

	if !resolver.CanAccessNamespace(token, u.ID, "production") {
		t.Error("group should grant access to production namespace")
	}
	if resolver.CanAccessNamespace(token, u.ID, "staging") {
		t.Error("group should NOT grant access to staging namespace")
	}
}

func TestResolver_NoUserID_FallsBackToToken(t *testing.T) {
	resolver, _, _ := setupResolver(t)

	token := &model.Token{
		Permissions: []string{"read"},
		Namespaces:  []string{"staging"},
	}

	// No userID = no group resolution.
	if !resolver.HasPermission(token, "", "read") {
		t.Error("token direct permission should work")
	}
	if resolver.HasPermission(token, "", "write") {
		t.Error("should not have write without group and without token perm")
	}
}
