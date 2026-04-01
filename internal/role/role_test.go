package role

import (
	"testing"

	"github.com/mariamills/burrow/internal/group"
	"github.com/mariamills/burrow/internal/model"
	"github.com/mariamills/burrow/internal/store"
	"github.com/mariamills/burrow/internal/user"
)

func setup(t *testing.T) (*Service, *user.Service, *group.Service, *store.Store) {
	t.Helper()
	db, err := store.New(":memory:")
	if err != nil {
		t.Fatalf("failed to create test store: %v", err)
	}
	userSvc := user.New(db, db)
	groupSvc := group.New(db, db)
	roleSvc := New(db, db, db)
	return roleSvc, userSvc, groupSvc, db
}

func TestCreateRole(t *testing.T) {
	svc, _, _, _ := setup(t)

	r, err := svc.Create(&model.CreateRoleRequest{
		Name:        "test-role",
		Description: "Test role",
		Permissions: []string{"read", "write"},
		Namespaces:  []string{"production"},
	})
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	if r.Name != "test-role" {
		t.Errorf("Name = %q, want test-role", r.Name)
	}
	if len(r.Permissions) != 2 {
		t.Errorf("got %d permissions, want 2", len(r.Permissions))
	}
}

func TestCreateRole_DuplicateName(t *testing.T) {
	svc, _, _, _ := setup(t)
	_, _ = svc.Create(&model.CreateRoleRequest{Name: "role-a", Permissions: []string{"read"}, Namespaces: []string{"*"}})
	_, err := svc.Create(&model.CreateRoleRequest{Name: "role-a", Permissions: []string{"read"}, Namespaces: []string{"*"}})
	if err == nil {
		t.Fatal("expected error for duplicate name")
	}
}

func TestCreateRole_InvalidPermission(t *testing.T) {
	svc, _, _, _ := setup(t)
	_, err := svc.Create(&model.CreateRoleRequest{
		Name: "bad-role", Permissions: []string{"superadmin"}, Namespaces: []string{"*"},
	})
	if err == nil {
		t.Fatal("expected error for invalid permission")
	}
}

func TestSeedDefaults(t *testing.T) {
	svc, _, _, _ := setup(t)

	if err := svc.SeedDefaults(); err != nil {
		t.Fatalf("SeedDefaults failed: %v", err)
	}

	roles, err := svc.List()
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(roles) != 4 {
		t.Errorf("got %d roles, want 4 seed roles", len(roles))
	}

	// Seeding again should be idempotent.
	if err := svc.SeedDefaults(); err != nil {
		t.Fatalf("second SeedDefaults failed: %v", err)
	}
	roles2, _ := svc.List()
	if len(roles2) != 4 {
		t.Errorf("got %d roles after re-seed, want 4", len(roles2))
	}
}

func TestAssignUserRole(t *testing.T) {
	svc, userSvc, _, db := setup(t)

	u, _ := userSvc.Register(&model.RegisterRequest{
		Email: "alice@example.com", Password: "strongpassword123",
	})
	r, _ := svc.Create(&model.CreateRoleRequest{
		Name: "reader", Permissions: []string{"read"}, Namespaces: []string{"production"},
	})

	if err := svc.AssignToUser(u.ID, r.ID); err != nil {
		t.Fatalf("AssignToUser failed: %v", err)
	}

	roles, err := db.GetUserRoles(u.ID)
	if err != nil {
		t.Fatalf("GetUserRoles failed: %v", err)
	}
	if len(roles) != 1 {
		t.Errorf("got %d roles, want 1", len(roles))
	}
	if roles[0].Name != "reader" {
		t.Errorf("role name = %q, want reader", roles[0].Name)
	}
}

func TestAssignGroupRole(t *testing.T) {
	svc, _, groupSvc, db := setup(t)

	g, _ := groupSvc.Create(&model.CreateGroupRequest{Name: "backend-team"})
	r, _ := svc.Create(&model.CreateRoleRequest{
		Name: "writer", Permissions: []string{"read", "write"}, Namespaces: []string{"staging"},
	})

	if err := svc.AssignToGroup(g.ID, r.ID); err != nil {
		t.Fatalf("AssignToGroup failed: %v", err)
	}

	roles, err := db.GetGroupRoles(g.ID)
	if err != nil {
		t.Fatalf("GetGroupRoles failed: %v", err)
	}
	if len(roles) != 1 {
		t.Errorf("got %d roles, want 1", len(roles))
	}
}

func TestEffectiveRoles_DirectAndViaGroup(t *testing.T) {
	svc, userSvc, groupSvc, db := setup(t)

	u, _ := userSvc.Register(&model.RegisterRequest{
		Email: "alice@example.com", Password: "strongpassword123",
	})
	g, _ := groupSvc.Create(&model.CreateGroupRequest{Name: "team-a"})
	_ = groupSvc.AddMember(g.ID, &model.AddMemberRequest{UserID: u.ID})

	r1, _ := svc.Create(&model.CreateRoleRequest{
		Name: "direct-role", Permissions: []string{"read"}, Namespaces: []string{"prod"},
	})
	r2, _ := svc.Create(&model.CreateRoleRequest{
		Name: "group-role", Permissions: []string{"write"}, Namespaces: []string{"staging"},
	})

	_ = svc.AssignToUser(u.ID, r1.ID)
	_ = svc.AssignToGroup(g.ID, r2.ID)

	effective, err := db.GetUserEffectiveRoles(u.ID)
	if err != nil {
		t.Fatalf("GetUserEffectiveRoles failed: %v", err)
	}
	if len(effective) != 2 {
		t.Errorf("got %d effective roles, want 2 (1 direct + 1 via group)", len(effective))
	}
}

func TestDeleteRole_Cascades(t *testing.T) {
	svc, userSvc, _, db := setup(t)

	u, _ := userSvc.Register(&model.RegisterRequest{
		Email: "alice@example.com", Password: "strongpassword123",
	})
	r, _ := svc.Create(&model.CreateRoleRequest{
		Name: "temp-role", Permissions: []string{"read"}, Namespaces: []string{"*"},
	})
	_ = svc.AssignToUser(u.ID, r.ID)

	if err := svc.Delete(r.ID); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	roles, _ := db.GetUserRoles(u.ID)
	if len(roles) != 0 {
		t.Errorf("got %d roles after delete, want 0 (cascade)", len(roles))
	}
}
