package group

import (
	"testing"

	"github.com/mariamills/burrow/internal/model"
	"github.com/mariamills/burrow/internal/store"
	"github.com/mariamills/burrow/internal/user"
)

func setup(t *testing.T) (*Service, *user.Service, *store.Store) {
	t.Helper()
	db, err := store.New(":memory:")
	if err != nil {
		t.Fatalf("failed to create test store: %v", err)
	}
	userSvc := user.New(db, db)
	groupSvc := New(db, db)
	return groupSvc, userSvc, db
}

func TestCreateGroup(t *testing.T) {
	svc, _, _ := setup(t)

	g, err := svc.Create(&model.CreateGroupRequest{
		Name:        "backend-team",
		Description: "Backend developers",
	})
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	if g.Name != "backend-team" {
		t.Errorf("Name = %q, want backend-team", g.Name)
	}
	if g.ID == "" {
		t.Error("ID should not be empty")
	}
}

func TestCreateGroup_DuplicateName(t *testing.T) {
	svc, _, _ := setup(t)

	_, _ = svc.Create(&model.CreateGroupRequest{Name: "team-a"})
	_, err := svc.Create(&model.CreateGroupRequest{Name: "team-a"})
	if err == nil {
		t.Fatal("expected error for duplicate name")
	}
}

func TestCreateGroup_EmptyName(t *testing.T) {
	svc, _, _ := setup(t)

	_, err := svc.Create(&model.CreateGroupRequest{Name: ""})
	if err == nil {
		t.Fatal("expected error for empty name")
	}
}

func TestListGroups(t *testing.T) {
	svc, _, _ := setup(t)

	_, _ = svc.Create(&model.CreateGroupRequest{Name: "team-a"})
	_, _ = svc.Create(&model.CreateGroupRequest{Name: "team-b"})

	groups, err := svc.List()
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(groups) != 2 {
		t.Errorf("got %d groups, want 2", len(groups))
	}
}

func TestGetGroupDetail(t *testing.T) {
	svc, userSvc, _ := setup(t)

	g, _ := svc.Create(&model.CreateGroupRequest{Name: "team-a"})
	u, _ := userSvc.Register(&model.RegisterRequest{
		Email: "alice@example.com", Password: "strongpassword123", Name: "Alice",
	})
	_ = svc.AddMember(g.ID, &model.AddMemberRequest{UserID: u.ID, Role: "admin"})
	_ = svc.SetPermissions(g.ID, &model.SetGroupPermissionsRequest{
		Namespace: "production", Permissions: []string{"read", "write"},
	})

	detail, err := svc.Get(g.ID)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if detail == nil {
		t.Fatal("detail should not be nil")
	}
	if len(detail.Members) != 1 {
		t.Errorf("got %d members, want 1", len(detail.Members))
	}
	if detail.Members[0].Email != "alice@example.com" {
		t.Errorf("member email = %q, want alice@example.com", detail.Members[0].Email)
	}
	if len(detail.Permissions) != 1 {
		t.Errorf("got %d permissions, want 1", len(detail.Permissions))
	}
	if detail.Permissions[0].Namespace != "production" {
		t.Errorf("namespace = %q, want production", detail.Permissions[0].Namespace)
	}
}

func TestUpdateGroup(t *testing.T) {
	svc, _, _ := setup(t)

	g, _ := svc.Create(&model.CreateGroupRequest{Name: "team-a"})

	updated, err := svc.Update(g.ID, &model.UpdateGroupRequest{
		Name: "team-alpha", Description: "Updated team",
	})
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}
	if updated.Name != "team-alpha" {
		t.Errorf("Name = %q, want team-alpha", updated.Name)
	}
}

func TestDeleteGroup_CascadesMembers(t *testing.T) {
	svc, userSvc, _ := setup(t)

	g, _ := svc.Create(&model.CreateGroupRequest{Name: "team-a"})
	u, _ := userSvc.Register(&model.RegisterRequest{
		Email: "alice@example.com", Password: "strongpassword123",
	})
	_ = svc.AddMember(g.ID, &model.AddMemberRequest{UserID: u.ID})

	if err := svc.Delete(g.ID); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	detail, _ := svc.Get(g.ID)
	if detail != nil {
		t.Error("group should be deleted")
	}
}

func TestAddMember_InvalidRole(t *testing.T) {
	svc, userSvc, _ := setup(t)

	g, _ := svc.Create(&model.CreateGroupRequest{Name: "team-a"})
	u, _ := userSvc.Register(&model.RegisterRequest{
		Email: "alice@example.com", Password: "strongpassword123",
	})

	err := svc.AddMember(g.ID, &model.AddMemberRequest{UserID: u.ID, Role: "superadmin"})
	if err == nil {
		t.Fatal("expected error for invalid role")
	}
}

func TestSetPermissions_InvalidPermission(t *testing.T) {
	svc, _, _ := setup(t)

	g, _ := svc.Create(&model.CreateGroupRequest{Name: "team-a"})
	err := svc.SetPermissions(g.ID, &model.SetGroupPermissionsRequest{
		Namespace: "prod", Permissions: []string{"read", "superwrite"},
	})
	if err == nil {
		t.Fatal("expected error for invalid permission")
	}
}

func TestRemoveMember(t *testing.T) {
	svc, userSvc, _ := setup(t)

	g, _ := svc.Create(&model.CreateGroupRequest{Name: "team-a"})
	u, _ := userSvc.Register(&model.RegisterRequest{
		Email: "alice@example.com", Password: "strongpassword123",
	})
	_ = svc.AddMember(g.ID, &model.AddMemberRequest{UserID: u.ID})

	if err := svc.RemoveMember(g.ID, u.ID); err != nil {
		t.Fatalf("RemoveMember failed: %v", err)
	}

	detail, _ := svc.Get(g.ID)
	if len(detail.Members) != 0 {
		t.Errorf("got %d members after remove, want 0", len(detail.Members))
	}
}
