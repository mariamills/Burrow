// Package group provides group/team management
package group

import (
	"fmt"
	"strings"
	"time"

	"github.com/mariamills/burrow/internal/crypto"
	"github.com/mariamills/burrow/internal/domain"
	"github.com/mariamills/burrow/internal/model"
)

// Service handles group operations
type Service struct {
	groups domain.GroupStore
	users  domain.UserStore
}

// New creates a new group Service
func New(g domain.GroupStore, u domain.UserStore) *Service {
	return &Service{groups: g, users: u}
}

// Create creates a new group.
func (s *Service) Create(req *model.CreateGroupRequest) (*model.Group, error) {
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return nil, fmt.Errorf("group: name is required")
	}
	if len(name) > 128 {
		return nil, fmt.Errorf("group: name must be at most 128 characters")
	}
	if !isValidGroupName(name) {
		return nil, fmt.Errorf("group: name may only contain letters, numbers, hyphens, and underscores")
	}

	existing, err := s.groups.GetGroupByName(name)
	if err != nil {
		return nil, fmt.Errorf("group: failed to check name: %w", err)
	}
	if existing != nil {
		return nil, fmt.Errorf("group: name already taken")
	}

	id, err := crypto.GenerateID()
	if err != nil {
		return nil, fmt.Errorf("group: failed to generate ID: %w", err)
	}

	now := time.Now()
	g := &model.Group{
		ID:          id,
		Name:        name,
		Description: strings.TrimSpace(req.Description),
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if err := s.groups.CreateGroup(g); err != nil {
		return nil, fmt.Errorf("group: create failed: %w", err)
	}
	return g, nil
}

// Get returns a group with its members and permissions
func (s *Service) Get(id string) (*model.GroupDetail, error) {
	g, err := s.groups.GetGroupByID(id)
	if err != nil {
		return nil, err
	}
	if g == nil {
		return nil, nil
	}

	members, err := s.groups.GetGroupMembers(id)
	if err != nil {
		return nil, err
	}

	perms, err := s.groups.GetGroupPermissions(id)
	if err != nil {
		return nil, err
	}

	if members == nil {
		members = []*model.GroupMemberInfo{}
	}
	if perms == nil {
		perms = []*model.GroupPermission{}
	}

	return &model.GroupDetail{
		Group:       g,
		Members:     members,
		Permissions: perms,
	}, nil
}

// List returns all groups
func (s *Service) List() ([]*model.Group, error) {
	return s.groups.ListGroups()
}

// Update modifies a group's name and description.
func (s *Service) Update(id string, req *model.UpdateGroupRequest) (*model.Group, error) {
	g, err := s.groups.GetGroupByID(id)
	if err != nil {
		return nil, err
	}
	if g == nil {
		return nil, fmt.Errorf("group: not found")
	}

	name := strings.TrimSpace(req.Name)
	if name != "" && name != g.Name {
		existing, err := s.groups.GetGroupByName(name)
		if err != nil {
			return nil, err
		}
		if existing != nil {
			return nil, fmt.Errorf("group: name already taken")
		}
		g.Name = name
	}
	if req.Description != "" {
		g.Description = strings.TrimSpace(req.Description)
	}
	g.UpdatedAt = time.Now()

	if err := s.groups.UpdateGroup(g); err != nil {
		return nil, err
	}
	return g, nil
}

// Delete removes a group and cascades to members/permissions
func (s *Service) Delete(id string) error {
	return s.groups.DeleteGroup(id)
}

// AddMember adds a user to a group.
func (s *Service) AddMember(groupID string, req *model.AddMemberRequest) error {
	if req.UserID == "" {
		return fmt.Errorf("group: user_id is required")
	}

	// Verify group exists.
	g, err := s.groups.GetGroupByID(groupID)
	if err != nil {
		return err
	}
	if g == nil {
		return fmt.Errorf("group: not found")
	}

	// Verify user exists.
	u, err := s.users.GetUserByID(req.UserID)
	if err != nil {
		return err
	}
	if u == nil {
		return fmt.Errorf("group: user not found")
	}

	role := req.Role
	if role == "" {
		role = "member"
	}
	if role != "member" && role != "admin" {
		return fmt.Errorf("group: role must be 'member' or 'admin'")
	}

	return s.groups.AddGroupMember(groupID, req.UserID, role)
}

// RemoveMember removes a user from a group
func (s *Service) RemoveMember(groupID, userID string) error {
	return s.groups.RemoveGroupMember(groupID, userID)
}

// SetPermissions sets a group's namespace permissions
func (s *Service) SetPermissions(groupID string, req *model.SetGroupPermissionsRequest) error {
	if req.Namespace == "" {
		return fmt.Errorf("group: namespace is required")
	}
	if len(req.Permissions) == 0 {
		return fmt.Errorf("group: at least one permission is required")
	}

	// Validate permissions.
	valid := map[string]bool{
		model.PermRead: true, model.PermWrite: true,
		model.PermDelete: true, model.PermAdmin: true,
	}
	for _, p := range req.Permissions {
		if !valid[p] {
			return fmt.Errorf("group: invalid permission %q", p)
		}
	}

	id, err := crypto.GenerateID()
	if err != nil {
		return err
	}

	return s.groups.SetGroupPermission(&model.GroupPermission{
		ID:          id,
		GroupID:     groupID,
		Namespace:   req.Namespace,
		Permissions: req.Permissions,
	})
}

// isValidGroupName checks that a group name only contains safe characters
func isValidGroupName(s string) bool {
	for _, r := range s {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '_') {
			return false
		}
	}
	return true
}
