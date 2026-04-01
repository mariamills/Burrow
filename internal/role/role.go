// Package role provides role/template management
package role

import (
	"fmt"
	"strings"
	"time"

	"github.com/mariamills/burrow/internal/crypto"
	"github.com/mariamills/burrow/internal/domain"
	"github.com/mariamills/burrow/internal/model"
)

// Service handles role operations
type Service struct {
	roles  domain.RoleStore
	users  domain.UserStore
	groups domain.GroupStore
}

// New creates a new role Service
func New(r domain.RoleStore, u domain.UserStore, g domain.GroupStore) *Service {
	return &Service{roles: r, users: u, groups: g}
}

// Create creates a new role
func (s *Service) Create(req *model.CreateRoleRequest) (*model.Role, error) {
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return nil, fmt.Errorf("role: name is required")
	}
	if len(name) > 128 {
		return nil, fmt.Errorf("role: name must be at most 128 characters")
	}
	if len(req.Permissions) == 0 {
		return nil, fmt.Errorf("role: at least one permission is required")
	}
	if len(req.Namespaces) == 0 {
		return nil, fmt.Errorf("role: at least one namespace is required")
	}

	if err := validatePermissions(req.Permissions); err != nil {
		return nil, err
	}
	if err := validateNamespaces(req.Namespaces); err != nil {
		return nil, err
	}

	existing, err := s.roles.GetRoleByName(name)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return nil, fmt.Errorf("role: name already taken")
	}

	id, err := crypto.GenerateID()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	r := &model.Role{
		ID:          id,
		Name:        name,
		Description: strings.TrimSpace(req.Description),
		Permissions: req.Permissions,
		Namespaces:  req.Namespaces,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if err := s.roles.CreateRole(r); err != nil {
		return nil, err
	}
	return r, nil
}

// Get returns a role by ID
func (s *Service) Get(id string) (*model.Role, error) {
	return s.roles.GetRoleByID(id)
}

// List returns all roles
func (s *Service) List() ([]*model.Role, error) {
	return s.roles.ListRoles()
}

// Update modifies a role.
func (s *Service) Update(id string, req *model.UpdateRoleRequest) (*model.Role, error) {
	r, err := s.roles.GetRoleByID(id)
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, fmt.Errorf("role: not found")
	}

	if name := strings.TrimSpace(req.Name); name != "" && name != r.Name {
		existing, err := s.roles.GetRoleByName(name)
		if err != nil {
			return nil, err
		}
		if existing != nil {
			return nil, fmt.Errorf("role: name already taken")
		}
		r.Name = name
	}
	if req.Description != "" {
		r.Description = strings.TrimSpace(req.Description)
	}
	if len(req.Permissions) > 0 {
		if err := validatePermissions(req.Permissions); err != nil {
			return nil, err
		}
		r.Permissions = req.Permissions
	}
	if len(req.Namespaces) > 0 {
		r.Namespaces = req.Namespaces
	}
	r.UpdatedAt = time.Now()

	if err := s.roles.UpdateRole(r); err != nil {
		return nil, err
	}
	return r, nil
}

// Delete removes a role
func (s *Service) Delete(id string) error {
	return s.roles.DeleteRole(id)
}

// AssignToUser assigns a role to a user
func (s *Service) AssignToUser(userID, roleID string) error {
	u, err := s.users.GetUserByID(userID)
	if err != nil || u == nil {
		return fmt.Errorf("role: user not found")
	}
	r, err := s.roles.GetRoleByID(roleID)
	if err != nil || r == nil {
		return fmt.Errorf("role: role not found")
	}
	return s.roles.AssignUserRole(userID, roleID)
}

// RemoveFromUser removes a role from a user
func (s *Service) RemoveFromUser(userID, roleID string) error {
	return s.roles.RemoveUserRole(userID, roleID)
}

// AssignToGroup assigns a role to a group
func (s *Service) AssignToGroup(groupID, roleID string) error {
	g, err := s.groups.GetGroupByID(groupID)
	if err != nil || g == nil {
		return fmt.Errorf("role: group not found")
	}
	r, err := s.roles.GetRoleByID(roleID)
	if err != nil || r == nil {
		return fmt.Errorf("role: role not found")
	}
	return s.roles.AssignGroupRole(groupID, roleID)
}

// RemoveFromGroup removes a role from a group
func (s *Service) RemoveFromGroup(groupID, roleID string) error {
	return s.roles.RemoveGroupRole(groupID, roleID)
}

// SeedDefaults creates built-in roles if they don't already exist.
func (s *Service) SeedDefaults() error {
	defaults := []model.CreateRoleRequest{
		{Name: "vault-admin", Description: "Full access to all namespaces and operations", Permissions: []string{model.PermAdmin}, Namespaces: []string{"*"}},
		{Name: "secret-reader", Description: "Read-only access to all namespaces", Permissions: []string{model.PermRead}, Namespaces: []string{"*"}},
		{Name: "secret-writer", Description: "Read and write access to all namespaces", Permissions: []string{model.PermRead, model.PermWrite}, Namespaces: []string{"*"}},
		{Name: "auditor", Description: "Read-only access to audit logs", Permissions: []string{model.PermRead}, Namespaces: []string{"*"}},
	}

	for _, req := range defaults {
		existing, _ := s.roles.GetRoleByName(req.Name)
		if existing != nil {
			continue // already exists
		}
		if _, err := s.Create(&req); err != nil {
			return fmt.Errorf("role: failed to seed %q: %w", req.Name, err)
		}
	}
	return nil
}

func validateNamespaces(namespaces []string) error {
	for _, ns := range namespaces {
		if ns == "*" {
			continue
		}
		if ns == "" || len(ns) > 128 {
			return fmt.Errorf("role: invalid namespace %q", ns)
		}
		for _, r := range ns {
			if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
				(r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.') {
				return fmt.Errorf("role: namespace %q contains invalid characters", ns)
			}
		}
	}
	return nil
}

func validatePermissions(perms []string) error {
	valid := map[string]bool{
		model.PermRead: true, model.PermWrite: true,
		model.PermDelete: true, model.PermAdmin: true,
	}
	for _, p := range perms {
		if !valid[p] {
			return fmt.Errorf("role: invalid permission %q", p)
		}
	}
	return nil
}
