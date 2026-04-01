package middleware

import (
	"github.com/mariamills/burrow/internal/domain"
	"github.com/mariamills/burrow/internal/model"
	"github.com/mariamills/burrow/pkg/logger"
)

// GroupPermissionResolver resolves permissions by merging token permissions
// with group-based permissions and role-based permissions from the store.
//
// Resolution order (union-based any source granting is sufficient):
//  1. Token direct permissions/namespaces
//  2. User's effective roles (direct + via group membership)
//  3. User's group direct permissions
type GroupPermissionResolver struct {
	groups domain.GroupStore
	roles  domain.RoleStore
}

// NewPermissionResolver creates a resolver backed by the group and role stores.
func NewPermissionResolver(groups domain.GroupStore, roles domain.RoleStore) *GroupPermissionResolver {
	return &GroupPermissionResolver{groups: groups, roles: roles}
}

// HasPermission returns true if the token, roles, or groups grant the permission.
func (r *GroupPermissionResolver) HasPermission(token *model.Token, userID string, perm string) bool {
	// 1. Token direct permissions (fast path).
	if token.HasPermission(perm) {
		return true
	}

	if userID == "" {
		return false
	}

	// 2. Check role-based permissions.
	if r.roles != nil {
		roles, err := r.roles.GetUserEffectiveRoles(userID)
		if err != nil {
			logger.Error("resolver: failed to get user roles", "user_id", userID, "error", err)
		} else {
			for _, role := range roles {
				for _, p := range role.Permissions {
					if p == perm || p == model.PermAdmin {
						return true
					}
				}
			}
		}
	}

	// 3. Check group direct permissions.
	if r.groups != nil {
		groupPerms, err := r.groups.GetUserGroupPermissions(userID)
		if err != nil {
			logger.Error("resolver: failed to get group permissions", "user_id", userID, "error", err)
		} else {
			for _, gp := range groupPerms {
				for _, p := range gp.Permissions {
					if p == perm || p == model.PermAdmin {
						return true
					}
				}
			}
		}
	}

	return false
}

// CanAccessNamespace returns true if the token, roles, or groups grant namespace access.
func (r *GroupPermissionResolver) CanAccessNamespace(token *model.Token, userID string, namespace string) bool {
	// 1. Token direct namespace access.
	if token.CanAccessNamespace(namespace) {
		return true
	}

	if userID == "" {
		return false
	}

	// 2. Check role-based namespace access.
	if r.roles != nil {
		roles, err := r.roles.GetUserEffectiveRoles(userID)
		if err != nil {
			logger.Error("resolver: failed to get user roles", "user_id", userID, "error", err)
		} else {
			for _, role := range roles {
				for _, ns := range role.Namespaces {
					if ns == "*" || ns == namespace {
						return true
					}
				}
			}
		}
	}

	// 3. Check group direct namespace access.
	if r.groups != nil {
		groupPerms, err := r.groups.GetUserGroupPermissions(userID)
		if err != nil {
			logger.Error("resolver: failed to get group permissions", "user_id", userID, "error", err)
		} else {
			for _, gp := range groupPerms {
				if gp.Namespace == "*" || gp.Namespace == namespace {
					return true
				}
			}
		}
	}

	return false
}
