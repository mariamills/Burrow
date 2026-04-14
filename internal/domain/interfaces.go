// Package domain defines the core interfaces for Burrow's dependency injection
//
// These interfaces decouple the handler and middleware layers from concrete
// implementations, enabling testability and future backend swaps (e.g., SQLite → Postgres).
package domain

import (
	"time"

	"github.com/mariamills/burrow/internal/model"
)

// SecretStore defines the persistence contract for secrets
type SecretStore interface {
	UpsertSecret(secret *model.Secret) error
	GetSecret(namespace, key string) (*model.Secret, error)
	ListSecrets(namespace string) ([]*model.SecretMeta, error)
	DeleteSecret(namespace, key string) (bool, error)
	DeleteNamespace(namespace string) (int64, error)
	ListNamespaces() ([]string, error)
	SearchSecrets(namespace, pattern string) ([]*model.SecretMeta, error)
	GetExpiringSecrets(before time.Time) ([]*model.SecretMeta, error)
	GetExpiredSecrets() ([]*model.SecretMeta, error)
	Ping() error
}

// TokenStore defines the persistence contract for API tokens
type TokenStore interface {
	CreateToken(t *model.Token) error
	UpsertRootToken(t *model.Token) error
	GetAllActiveTokens() ([]*model.Token, error)
	GetTokenByID(id string) (*model.Token, error)
	ListTokens() ([]*model.Token, error)
	RevokeToken(id string) (bool, error)
	TouchToken(id string) error
}

// AuditStore defines the persistence contract for audit logging
type AuditStore interface {
	WriteAuditEvent(e *model.AuditEvent) error
	GetAuditLog(namespace string, limit int) ([]*model.AuditEvent, error)
}

// Encryptor defines the contract for encrypting and decrypting secret values
type Encryptor interface {
	Encrypt(plaintext string) (string, error)
	Decrypt(ciphertext string) (string, error)
}

// UserStore defines the persistence contract for user accounts.
type UserStore interface {
	CreateUser(u *model.User) error
	GetUserByEmail(email string) (*model.User, error)
	GetUserByID(id string) (*model.User, error)
	ListUsers() ([]*model.User, error)
	DeactivateUser(id string) error
	UpdateUserPassword(id string, hashedPassword string) error
}

// SessionStore defines the persistence contract for user sessions.
type SessionStore interface {
	CreateSession(s *model.Session) error
	GetSessionByHash(tokenHash string) (*model.Session, error)
	DeleteSession(id string) error
	DeleteUserSessions(userID string) error
	CleanExpiredSessions() (int64, error)
}

// GroupStore defines the persistence contract for groups, membership, and permissions.
type GroupStore interface {
	CreateGroup(g *model.Group) error
	GetGroupByID(id string) (*model.Group, error)
	GetGroupByName(name string) (*model.Group, error)
	ListGroups() ([]*model.Group, error)
	UpdateGroup(g *model.Group) error
	DeleteGroup(id string) error

	AddGroupMember(groupID, userID, role string) error
	RemoveGroupMember(groupID, userID string) error
	GetGroupMembers(groupID string) ([]*model.GroupMemberInfo, error)
	GetUserGroups(userID string) ([]*model.Group, error)

	SetGroupPermission(gp *model.GroupPermission) error
	GetGroupPermissions(groupID string) ([]*model.GroupPermission, error)
	GetUserGroupPermissions(userID string) ([]*model.GroupPermission, error)
}

// SessionValidator defines the contract for validating session tokens.
type SessionValidator interface {
	Validate(rawToken string) (*model.Session, error)
}

// RoleStore defines the persistence contract for roles and role assignments.
type RoleStore interface {
	CreateRole(r *model.Role) error
	GetRoleByID(id string) (*model.Role, error)
	GetRoleByName(name string) (*model.Role, error)
	ListRoles() ([]*model.Role, error)
	UpdateRole(r *model.Role) error
	DeleteRole(id string) error

	AssignUserRole(userID, roleID string) error
	RemoveUserRole(userID, roleID string) error
	GetUserRoles(userID string) ([]*model.Role, error)

	AssignGroupRole(groupID, roleID string) error
	RemoveGroupRole(groupID, roleID string) error
	GetGroupRoles(groupID string) ([]*model.Role, error)

	// GetUserEffectiveRoles returns roles assigned directly to the user
	// AND roles assigned to any group the user belongs to.
	GetUserEffectiveRoles(userID string) ([]*model.Role, error)
}

// VersionStore defines the persistence contract for secret versions.
type VersionStore interface {
	CreateSecretVersion(v *model.SecretVersion) error
	GetSecretVersions(namespace, key string) ([]*model.SecretVersionMeta, error)
	GetSecretVersion(namespace, key string, version int) (*model.SecretVersion, error)
	GetLatestVersionNumber(namespace, key string) (int, error)
}

// RotationStore defines the persistence contract for rotation policies.
type RotationStore interface {
	UpsertRotationPolicy(rp *model.RotationPolicy) error
	GetRotationPolicy(namespace, key string) (*model.RotationPolicy, error)
	GetDueRotations() ([]*model.RotationPolicy, error)
	UpdateRotationTimestamps(id string, lastRotated, nextRotation time.Time) error
}

// IdentityStore defines the persistence contract for identity providers
type IdentityStore interface {
	CreateIdentityProvider(p *model.IdentityProvider) error
	GetIdentityProvider(id string) (*model.IdentityProvider, error)
	GetIdentityProviderByName(name string) (*model.IdentityProvider, error)
	ListIdentityProviders() ([]*model.IdentityProvider, error)
	DeleteIdentityProvider(id string) error

	CreateUserIdentity(ui *model.UserIdentity) error
	GetUserIdentityByExternal(providerID, externalID string) (*model.UserIdentity, error)
	GetUserIdentities(userID string) ([]*model.UserIdentity, error)
}

// PermissionResolver resolves effective permissions for a user, merging token direct perms + group perms.
type PermissionResolver interface {
	// HasPermission checks if the user (identified by token + optional user ID)
	// has the given permission, considering both token and group permissions.
	HasPermission(token *model.Token, userID string, perm string) bool
	// CanAccessNamespace checks if the user can access the given namespace.
	CanAccessNamespace(token *model.Token, userID string, namespace string) bool
}

// Authenticator defines the contract for token authentication and management
type Authenticator interface {
	ValidateToken(rawToken string) (*model.Token, error)
	CreateToken(req *model.CreateTokenRequest) (*model.CreateTokenResponse, error)
	RevokeToken(id string) (bool, error)
	ListTokens() ([]*model.Token, error)
}
