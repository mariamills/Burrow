// Package model defines the core domain types
package model

import "time"

// Secret represents an encrypted key-value secret stored in the vault
type Secret struct {
	ID        string `json:"id"`
	Namespace string `json:"namespace"`
	Key       string `json:"key"`
	// Value is NEVER included in API responses — only returned on explicit Get
	Value       string     `json:"value,omitempty"`
	Description string     `json:"description,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	CreatedBy   string     `json:"created_by"` // token ID that created this secret
}

// IsExpiredSecret returns true if the secret has a TTL and it has passed.
func (s *Secret) IsExpiredSecret() bool {
	if s.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*s.ExpiresAt)
}

// Token represents an API access token scoped to one or more namespaces.
type Token struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Hash is the bcrypt hash of the raw token - never returned in responses.
	Hash        string     `json:"-"`
	Namespaces  []string   `json:"namespaces"`  // "*" means all namespaces (root token)
	Permissions []string   `json:"permissions"` // "read", "write", "delete", "admin"
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
	Active      bool       `json:"active"`
}

// AuditEvent records every access attempt to the vault.
type AuditEvent struct {
	ID         int64     `json:"id"`
	TokenID    string    `json:"token_id"`
	TokenName  string    `json:"token_name"`
	Action     string    `json:"action"` // "read", "write", "delete", "list", "auth_fail"
	Namespace  string    `json:"namespace"`
	SecretKey  string    `json:"secret_key"`
	StatusCode int       `json:"status_code"`
	IPAddress  string    `json:"ip_address"`
	UserAgent  string    `json:"user_agent"`
	Timestamp  time.Time `json:"timestamp"`
}

// ---- Request/Response DTOs ----

// CreateSecretRequest is the request body for POST /v1/secrets/:namespace/:key
type CreateSecretRequest struct {
	Value       string     `json:"value"`
	Description string     `json:"description,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"` // optional TTL
}

// SecretResponse is returned when reading a single secret (includes value).
type SecretResponse struct {
	ID          string     `json:"id"`
	Namespace   string     `json:"namespace"`
	Key         string     `json:"key"`
	Value       string     `json:"value"`
	Description string     `json:"description,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// SecretMeta is returned in list responses (NO value field — intentional).
type SecretMeta struct {
	ID          string     `json:"id"`
	Namespace   string     `json:"namespace"`
	Key         string     `json:"key"`
	Description string     `json:"description,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// CreateTokenRequest is the request body for POST /v1/tokens
type CreateTokenRequest struct {
	Name        string     `json:"name"`
	Namespaces  []string   `json:"namespaces"`
	Permissions []string   `json:"permissions"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

// CreateTokenResponse includes the raw token ONCE — it is never stored or retrievable again.
type CreateTokenResponse struct {
	Token     string    `json:"token"` // raw token — show once, store nowhere
	TokenID   string    `json:"token_id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

// APIError is the standard error response envelope.
type APIError struct {
	Error   string `json:"error"`
	Code    string `json:"code,omitempty"`
	Details string `json:"details,omitempty"`
}

// APIResponse is the standard success response envelope.
type APIResponse struct {
	Data    interface{} `json:"data"`
	Message string      `json:"message,omitempty"`
}

// HealthResponse is returned by GET /health
type HealthResponse struct {
	Status    string    `json:"status"`
	Version   string    `json:"version"`
	Timestamp time.Time `json:"timestamp"`
	DBStatus  string    `json:"db_status"`
}

// ---- User & Session Types ----

// User represents a registered Burrow user account.
type User struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	Password  string    `json:"-"` // bcrypt hash — never returned in responses
	Name      string    `json:"name"`
	Active    bool      `json:"active"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Session represents an authenticated user session.
type Session struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	TokenHash string    `json:"-"` // SHA-256 hash of session token
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
	IPAddress string    `json:"ip_address"`
	UserAgent string    `json:"user_agent"`
}

// RegisterRequest is the request body for POST /v1/auth/register
type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Name     string `json:"name"`
}

// LoginRequest is the request body for POST /v1/auth/login
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// LoginResponse is returned on successful login.
type LoginResponse struct {
	Token     string    `json:"token"` // raw session token — shown once
	ExpiresAt time.Time `json:"expires_at"`
	User      *User     `json:"user"`
}

// ResetPasswordRequest is the request body for PUT /v1/users/{id}/password.
type ResetPasswordRequest struct {
	Password string `json:"password"`
}

// ---- Group Types ----

// Group represents a team or organizational unit.
type Group struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// GroupMember represents a user's membership in a group.
type GroupMember struct {
	GroupID string    `json:"group_id"`
	UserID  string    `json:"user_id"`
	Role    string    `json:"role"` // "member" or "admin"
	AddedAt time.Time `json:"added_at"`
}

// GroupPermission defines a group's access to a namespace.
type GroupPermission struct {
	ID          string   `json:"id"`
	GroupID     string   `json:"group_id"`
	Namespace   string   `json:"namespace"`
	Permissions []string `json:"permissions"`
}

// GroupDetail is a group with its members and permissions (for GET responses).
type GroupDetail struct {
	Group       *Group             `json:"group"`
	Members     []*GroupMemberInfo `json:"members"`
	Permissions []*GroupPermission `json:"permissions"`
}

// GroupMemberInfo is a group member with user info attached.
type GroupMemberInfo struct {
	UserID  string    `json:"user_id"`
	Email   string    `json:"email"`
	Name    string    `json:"name"`
	Role    string    `json:"role"`
	AddedAt time.Time `json:"added_at"`
}

// CreateGroupRequest is the request body for POST /v1/groups.
type CreateGroupRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// UpdateGroupRequest is the request body for PUT /v1/groups/{id}.
type UpdateGroupRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// AddMemberRequest is the request body for POST /v1/groups/{id}/members.
type AddMemberRequest struct {
	UserID string `json:"user_id"`
	Role   string `json:"role"` // optional, defaults to "member"
}

// SetGroupPermissionsRequest is the request body for PUT /v1/groups/{id}/permissions.
type SetGroupPermissionsRequest struct {
	Namespace   string   `json:"namespace"`
	Permissions []string `json:"permissions"`
}

// ---- Role Types ----

// Role represents a predefined permission bundle.
type Role struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Permissions []string  `json:"permissions"`
	Namespaces  []string  `json:"namespaces"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// CreateRoleRequest is the request body for POST /v1/roles.
type CreateRoleRequest struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Permissions []string `json:"permissions"`
	Namespaces  []string `json:"namespaces"`
}

// UpdateRoleRequest is the request body for PUT /v1/roles/{id}.
type UpdateRoleRequest struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Permissions []string `json:"permissions"`
	Namespaces  []string `json:"namespaces"`
}

// AssignRoleRequest is the request body for POST /v1/users/{id}/roles or /v1/groups/{id}/roles.
type AssignRoleRequest struct {
	RoleID string `json:"role_id"`
}

// ---- Rotation / Versioning Types ----

// SecretVersion represents a historical version of a secret.
type SecretVersion struct {
	ID        string    `json:"id"`
	Namespace string    `json:"namespace"`
	Key       string    `json:"key"`
	Value     string    `json:"value,omitempty"` // encrypted ciphertext
	Version   int       `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by"`
}

// RotationPolicy defines an autorotation schedule for a secret.
type RotationPolicy struct {
	ID           string     `json:"id"`
	Namespace    string     `json:"namespace"`
	Key          string     `json:"key"`
	IntervalSecs int        `json:"interval_secs"`
	CallbackURL  string     `json:"callback_url,omitempty"`
	LastRotated  *time.Time `json:"last_rotated,omitempty"`
	NextRotation *time.Time `json:"next_rotation,omitempty"`
	Active       bool       `json:"active"`
}

// SetRotationPolicyRequest is the request body for PUT /v1/secrets/{ns}/{key}/rotation-policy.
type SetRotationPolicyRequest struct {
	IntervalSecs int    `json:"interval_secs"` // rotation interval in seconds
	CallbackURL  string `json:"callback_url"`  // optional URL to call for new value
}

// SecretVersionMeta is a version without the encrypted value (for list responses).
type SecretVersionMeta struct {
	ID        string    `json:"id"`
	Version   int       `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by"`
}

// ---- Identity Federation Types ----

// IdentityProvider represents a configured SSO/LDAP/OIDC provider.
type IdentityProvider struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Type      string    `json:"type"` // "oidc" or "ldap"
	Config    string    `json:"-"`    // encrypted JSON config blob — never in responses
	Active    bool      `json:"active"`
	CreatedAt time.Time `json:"created_at"`
}

// UserIdentity links a Burrow user to an external identity provider.
type UserIdentity struct {
	ID         string    `json:"id"`
	UserID     string    `json:"user_id"`
	ProviderID string    `json:"provider_id"`
	ExternalID string    `json:"external_id"`
	Email      string    `json:"email"`
	CreatedAt  time.Time `json:"created_at"`
}

// OIDCConfig holds configuration for an OIDC provider.
type OIDCConfig struct {
	IssuerURL     string            `json:"issuer_url"`
	ClientID      string            `json:"client_id"`
	ClientSecret  string            `json:"client_secret"`
	RedirectURL   string            `json:"redirect_url"`
	Scopes        []string          `json:"scopes"`
	GroupMapping  map[string]string `json:"group_mapping,omitempty"` // external group → burrow group ID
	AutoProvision bool              `json:"auto_provision"`          // auto-create user on first login
}

// LDAPConfig holds configuration for an LDAP provider.
type LDAPConfig struct {
	URL             string            `json:"url"`     // e.g. "ldaps://ldap.example.com:636"
	BindDN          string            `json:"bind_dn"` // service account DN
	BindPassword    string            `json:"bind_password"`
	UserSearchBase  string            `json:"user_search_base"` // e.g. "ou=users,dc=example,dc=com"
	UserSearchAttr  string            `json:"user_search_attr"` // e.g. "uid" or "sAMAccountName"
	EmailAttr       string            `json:"email_attr"`       // e.g. "mail"
	GroupSearchBase string            `json:"group_search_base"`
	GroupAttr       string            `json:"group_attr"` // e.g. "memberOf"
	GroupMapping    map[string]string `json:"group_mapping,omitempty"`
	AutoProvision   bool              `json:"auto_provision"`
}

// CreateIdentityProviderRequest is the request body for POST /v1/sys/identity-providers.
type CreateIdentityProviderRequest struct {
	Name   string `json:"name"`
	Type   string `json:"type"`   // "oidc" or "ldap"
	Config string `json:"config"` // JSON string of OIDCConfig or LDAPConfig
}

// ExternalIdentity represents a user authenticated by an external provider.
type ExternalIdentity struct {
	ProviderName string
	ExternalID   string
	Email        string
	DisplayName  string
	Groups       []string
}

// Permission constants
const (
	PermRead   = "read"
	PermWrite  = "write"
	PermDelete = "delete"
	PermAdmin  = "admin"
)

// HasPermission returns true if the token has the given permission.
func (t *Token) HasPermission(perm string) bool {
	for _, p := range t.Permissions {
		if p == perm || p == PermAdmin {
			return true
		}
	}
	return false
}

// CanAccessNamespace returns true if the token can access the given namespace.
func (t *Token) CanAccessNamespace(ns string) bool {
	for _, n := range t.Namespaces {
		if n == "*" || n == ns {
			return true
		}
	}
	return false
}

// IsExpired returns true if the token has an expiry and it has passed.
func (t *Token) IsExpired() bool {
	if t.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*t.ExpiresAt)
}
