// Package identity manages external identity providers (OIDC, LDAP)
//
// Flow:
//  1. Admin configures a provider via POST /v1/sys/identity-providers
//  2. User authenticates via the provider (OIDC redirect flow or LDAP bind)
//  3. Burrow resolves the external identity to a local user (auto-provision or link)
//  4. A session is created for the user
package identity

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/mariamills/burrow/internal/crypto"
	"github.com/mariamills/burrow/internal/domain"
	"github.com/mariamills/burrow/internal/model"
	"github.com/mariamills/burrow/pkg/logger"
)

// Provider is the interface for external identity providers
type Provider interface {
	// Type returns "oidc" or "ldap".
	Type() string
	// AuthURL returns the URL to redirect the user to for authentication (OIDC only)
	AuthURL(state string) string
	// ExchangeCode exchanges an authorization code for an identity (OIDC only)
	ExchangeCode(code string) (*model.ExternalIdentity, error)
	// Authenticate validates credentials directly (LDAP only).
	Authenticate(username, password string) (*model.ExternalIdentity, error)
}

// Service manages identity providers and user linking
type Service struct {
	store    domain.IdentityStore
	users    domain.UserStore
	sessions domain.SessionStore
	groups   domain.GroupStore
	enc      domain.Encryptor
}

// New creates a new identity Service
func New(store domain.IdentityStore, users domain.UserStore, sessions domain.SessionStore, groups domain.GroupStore, enc domain.Encryptor) *Service {
	return &Service{store: store, users: users, sessions: sessions, groups: groups, enc: enc}
}

// CreateProvider creates a new identity provider. The config is encrypted before storage
func (s *Service) CreateProvider(req *model.CreateIdentityProviderRequest) (*model.IdentityProvider, error) {
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return nil, fmt.Errorf("identity: name is required")
	}
	if req.Type != "oidc" && req.Type != "ldap" {
		return nil, fmt.Errorf("identity: type must be 'oidc' or 'ldap'")
	}
	if req.Config == "" {
		return nil, fmt.Errorf("identity: config is required")
	}

	// Validate the config JSON is parseable
	if req.Type == "oidc" {
		var cfg model.OIDCConfig
		if err := json.Unmarshal([]byte(req.Config), &cfg); err != nil {
			return nil, fmt.Errorf("identity: invalid OIDC config: %w", err)
		}
		if cfg.IssuerURL == "" || cfg.ClientID == "" || cfg.ClientSecret == "" {
			return nil, fmt.Errorf("identity: OIDC config requires issuer_url, client_id, client_secret")
		}
	} else {
		var cfg model.LDAPConfig
		if err := json.Unmarshal([]byte(req.Config), &cfg); err != nil {
			return nil, fmt.Errorf("identity: invalid LDAP config: %w", err)
		}
		if cfg.URL == "" || cfg.BindDN == "" || cfg.UserSearchBase == "" {
			return nil, fmt.Errorf("identity: LDAP config requires url, bind_dn, user_search_base")
		}
	}

	// Check for duplicate name
	existing, err := s.store.GetIdentityProviderByName(name)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return nil, fmt.Errorf("identity: provider name already exists")
	}

	// Encrypt the config before storage (contains secrets like client_secret, bind_password)
	encryptedConfig, err := s.enc.Encrypt(req.Config)
	if err != nil {
		return nil, fmt.Errorf("identity: failed to encrypt config: %w", err)
	}

	id, _ := crypto.GenerateID()
	provider := &model.IdentityProvider{
		ID:        id,
		Name:      name,
		Type:      req.Type,
		Config:    encryptedConfig,
		Active:    true,
		CreatedAt: time.Now(),
	}

	if err := s.store.CreateIdentityProvider(provider); err != nil {
		return nil, err
	}

	// Return without the encrypted config
	provider.Config = ""
	return provider, nil
}

// ListProviders returns all providers (configs excluded)
func (s *Service) ListProviders() ([]*model.IdentityProvider, error) {
	return s.store.ListIdentityProviders()
}

// DeleteProvider removes a provider
func (s *Service) DeleteProvider(id string) error {
	return s.store.DeleteIdentityProvider(id)
}

// GetProviderConfig retrieves and decrypts a provider's config.
func (s *Service) GetProviderConfig(providerID string) (string, *model.IdentityProvider, error) {
	provider, err := s.store.GetIdentityProvider(providerID)
	if err != nil {
		return "", nil, err
	}
	if provider == nil {
		return "", nil, fmt.Errorf("identity: provider not found")
	}
	if !provider.Active {
		return "", nil, fmt.Errorf("identity: provider is disabled")
	}

	configJSON, err := s.enc.Decrypt(provider.Config)
	if err != nil {
		return "", nil, fmt.Errorf("identity: failed to decrypt config: %w", err)
	}

	return configJSON, provider, nil
}

// ResolveExternalIdentity maps an external identity to a local Burrow user
// If auto-provisioning is enabled and no user exists, creates one
// Returns the user ID
func (s *Service) ResolveExternalIdentity(providerID string, ext *model.ExternalIdentity, autoProvision bool) (string, error) {
	// Check if this external identity is already linked.
	ui, err := s.store.GetUserIdentityByExternal(providerID, ext.ExternalID)
	if err != nil {
		return "", err
	}
	if ui != nil {
		return ui.UserID, nil
	}

	// Not linked - do NOT auto-link by email (prevents account takeover via compromised IdP setting an email matching an existing admin user)
	// Users must be explicitly linked by an admin or auto-provisioned as new accounts

	// No existing link - auto-provision if enabled
	if !autoProvision {
		return "", fmt.Errorf("identity: no matching user found and auto-provisioning is disabled")
	}

	// create a new user
	userID, err := s.provisionUser(ext)
	if err != nil {
		return "", err
	}

	// link the external identity
	if err := s.linkIdentity(providerID, userID, ext); err != nil {
		return "", err
	}

	// Map external groups to Burrow groups if available
	if len(ext.Groups) > 0 {
		s.mapGroups(userID, ext.Groups, providerID)
	}

	logger.Info("auto-provisioned user from external identity",
		"provider", ext.ProviderName, "email", ext.Email, "user_id", userID)

	return userID, nil
}

func (s *Service) provisionUser(ext *model.ExternalIdentity) (string, error) {
	id, _ := crypto.GenerateID()
	now := time.Now()

	// Generate and hash a random password (SSO users auth via provider, not password)
	randomPass, _ := crypto.GenerateToken(32)
	hashedPass, _ := bcrypt.GenerateFromPassword([]byte(randomPass), 12)

	user := &model.User{
		ID:        id,
		Email:     ext.Email,
		Password:  string(hashedPass),
		Name:      ext.DisplayName,
		Active:    true,
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := s.users.CreateUser(user); err != nil {
		return "", fmt.Errorf("identity: failed to create user: %w", err)
	}
	return id, nil
}

func (s *Service) linkIdentity(providerID, userID string, ext *model.ExternalIdentity) error {
	id, _ := crypto.GenerateID()
	return s.store.CreateUserIdentity(&model.UserIdentity{
		ID:         id,
		UserID:     userID,
		ProviderID: providerID,
		ExternalID: ext.ExternalID,
		Email:      ext.Email,
		CreatedAt:  time.Now(),
	})
}

func (s *Service) mapGroups(userID string, externalGroups []string, providerID string) {
	// Get the provider config to find group mappings.
	configJSON, provider, err := s.GetProviderConfig(providerID)
	if err != nil {
		logger.Error("identity: failed to get provider config for group mapping", "error", err)
		return
	}

	var mapping map[string]string
	if provider.Type == "oidc" {
		var cfg model.OIDCConfig
		json.Unmarshal([]byte(configJSON), &cfg)
		mapping = cfg.GroupMapping
	} else {
		var cfg model.LDAPConfig
		json.Unmarshal([]byte(configJSON), &cfg)
		mapping = cfg.GroupMapping
	}

	if len(mapping) == 0 {
		return
	}

	for _, extGroup := range externalGroups {
		if burrowGroupID, ok := mapping[extGroup]; ok {
			if s.groups != nil {
				if err := s.groups.AddGroupMember(burrowGroupID, userID, "member"); err != nil {
					logger.Warn("identity: failed to add user to mapped group",
						"user_id", userID, "group_id", burrowGroupID, "error", err)
				}
			}
		}
	}
}
