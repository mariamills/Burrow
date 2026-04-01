package identity

import (
	"encoding/json"
	"testing"

	"github.com/mariamills/burrow/internal/crypto"
	"github.com/mariamills/burrow/internal/group"
	"github.com/mariamills/burrow/internal/model"
	"github.com/mariamills/burrow/internal/store"
	"github.com/mariamills/burrow/internal/user"
)

func setup(t *testing.T) (*Service, *store.Store) {
	t.Helper()
	db, err := store.New(":memory:")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	enc, err := crypto.New([]byte("this-is-a-test-key-at-least-32ch"))
	if err != nil {
		t.Fatalf("crypto: %v", err)
	}
	svc := New(db, db, db, db, enc)
	return svc, db
}

func TestCreateProvider_OIDC(t *testing.T) {
	svc, _ := setup(t)

	oidcConfig, _ := json.Marshal(model.OIDCConfig{
		IssuerURL:    "https://accounts.google.com",
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		RedirectURL:  "https://burrow.example.com/v1/auth/oidc/callback",
		Scopes:       []string{"openid", "email", "profile"},
	})

	provider, err := svc.CreateProvider(&model.CreateIdentityProviderRequest{
		Name:   "google",
		Type:   "oidc",
		Config: string(oidcConfig),
	})
	if err != nil {
		t.Fatalf("CreateProvider failed: %v", err)
	}
	if provider.Name != "google" {
		t.Errorf("name = %q, want google", provider.Name)
	}
	if provider.Type != "oidc" {
		t.Errorf("type = %q, want oidc", provider.Type)
	}
	if provider.Config != "" {
		t.Error("config should be empty in response (encrypted in DB)")
	}
}

func TestCreateProvider_LDAP(t *testing.T) {
	svc, _ := setup(t)

	ldapConfig, _ := json.Marshal(model.LDAPConfig{
		URL:            "ldaps://ldap.example.com:636",
		BindDN:         "cn=admin,dc=example,dc=com",
		BindPassword:   "admin-password",
		UserSearchBase: "ou=users,dc=example,dc=com",
		UserSearchAttr: "uid",
		EmailAttr:      "mail",
	})

	provider, err := svc.CreateProvider(&model.CreateIdentityProviderRequest{
		Name:   "corp-ldap",
		Type:   "ldap",
		Config: string(ldapConfig),
	})
	if err != nil {
		t.Fatalf("CreateProvider failed: %v", err)
	}
	if provider.Type != "ldap" {
		t.Errorf("type = %q, want ldap", provider.Type)
	}
}

func TestCreateProvider_InvalidType(t *testing.T) {
	svc, _ := setup(t)

	_, err := svc.CreateProvider(&model.CreateIdentityProviderRequest{
		Name: "bad", Type: "saml", Config: "{}",
	})
	if err == nil {
		t.Fatal("expected error for invalid type")
	}
}

func TestCreateProvider_DuplicateName(t *testing.T) {
	svc, _ := setup(t)

	oidcConfig, _ := json.Marshal(model.OIDCConfig{
		IssuerURL: "https://a.com", ClientID: "c", ClientSecret: "s",
	})
	_, _ = svc.CreateProvider(&model.CreateIdentityProviderRequest{
		Name: "google", Type: "oidc", Config: string(oidcConfig),
	})
	_, err := svc.CreateProvider(&model.CreateIdentityProviderRequest{
		Name: "google", Type: "oidc", Config: string(oidcConfig),
	})
	if err == nil {
		t.Fatal("expected error for duplicate name")
	}
}

func TestCreateProvider_MissingOIDCFields(t *testing.T) {
	svc, _ := setup(t)

	_, err := svc.CreateProvider(&model.CreateIdentityProviderRequest{
		Name: "bad-oidc", Type: "oidc", Config: `{"issuer_url":""}`,
	})
	if err == nil {
		t.Fatal("expected error for missing OIDC fields")
	}
}

func TestListProviders(t *testing.T) {
	svc, _ := setup(t)

	oidcConfig, _ := json.Marshal(model.OIDCConfig{
		IssuerURL: "https://a.com", ClientID: "c", ClientSecret: "s",
	})
	_, _ = svc.CreateProvider(&model.CreateIdentityProviderRequest{
		Name: "provider-a", Type: "oidc", Config: string(oidcConfig),
	})
	_, _ = svc.CreateProvider(&model.CreateIdentityProviderRequest{
		Name: "provider-b", Type: "oidc", Config: string(oidcConfig),
	})

	providers, err := svc.ListProviders()
	if err != nil {
		t.Fatalf("ListProviders failed: %v", err)
	}
	if len(providers) != 2 {
		t.Errorf("got %d providers, want 2", len(providers))
	}
	// Configs should be stripped in list responses.
	for _, p := range providers {
		if p.Config != "" {
			t.Errorf("config should be empty in list response, got %q", p.Config)
		}
	}
}

func TestDeleteProvider(t *testing.T) {
	svc, _ := setup(t)

	oidcConfig, _ := json.Marshal(model.OIDCConfig{
		IssuerURL: "https://a.com", ClientID: "c", ClientSecret: "s",
	})
	p, _ := svc.CreateProvider(&model.CreateIdentityProviderRequest{
		Name: "to-delete", Type: "oidc", Config: string(oidcConfig),
	})

	if err := svc.DeleteProvider(p.ID); err != nil {
		t.Fatalf("DeleteProvider failed: %v", err)
	}

	providers, _ := svc.ListProviders()
	if len(providers) != 0 {
		t.Errorf("got %d providers after delete, want 0", len(providers))
	}
}

func TestGetProviderConfig_Decrypts(t *testing.T) {
	svc, _ := setup(t)

	originalConfig := model.OIDCConfig{
		IssuerURL: "https://accounts.google.com", ClientID: "myid", ClientSecret: "mysecret",
	}
	configJSON, _ := json.Marshal(originalConfig)

	p, _ := svc.CreateProvider(&model.CreateIdentityProviderRequest{
		Name: "google", Type: "oidc", Config: string(configJSON),
	})

	decryptedJSON, _, err := svc.GetProviderConfig(p.ID)
	if err != nil {
		t.Fatalf("GetProviderConfig failed: %v", err)
	}

	var decrypted model.OIDCConfig
	json.Unmarshal([]byte(decryptedJSON), &decrypted)

	if decrypted.ClientSecret != "mysecret" {
		t.Errorf("client_secret = %q, want mysecret", decrypted.ClientSecret)
	}
}

func TestResolveExternalIdentity_AutoProvision(t *testing.T) {
	svc, db := setup(t)

	oidcConfig, _ := json.Marshal(model.OIDCConfig{
		IssuerURL: "https://a.com", ClientID: "c", ClientSecret: "s", AutoProvision: true,
	})
	p, _ := svc.CreateProvider(&model.CreateIdentityProviderRequest{
		Name: "google", Type: "oidc", Config: string(oidcConfig),
	})

	ext := &model.ExternalIdentity{
		ProviderName: "google",
		ExternalID:   "google-user-123",
		Email:        "alice@gmail.com",
		DisplayName:  "Alice",
	}

	userID, err := svc.ResolveExternalIdentity(p.ID, ext, true)
	if err != nil {
		t.Fatalf("ResolveExternalIdentity failed: %v", err)
	}
	if userID == "" {
		t.Fatal("userID should not be empty")
	}

	// Verify user was created.
	u, _ := db.GetUserByID(userID)
	if u == nil {
		t.Fatal("user should exist")
	}
	if u.Email != "alice@gmail.com" {
		t.Errorf("email = %q, want alice@gmail.com", u.Email)
	}

	// Second call should return the same user (linked).
	userID2, _ := svc.ResolveExternalIdentity(p.ID, ext, true)
	if userID2 != userID {
		t.Errorf("second resolve should return same user: got %q, want %q", userID2, userID)
	}
}

func TestResolveExternalIdentity_NoAutoLinkByEmail(t *testing.T) {
	svc, db := setup(t)

	// Pre-create a user with the same email.
	userSvc := user.New(db, db)
	_, _ = userSvc.Register(&model.RegisterRequest{
		Email: "bob@company.com", Password: "strongpassword123", Name: "Bob",
	})

	oidcConfig, _ := json.Marshal(model.OIDCConfig{
		IssuerURL: "https://a.com", ClientID: "c", ClientSecret: "s",
	})
	p, _ := svc.CreateProvider(&model.CreateIdentityProviderRequest{
		Name: "corp-sso", Type: "oidc", Config: string(oidcConfig),
	})

	ext := &model.ExternalIdentity{
		ExternalID: "sso-bob-456",
		Email:      "bob@company.com",
	}

	// Should NOT auto-link by email (security: prevents account takeover via compromised IdP).
	_, err := svc.ResolveExternalIdentity(p.ID, ext, false)
	if err == nil {
		t.Fatal("should NOT auto-link by email without auto-provisioning")
	}
}

func TestResolveExternalIdentity_NoAutoProvision(t *testing.T) {
	svc, _ := setup(t)

	oidcConfig, _ := json.Marshal(model.OIDCConfig{
		IssuerURL: "https://a.com", ClientID: "c", ClientSecret: "s",
	})
	p, _ := svc.CreateProvider(&model.CreateIdentityProviderRequest{
		Name: "strict-sso", Type: "oidc", Config: string(oidcConfig),
	})

	ext := &model.ExternalIdentity{
		ExternalID: "unknown-user",
		Email:      "nobody@nowhere.com",
	}

	_, err := svc.ResolveExternalIdentity(p.ID, ext, false)
	if err == nil {
		t.Fatal("expected error when auto-provisioning is disabled and no user exists")
	}
}

func TestResolveExternalIdentity_GroupMapping(t *testing.T) {
	svc, db := setup(t)

	// Create a Burrow group.
	groupSvc := group.New(db, db)
	g, _ := groupSvc.Create(&model.CreateGroupRequest{Name: "backend-team"})

	// Create provider with group mapping.
	oidcConfig, _ := json.Marshal(model.OIDCConfig{
		IssuerURL:     "https://a.com",
		ClientID:      "c",
		ClientSecret:  "s",
		AutoProvision: true,
		GroupMapping:  map[string]string{"engineering": g.ID},
	})
	p, _ := svc.CreateProvider(&model.CreateIdentityProviderRequest{
		Name: "mapped-sso", Type: "oidc", Config: string(oidcConfig),
	})

	ext := &model.ExternalIdentity{
		ExternalID:  "eng-user-1",
		Email:       "engineer@company.com",
		DisplayName: "Engineer",
		Groups:      []string{"engineering", "unknown-group"},
	}

	userID, err := svc.ResolveExternalIdentity(p.ID, ext, true)
	if err != nil {
		t.Fatalf("ResolveExternalIdentity failed: %v", err)
	}

	// Verify user was added to the mapped group.
	members, _ := db.GetGroupMembers(g.ID)
	found := false
	for _, m := range members {
		if m.UserID == userID {
			found = true
		}
	}
	if !found {
		t.Error("user should be a member of the mapped group")
	}
}
