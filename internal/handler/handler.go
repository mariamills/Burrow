// Package handler implements the Burrow HTTP route handlers
//
// Route layout:
//
//	GET  /health
//	GET  /v1/namespaces                        (admin)
//	GET  /v1/secrets/{namespace}               (read)
//	GET  /v1/secrets/{namespace}/{key}         (read)
//	POST /v1/secrets/{namespace}/{key}         (write)
//	DELETE /v1/secrets/{namespace}/{key}       (delete)
//	DELETE /v1/secrets/{namespace}             (delete - entire namespace)
//	GET  /v1/secrets/{namespace}/search?q=     (read)
//	POST /v1/tokens                            (admin)
//	GET  /v1/tokens                            (admin)
//	DELETE /v1/tokens/{id}                     (admin)
//	GET  /v1/audit                             (admin)
//	GET  /v1/audit/{namespace}                 (read)
package handler

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/mariamills/burrow/internal/cluster"
	"github.com/mariamills/burrow/internal/crypto"
	"github.com/mariamills/burrow/internal/domain"
	"github.com/mariamills/burrow/internal/expiry"
	"github.com/mariamills/burrow/internal/group"
	"github.com/mariamills/burrow/internal/identity"
	"github.com/mariamills/burrow/internal/middleware"
	"github.com/mariamills/burrow/internal/model"
	"github.com/mariamills/burrow/internal/role"
	"github.com/mariamills/burrow/internal/rotation"
	"github.com/mariamills/burrow/internal/seal"
	"github.com/mariamills/burrow/internal/session"
	"github.com/mariamills/burrow/internal/user"
	"github.com/mariamills/burrow/pkg/logger"
)

// Store combines all store interfaces needed by handlers
type Store interface {
	domain.SecretStore
	domain.AuditStore
}

// Handler holds dependencies for all route handlers
type Handler struct {
	store      Store
	auth       domain.Authenticator
	enc        domain.Encryptor
	users      *user.Service
	sessions   *session.Service
	groups     *group.Service
	roles      *role.Service
	expiry     *expiry.Worker
	rotation   *rotation.Service
	sealMgr    *seal.Manager
	identity   *identity.Service
	clusterMgr *cluster.Manager
	version    string
}

// New creates a Handler with all required dependencies
func New(s Store, a domain.Authenticator, enc domain.Encryptor, version string) *Handler {
	return &Handler{store: s, auth: a, enc: enc, version: version}
}

// SetUserServices attaches user and session services
func (h *Handler) SetUserServices(u *user.Service, sess *session.Service) {
	h.users = u
	h.sessions = sess
}

// SetGroupService attaches the group service
func (h *Handler) SetGroupService(g *group.Service) {
	h.groups = g
}

// SetRoleService attaches the role service
func (h *Handler) SetRoleService(r *role.Service) {
	h.roles = r
}

// SetExpiryWorker attaches the expiry worker
func (h *Handler) SetExpiryWorker(w *expiry.Worker) {
	h.expiry = w
}

// SetRotationService attaches the rotation service
func (h *Handler) SetRotationService(r *rotation.Service) {
	h.rotation = r
}

// SetSealManager attaches the seal manager
func (h *Handler) SetSealManager(m *seal.Manager) {
	h.sealMgr = m
}

// SetIdentityService attaches the identity service
func (h *Handler) SetIdentityService(s *identity.Service) {
	h.identity = s
}

// SetClusterManager attaches the cluster manager
func (h *Handler) SetClusterManager(m *cluster.Manager) {
	h.clusterMgr = m
}

// ClusterStatus handles GET /v1/sys/cluster (admin only)
func (h *Handler) ClusterStatus(w http.ResponseWriter, r *http.Request) {
	if h.clusterMgr == nil {
		writeJSON(w, http.StatusOK, model.APIResponse{Data: map[string]interface{}{
			"enabled": false,
		}})
		return
	}
	writeJSON(w, http.StatusOK, model.APIResponse{Data: h.clusterMgr.Status()})
}

// HEALTH
// GET /health - no auth required
func (h *Handler) Health(w http.ResponseWriter, r *http.Request) {
	dbStatus := "ok"
	if err := h.store.Ping(); err != nil {
		logger.Error("health check: database degraded", "error", err)
		dbStatus = "degraded"
	}
	writeJSON(w, http.StatusOK, model.HealthResponse{
		Status:    "ok",
		Version:   h.version,
		Timestamp: time.Now(),
		DBStatus:  dbStatus,
	})
}

// SEAL / UNSEAL
// SealStatus handles GET /v1/sys/seal-status (no auth required)
func (h *Handler) SealStatus(w http.ResponseWriter, r *http.Request) {
	if h.sealMgr == nil {
		writeJSON(w, http.StatusOK, model.APIResponse{Data: map[string]interface{}{
			"sealed": false, "initialized": true, "mode": "auto",
		}})
		return
	}
	status, err := h.sealMgr.Status()
	if err != nil {
		logger.Error("seal status", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to get seal status")
		return
	}
	writeJSON(w, http.StatusOK, model.APIResponse{Data: status})
}

type initRequest struct {
	Shares    int `json:"shares"`
	Threshold int `json:"threshold"`
}

// SealInit handles POST /v1/sys/init (no auth - only works when uninitialized)
func (h *Handler) SealInit(w http.ResponseWriter, r *http.Request) {
	if h.sealMgr == nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Vault is in auto-unseal mode")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req initRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid JSON body")
		return
	}

	resp, err := h.sealMgr.Init(req.Shares, req.Threshold)
	if err != nil {
		if strings.Contains(err.Error(), "already initialized") {
			writeError(w, http.StatusConflict, "CONFLICT", "Vault is already initialized")
			return
		}
		if strings.Contains(err.Error(), "shares must be") || strings.Contains(err.Error(), "threshold must be") {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", err.Error())
		} else {
			logger.Error("vault init failed", "error", err)
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Vault initialization failed")
		}
		return
	}

	writeJSON(w, http.StatusOK, model.APIResponse{
		Message: "Vault initialized. Store these keys and the root token securely - they will not be shown again.",
		Data:    resp,
	})
}

type unsealRequest struct {
	Key string `json:"key"`
}

// Unseal handles POST /v1/sys/unseal (no auth - accepts key shares).
func (h *Handler) Unseal(w http.ResponseWriter, r *http.Request) {
	if h.sealMgr == nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Vault is in auto-unseal mode")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req unsealRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid JSON body")
		return
	}

	if req.Key == "" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "key is required")
		return
	}

	unsealed, err := h.sealMgr.SubmitUnsealShare(req.Key)
	if err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", err.Error())
		return
	}

	status, _ := h.sealMgr.Status()
	msg := "Unseal share accepted"
	if unsealed {
		msg = "Vault is now unsealed"
	}

	writeJSON(w, http.StatusOK, model.APIResponse{Message: msg, Data: status})
}

// Seal handles POST /v1/sys/seal (requires auth + admin)
func (h *Handler) Seal(w http.ResponseWriter, r *http.Request) {
	if h.sealMgr == nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Vault is in auto-unseal mode")
		return
	}

	h.sealMgr.Seal()
	writeJSON(w, http.StatusOK, model.APIResponse{Message: "Vault sealed"})
}

// IDENTITY PROVIDERS
// CreateIdentityProvider handles POST /v1/sys/identity-providers (admin only)
func (h *Handler) CreateIdentityProvider(w http.ResponseWriter, r *http.Request) {
	if h.identity == nil {
		writeError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "Identity federation is not enabled")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req model.CreateIdentityProviderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid JSON body")
		return
	}

	provider, err := h.identity.CreateProvider(&req)
	if err != nil {
		if strings.Contains(err.Error(), "already exists") {
			writeError(w, http.StatusConflict, "CONFLICT", "Provider name already exists")
			return
		}
		if strings.Contains(err.Error(), "is required") || strings.Contains(err.Error(), "must be") || strings.Contains(err.Error(), "invalid") || strings.Contains(err.Error(), "requires") {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", err.Error())
			return
		}
		logger.Error("create identity provider", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create identity provider")
		return
	}

	writeJSON(w, http.StatusCreated, model.APIResponse{
		Message: "Identity provider created",
		Data:    provider,
	})
}

// ListIdentityProviders handles GET /v1/sys/identity-providers (admin only).
func (h *Handler) ListIdentityProviders(w http.ResponseWriter, r *http.Request) {
	if h.identity == nil {
		writeError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "Identity federation is not enabled")
		return
	}

	providers, err := h.identity.ListProviders()
	if err != nil {
		logger.Error("list identity providers", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list providers")
		return
	}
	if providers == nil {
		providers = []*model.IdentityProvider{}
	}

	writeJSON(w, http.StatusOK, model.APIResponse{Data: providers})
}

// DeleteIdentityProvider handles DELETE /v1/sys/identity-providers/{id} (admin only)
func (h *Handler) DeleteIdentityProvider(w http.ResponseWriter, r *http.Request) {
	if h.identity == nil {
		writeError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "Identity federation is not enabled")
		return
	}

	id := pathSegment(r.URL.Path, 4)
	if id == "" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Provider ID is required")
		return
	}

	if err := h.identity.DeleteProvider(id); err != nil {
		logger.Error("delete identity provider", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to delete provider")
		return
	}

	writeJSON(w, http.StatusOK, model.APIResponse{Message: "Identity provider deleted"})
}

// LDAPLogin handles POST /v1/auth/ldap/login (public, seal-gated)
func (h *Handler) LDAPLogin(w http.ResponseWriter, r *http.Request) {
	if h.identity == nil || h.sessions == nil {
		writeError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "LDAP login is not enabled")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req struct {
		Provider string `json:"provider"`
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid JSON body")
		return
	}

	if req.Provider == "" || req.Username == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "provider, username, and password are required")
		return
	}

	// For now, LDAP login is a placeholder - the full LDAP bind implementation
	// requires the go-ldap package. The architecture is ready; the actual
	// LDAP client can be plugged in via the Provider interface.
	writeError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED",
		"LDAP authentication requires the go-ldap package - configure via identity provider API")
}

// OIDCLogin handles GET /v1/auth/oidc/login (public, seal-gated)
// Redirects the user to the OIDC provider for authentication.
func (h *Handler) OIDCLogin(w http.ResponseWriter, r *http.Request) {
	if h.identity == nil {
		writeError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "OIDC login is not enabled")
		return
	}

	providerName := r.URL.Query().Get("provider")
	if providerName == "" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "provider query parameter is required")
		return
	}

	// For now, OIDC login is a placeholder - the full OIDC flow requires
	// the go-oidc and oauth2 packages. The architecture is ready; the actual
	// OIDC client can be plugged in via the Provider interface.
	writeError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED",
		"OIDC authentication requires the go-oidc package - configure via identity provider API")
}

// OIDCCallback handles GET /v1/auth/oidc/callback (public, seal-gated)
// Processes the callback from the OIDC provider after user authentication.
func (h *Handler) OIDCCallback(w http.ResponseWriter, r *http.Request) {
	if h.identity == nil {
		writeError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "OIDC login is not enabled")
		return
	}

	// Placeholder - full implementation requires go-oidc package.
	writeError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED",
		"OIDC callback requires the go-oidc package")
}

// SECRETS
// ListSecrets handles GET /v1/secrets/{namespace}
// Returns metadata only - no secret values in list responses.
func (h *Handler) ListSecrets(w http.ResponseWriter, r *http.Request) {
	namespace := pathSegment(r.URL.Path, 3)
	if namespace == "" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "namespace is required")
		return
	}
	if !isValidIdentifier(namespace) {
		writeError(w, http.StatusBadRequest, "INVALID_IDENTIFIER",
			"namespace may only contain letters, numbers, hyphens, underscores, and dots")
		return
	}

	// Search mode: GET /v1/secrets/{namespace}?q=pattern
	if q := r.URL.Query().Get("q"); q != "" {
		results, err := h.store.SearchSecrets(namespace, q)
		if err != nil {
			logger.Error("search secrets", "error", err)
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Search failed")
			return
		}
		writeJSON(w, http.StatusOK, model.APIResponse{Data: results})
		return
	}

	secrets, err := h.store.ListSecrets(namespace)
	if err != nil {
		logger.Error("list secrets", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list secrets")
		return
	}

	if secrets == nil {
		secrets = []*model.SecretMeta{} // never return null
	}

	writeJSON(w, http.StatusOK, model.APIResponse{Data: secrets})
}

// GetSecret handles GET /v1/secrets/{namespace}/{key}
// This is the ONLY endpoint that returns the decrypted secret value
func (h *Handler) GetSecret(w http.ResponseWriter, r *http.Request) {
	namespace := pathSegment(r.URL.Path, 3)
	key := pathSegment(r.URL.Path, 4)

	if namespace == "" || key == "" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "namespace and key are required")
		return
	}
	if !isValidIdentifier(namespace) || !isValidIdentifier(key) {
		writeError(w, http.StatusBadRequest, "INVALID_IDENTIFIER",
			"namespace and key may only contain letters, numbers, hyphens, underscores, and dots")
		return
	}

	secret, err := h.store.GetSecret(namespace, key)
	if err != nil {
		logger.Error("get secret", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to retrieve secret")
		return
	}

	if secret == nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "Secret not found")
		return
	}

	// Check if the secret has expired.
	if secret.IsExpiredSecret() {
		writeError(w, http.StatusGone, "EXPIRED", "Secret has expired")
		return
	}

	// Decrypt the stored ciphertext.
	plaintext, err := h.enc.Decrypt(secret.Value)
	if err != nil {
		logger.Error("decrypt secret", "namespace", namespace, "key", key, "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to retrieve secret")
		return
	}

	writeJSON(w, http.StatusOK, model.APIResponse{
		Data: model.SecretResponse{
			ID:          secret.ID,
			Namespace:   secret.Namespace,
			Key:         secret.Key,
			Value:       plaintext,
			Description: secret.Description,
			ExpiresAt:   secret.ExpiresAt,
			CreatedAt:   secret.CreatedAt,
			UpdatedAt:   secret.UpdatedAt,
		},
	})
}

// UpsertSecret handles POST /v1/secrets/{namespace}/{key}
// Creates or updates a secret.  The value is encrypted before storage
func (h *Handler) UpsertSecret(w http.ResponseWriter, r *http.Request) {
	namespace := pathSegment(r.URL.Path, 3)
	key := pathSegment(r.URL.Path, 4)

	if namespace == "" || key == "" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "namespace and key are required")
		return
	}

	// Validate namespace and key characters (prevent path traversal)
	if !isValidIdentifier(namespace) || !isValidIdentifier(key) {
		writeError(w, http.StatusBadRequest, "INVALID_IDENTIFIER",
			"namespace and key may only contain letters, numbers, hyphens, and underscores")
		return
	}

	// Limit request body to 1MB to prevent DoS via oversized payloads.
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	var req model.CreateSecretRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		if err.Error() == "http: request body too large" {
			writeError(w, http.StatusRequestEntityTooLarge, "PAYLOAD_TOO_LARGE", "Request body must be under 1MB")
			return
		}
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid JSON body")
		return
	}

	if req.Value == "" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "value is required")
		return
	}

	// Encrypt the value before storing.
	ciphertext, err := h.enc.Encrypt(req.Value)
	if err != nil {
		logger.Error("encrypt secret", "key", key, "error", err)
		writeError(w, http.StatusInternalServerError, "CRYPTO_ERROR", "Encryption failed")
		return
	}

	token := middleware.TokenFromContext(r.Context())
	tokenID := ""
	if token != nil {
		tokenID = token.ID
	}

	// Check if updating or creating.
	existing, _ := h.store.GetSecret(namespace, key)
	isUpdate := existing != nil

	id, _ := crypto.GenerateID()
	now := time.Now()
	createdAt := now
	if isUpdate {
		createdAt = existing.CreatedAt
	}

	secret := &model.Secret{
		ID:          id,
		Namespace:   namespace,
		Key:         key,
		Value:       ciphertext,
		Description: req.Description,
		ExpiresAt:   req.ExpiresAt,
		CreatedAt:   createdAt,
		UpdatedAt:   now,
		CreatedBy:   tokenID,
	}

	if err := h.store.UpsertSecret(secret); err != nil {
		logger.Error("upsert secret", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to save secret")
		return
	}

	status := http.StatusCreated
	msg := "Secret created"
	if isUpdate {
		status = http.StatusOK
		msg = "Secret updated"
	}

	writeJSON(w, status, model.APIResponse{
		Message: msg,
		Data: model.SecretMeta{
			ID:          secret.ID,
			Namespace:   secret.Namespace,
			Key:         secret.Key,
			Description: secret.Description,
			CreatedAt:   secret.CreatedAt,
			UpdatedAt:   secret.UpdatedAt,
		},
	})
}

// DeleteSecret handles DELETE /v1/secrets/{namespace}/{key}
func (h *Handler) DeleteSecret(w http.ResponseWriter, r *http.Request) {
	namespace := pathSegment(r.URL.Path, 3)
	key := pathSegment(r.URL.Path, 4)

	if namespace == "" || key == "" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "namespace and key are required")
		return
	}
	if !isValidIdentifier(namespace) || !isValidIdentifier(key) {
		writeError(w, http.StatusBadRequest, "INVALID_IDENTIFIER",
			"namespace and key may only contain letters, numbers, hyphens, underscores, and dots")
		return
	}

	deleted, err := h.store.DeleteSecret(namespace, key)
	if err != nil {
		logger.Error("delete secret", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Delete failed")
		return
	}

	if !deleted {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "Secret not found")
		return
	}

	writeJSON(w, http.StatusOK, model.APIResponse{Message: "Secret deleted"})
}

// DeleteNamespace handles DELETE /v1/secrets/{namespace}
func (h *Handler) DeleteNamespace(w http.ResponseWriter, r *http.Request) {
	namespace := pathSegment(r.URL.Path, 3)
	if namespace == "" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "namespace is required")
		return
	}
	if !isValidIdentifier(namespace) {
		writeError(w, http.StatusBadRequest, "INVALID_IDENTIFIER",
			"namespace may only contain letters, numbers, hyphens, underscores, and dots")
		return
	}

	count, err := h.store.DeleteNamespace(namespace)
	if err != nil {
		logger.Error("delete namespace", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Delete failed")
		return
	}

	writeJSON(w, http.StatusOK, model.APIResponse{
		Message: "Namespace deleted",
		Data:    map[string]int64{"deleted_count": count},
	})
}

// ListNamespaces handles GET /v1/namespaces
func (h *Handler) ListNamespaces(w http.ResponseWriter, r *http.Request) {
	namespaces, err := h.store.ListNamespaces()
	if err != nil {
		logger.Error("list namespaces", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list namespaces")
		return
	}
	if namespaces == nil {
		namespaces = []string{}
	}
	writeJSON(w, http.StatusOK, model.APIResponse{Data: namespaces})
}

// TOKENS
// CreateToken handles POST /v1/tokens (admin only)
func (h *Handler) CreateToken(w http.ResponseWriter, r *http.Request) {
	// Limit request body to 1MB to prevent DoS via oversized payloads.
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	var req model.CreateTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		if err.Error() == "http: request body too large" {
			writeError(w, http.StatusRequestEntityTooLarge, "PAYLOAD_TOO_LARGE", "Request body must be under 1MB")
			return
		}
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid JSON body")
		return
	}

	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "name is required")
		return
	}
	if len(req.Namespaces) == 0 {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "at least one namespace is required")
		return
	}
	if len(req.Permissions) == 0 {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "at least one permission is required")
		return
	}

	// Validate permission values against known constants.
	validPerms := map[string]bool{
		model.PermRead: true, model.PermWrite: true,
		model.PermDelete: true, model.PermAdmin: true,
	}
	for _, p := range req.Permissions {
		if !validPerms[p] {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST",
				"invalid permission '"+p+"'; valid values: read, write, delete, admin")
			return
		}
	}

	// Validate namespace identifiers.
	for _, ns := range req.Namespaces {
		if ns != "*" && !isValidIdentifier(ns) {
			writeError(w, http.StatusBadRequest, "INVALID_IDENTIFIER",
				"namespace '"+ns+"' contains invalid characters")
			return
		}
	}

	resp, err := h.auth.CreateToken(&req)
	if err != nil {
		logger.Error("create token", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create token")
		return
	}

	// 201 Created - the raw token is included ONCE in this response.
	writeJSON(w, http.StatusCreated, model.APIResponse{
		Message: "Token created. Store the token value now - it will not be shown again.",
		Data:    resp,
	})
}

// ListTokens handles GET /v1/tokens (admin only).
func (h *Handler) ListTokens(w http.ResponseWriter, r *http.Request) {
	tokens, err := h.auth.ListTokens()
	if err != nil {
		logger.Error("list tokens", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list tokens")
		return
	}
	if tokens == nil {
		tokens = []*model.Token{}
	}
	writeJSON(w, http.StatusOK, model.APIResponse{Data: tokens})
}

// RevokeToken handles DELETE /v1/tokens/{id} (admin only)
func (h *Handler) RevokeToken(w http.ResponseWriter, r *http.Request) {
	id := pathSegment(r.URL.Path, 3)
	if id == "" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "token ID is required")
		return
	}

	if id == "root" {
		writeError(w, http.StatusForbidden, "FORBIDDEN", "The root token cannot be revoked via API")
		return
	}

	revoked, err := h.auth.RevokeToken(id)
	if err != nil {
		logger.Error("revoke token", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Revoke failed")
		return
	}

	if !revoked {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "Token not found")
		return
	}

	writeJSON(w, http.StatusOK, model.APIResponse{Message: "Token revoked"})
}

// AUDIT
// GetAuditLog handles GET /v1/audit and GET /v1/audit/{namespace}
func (h *Handler) GetAuditLog(w http.ResponseWriter, r *http.Request) {
	namespace := pathSegment(r.URL.Path, 3)

	limitStr := r.URL.Query().Get("limit")
	limit := 100
	if limitStr != "" {
		if n, err := strconv.Atoi(limitStr); err == nil && n > 0 && n <= 1000 {
			limit = n
		}
	}

	events, err := h.store.GetAuditLog(namespace, limit)
	if err != nil {
		logger.Error("get audit log", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to retrieve audit log")
		return
	}

	if events == nil {
		events = []*model.AuditEvent{}
	}

	writeJSON(w, http.StatusOK, model.APIResponse{Data: events})
}

// EXPIRY
// GetExpiringSecrets handles GET /v1/expiring?within=24h (admin only).
func (h *Handler) GetExpiringSecrets(w http.ResponseWriter, r *http.Request) {
	if h.expiry == nil {
		writeError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "Expiry monitoring is not enabled")
		return
	}

	withinStr := r.URL.Query().Get("within")
	if withinStr == "" {
		withinStr = "24h"
	}

	within, err := expiry.ParseDuration(withinStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid 'within' duration (e.g. 24h, 7d)")
		return
	}

	secrets, err := h.expiry.GetExpiringSecrets(within)
	if err != nil {
		logger.Error("get expiring secrets", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to check expiring secrets")
		return
	}

	if secrets == nil {
		secrets = []*model.SecretMeta{}
	}

	writeJSON(w, http.StatusOK, model.APIResponse{Data: secrets})
}

// AUTH / USERS
// Register handles POST /v1/auth/register (admin only)
func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	if h.users == nil {
		writeError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "User management is not enabled")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req model.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid JSON body")
		return
	}

	u, err := h.users.Register(&req)
	if err != nil {
		if strings.Contains(err.Error(), "email already registered") {
			writeError(w, http.StatusConflict, "CONFLICT", "Email already registered")
			return
		}
		if strings.Contains(err.Error(), "is required") || strings.Contains(err.Error(), "at least") {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", err.Error())
			return
		}
		logger.Error("register user", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create user")
		return
	}

	writeJSON(w, http.StatusCreated, model.APIResponse{
		Message: "User created",
		Data:    u,
	})
}

// Login handles POST /v1/auth/login (no auth required)
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	if h.users == nil || h.sessions == nil {
		writeError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "User management is not enabled")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req model.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid JSON body")
		return
	}

	u, err := h.users.Authenticate(req.Email, req.Password)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Invalid email or password")
		return
	}

	resp, err := h.sessions.Create(u.ID, middleware.RealIP(r), r.UserAgent())
	if err != nil {
		logger.Error("create session", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create session")
		return
	}

	writeJSON(w, http.StatusOK, model.APIResponse{
		Message: "Login successful",
		Data:    resp,
	})
}

// Logout handles POST /v1/auth/logout (session auth required)
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	sess := middleware.SessionFromContext(r.Context())
	if sess == nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Not authenticated")
		return
	}

	if err := h.sessions.Destroy(sess.ID); err != nil {
		logger.Error("logout", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to destroy session")
		return
	}

	writeJSON(w, http.StatusOK, model.APIResponse{Message: "Logged out"})
}

// Me handles GET /v1/auth/me (session auth required).
func (h *Handler) Me(w http.ResponseWriter, r *http.Request) {
	sess := middleware.SessionFromContext(r.Context())
	if sess == nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Not authenticated")
		return
	}

	u, err := h.users.GetByID(sess.UserID)
	if err != nil || u == nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "User not found")
		return
	}

	writeJSON(w, http.StatusOK, model.APIResponse{Data: u})
}

// ListUsers handles GET /v1/users (admin only)
func (h *Handler) ListUsers(w http.ResponseWriter, r *http.Request) {
	if h.users == nil {
		writeError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "User management is not enabled")
		return
	}

	users, err := h.users.List()
	if err != nil {
		logger.Error("list users", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list users")
		return
	}
	if users == nil {
		users = []*model.User{}
	}

	writeJSON(w, http.StatusOK, model.APIResponse{Data: users})
}

// DeactivateUser handles DELETE /v1/users/{id} (admin only).
func (h *Handler) DeactivateUser(w http.ResponseWriter, r *http.Request) {
	if h.users == nil {
		writeError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "User management is not enabled")
		return
	}

	id := pathSegment(r.URL.Path, 3)
	if id == "" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "User ID is required")
		return
	}

	if err := h.users.Deactivate(id); err != nil {
		logger.Error("deactivate user", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to deactivate user")
		return
	}

	writeJSON(w, http.StatusOK, model.APIResponse{Message: "User deactivated"})
}

// ResetUserPassword allows an admin to set a new password for a user
func (h *Handler) ResetUserPassword(w http.ResponseWriter, r *http.Request) {
	if h.users == nil {
		writeError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "User management is not enabled")
		return
	}

	id := pathSegment(r.URL.Path, 3)
	if id == "" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "User ID is required")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req model.ResetPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid JSON body")
		return
	}

	if err := h.users.ResetPassword(id, req.Password); err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, "NOT_FOUND", "User not found")
			return
		}
		if strings.Contains(err.Error(), "deactivated") {
			writeError(w, http.StatusConflict, "CONFLICT", "User account is deactivated")
			return
		}
		if strings.Contains(err.Error(), "at least") || strings.Contains(err.Error(), "at most") {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", err.Error())
			return
		}
		logger.Error("reset user password", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to reset password")
		return
	}

	writeJSON(w, http.StatusOK, model.APIResponse{Message: "Password reset successfully"})
}

// ── GROUPS ────────────────────────────────────────────────────────────────────

func (h *Handler) groupsCheck(w http.ResponseWriter) bool {
	if h.groups == nil {
		writeError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "Group management is not enabled")
		return false
	}
	return true
}

// CreateGroup handles POST /v1/groups (admin only)
func (h *Handler) CreateGroup(w http.ResponseWriter, r *http.Request) {
	if !h.groupsCheck(w) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req model.CreateGroupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid JSON body")
		return
	}

	g, err := h.groups.Create(&req)
	if err != nil {
		if strings.Contains(err.Error(), "name already taken") {
			writeError(w, http.StatusConflict, "CONFLICT", "Group name already taken")
			return
		}
		if strings.Contains(err.Error(), "is required") {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", err.Error())
			return
		}
		logger.Error("create group", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create group")
		return
	}

	writeJSON(w, http.StatusCreated, model.APIResponse{Data: g})
}

// ListGroups handles GET /v1/groups (admin only).
func (h *Handler) ListGroups(w http.ResponseWriter, r *http.Request) {
	if !h.groupsCheck(w) {
		return
	}

	groups, err := h.groups.List()
	if err != nil {
		logger.Error("list groups", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list groups")
		return
	}
	if groups == nil {
		groups = []*model.Group{}
	}

	writeJSON(w, http.StatusOK, model.APIResponse{Data: groups})
}

// GetGroup handles GET /v1/groups/{id} (admin only).
func (h *Handler) GetGroup(w http.ResponseWriter, r *http.Request) {
	if !h.groupsCheck(w) {
		return
	}

	id := pathSegment(r.URL.Path, 3)
	if id == "" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Group ID is required")
		return
	}

	detail, err := h.groups.Get(id)
	if err != nil {
		logger.Error("get group", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to get group")
		return
	}
	if detail == nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "Group not found")
		return
	}

	writeJSON(w, http.StatusOK, model.APIResponse{Data: detail})
}

// UpdateGroup handles PUT /v1/groups/{id} (admin only).
func (h *Handler) UpdateGroup(w http.ResponseWriter, r *http.Request) {
	if !h.groupsCheck(w) {
		return
	}

	id := pathSegment(r.URL.Path, 3)
	if id == "" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Group ID is required")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req model.UpdateGroupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid JSON body")
		return
	}

	g, err := h.groups.Update(id, &req)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, "NOT_FOUND", "Group not found")
			return
		}
		if strings.Contains(err.Error(), "name already taken") {
			writeError(w, http.StatusConflict, "CONFLICT", "Group name already taken")
			return
		}
		logger.Error("update group", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to update group")
		return
	}

	writeJSON(w, http.StatusOK, model.APIResponse{Data: g})
}

// DeleteGroup handles DELETE /v1/groups/{id} (admin only)
func (h *Handler) DeleteGroup(w http.ResponseWriter, r *http.Request) {
	if !h.groupsCheck(w) {
		return
	}

	id := pathSegment(r.URL.Path, 3)
	if id == "" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Group ID is required")
		return
	}

	if err := h.groups.Delete(id); err != nil {
		logger.Error("delete group", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to delete group")
		return
	}

	writeJSON(w, http.StatusOK, model.APIResponse{Message: "Group deleted"})
}

// AddGroupMember handles POST /v1/groups/{id}/members (admin only)
func (h *Handler) AddGroupMember(w http.ResponseWriter, r *http.Request) {
	if !h.groupsCheck(w) {
		return
	}

	groupID := pathSegment(r.URL.Path, 3)
	if groupID == "" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Group ID is required")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req model.AddMemberRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid JSON body")
		return
	}

	if err := h.groups.AddMember(groupID, &req); err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, "NOT_FOUND", err.Error())
			return
		}
		if strings.Contains(err.Error(), "is required") || strings.Contains(err.Error(), "must be") {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", err.Error())
			return
		}
		logger.Error("add group member", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to add member")
		return
	}

	writeJSON(w, http.StatusOK, model.APIResponse{Message: "Member added"})
}

// RemoveGroupMember handles DELETE /v1/groups/{id}/members/{user_id} (admin only)
func (h *Handler) RemoveGroupMember(w http.ResponseWriter, r *http.Request) {
	if !h.groupsCheck(w) {
		return
	}

	groupID := pathSegment(r.URL.Path, 3)
	userID := pathSegment(r.URL.Path, 5)
	if groupID == "" || userID == "" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Group ID and User ID are required")
		return
	}

	if err := h.groups.RemoveMember(groupID, userID); err != nil {
		logger.Error("remove group member", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to remove member")
		return
	}

	writeJSON(w, http.StatusOK, model.APIResponse{Message: "Member removed"})
}

// SetGroupPermissions handles PUT /v1/groups/{id}/permissions (admin only)
func (h *Handler) SetGroupPermissions(w http.ResponseWriter, r *http.Request) {
	if !h.groupsCheck(w) {
		return
	}

	groupID := pathSegment(r.URL.Path, 3)
	if groupID == "" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Group ID is required")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req model.SetGroupPermissionsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid JSON body")
		return
	}

	if err := h.groups.SetPermissions(groupID, &req); err != nil {
		if strings.Contains(err.Error(), "is required") || strings.Contains(err.Error(), "invalid permission") {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", err.Error())
			return
		}
		logger.Error("set group permissions", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to set permissions")
		return
	}

	writeJSON(w, http.StatusOK, model.APIResponse{Message: "Permissions updated"})
}

// ROLES
func (h *Handler) rolesCheck(w http.ResponseWriter) bool {
	if h.roles == nil {
		writeError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "Role management is not enabled")
		return false
	}
	return true
}

// CreateRole handles POST /v1/roles (admin only)
func (h *Handler) CreateRole(w http.ResponseWriter, r *http.Request) {
	if !h.rolesCheck(w) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req model.CreateRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid JSON body")
		return
	}

	role, err := h.roles.Create(&req)
	if err != nil {
		if strings.Contains(err.Error(), "name already taken") {
			writeError(w, http.StatusConflict, "CONFLICT", "Role name already taken")
			return
		}
		if strings.Contains(err.Error(), "is required") || strings.Contains(err.Error(), "invalid permission") {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", err.Error())
			return
		}
		logger.Error("create role", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create role")
		return
	}

	writeJSON(w, http.StatusCreated, model.APIResponse{Data: role})
}

// ListRoles handles GET /v1/roles (admin only)
func (h *Handler) ListRoles(w http.ResponseWriter, r *http.Request) {
	if !h.rolesCheck(w) {
		return
	}
	roles, err := h.roles.List()
	if err != nil {
		logger.Error("list roles", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list roles")
		return
	}
	if roles == nil {
		roles = []*model.Role{}
	}
	writeJSON(w, http.StatusOK, model.APIResponse{Data: roles})
}

// GetRole handles GET /v1/roles/{id} (admin only)
func (h *Handler) GetRole(w http.ResponseWriter, r *http.Request) {
	if !h.rolesCheck(w) {
		return
	}
	id := pathSegment(r.URL.Path, 3)
	if id == "" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Role ID is required")
		return
	}
	userRole, err := h.roles.Get(id)
	if err != nil {
		logger.Error("get userRole", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to get userRole")
		return
	}
	if userRole == nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "Role not found")
		return
	}
	writeJSON(w, http.StatusOK, model.APIResponse{Data: userRole})
}

// UpdateRole handles PUT /v1/roles/{id} (admin only)
func (h *Handler) UpdateRole(w http.ResponseWriter, r *http.Request) {
	if !h.rolesCheck(w) {
		return
	}
	id := pathSegment(r.URL.Path, 3)
	if id == "" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Role ID is required")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req model.UpdateRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid JSON body")
		return
	}
	userRole, err := h.roles.Update(id, &req)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, "NOT_FOUND", "Role not found")
			return
		}
		logger.Error("update userRole", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to update userRole")
		return
	}
	writeJSON(w, http.StatusOK, model.APIResponse{Data: userRole})
}

// DeleteRole handles DELETE /v1/roles/{id} (admin only)
func (h *Handler) DeleteRole(w http.ResponseWriter, r *http.Request) {
	if !h.rolesCheck(w) {
		return
	}
	id := pathSegment(r.URL.Path, 3)
	if id == "" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Role ID is required")
		return
	}
	if err := h.roles.Delete(id); err != nil {
		logger.Error("delete role", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to delete role")
		return
	}
	writeJSON(w, http.StatusOK, model.APIResponse{Message: "Role deleted"})
}

// AssignUserRole handles POST /v1/users/{id}/roles (admin only)
func (h *Handler) AssignUserRole(w http.ResponseWriter, r *http.Request) {
	if !h.rolesCheck(w) {
		return
	}
	userID := pathSegment(r.URL.Path, 3)
	if userID == "" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "User ID is required")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req model.AssignRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid JSON body")
		return
	}
	if err := h.roles.AssignToUser(userID, req.RoleID); err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, "NOT_FOUND", err.Error())
			return
		}
		logger.Error("assign user role", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to assign role")
		return
	}
	writeJSON(w, http.StatusOK, model.APIResponse{Message: "Role assigned"})
}

// RemoveUserRole handles DELETE /v1/users/{id}/roles/{role_id} (admin only)
func (h *Handler) RemoveUserRole(w http.ResponseWriter, r *http.Request) {
	if !h.rolesCheck(w) {
		return
	}
	userID := pathSegment(r.URL.Path, 3)
	roleID := pathSegment(r.URL.Path, 5)
	if userID == "" || roleID == "" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "User ID and Role ID are required")
		return
	}
	if err := h.roles.RemoveFromUser(userID, roleID); err != nil {
		logger.Error("remove user role", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to remove role")
		return
	}
	writeJSON(w, http.StatusOK, model.APIResponse{Message: "Role removed"})
}

// AssignGroupRole handles POST /v1/groups/{id}/roles (admin only)
func (h *Handler) AssignGroupRole(w http.ResponseWriter, r *http.Request) {
	if !h.rolesCheck(w) {
		return
	}
	groupID := pathSegment(r.URL.Path, 3)
	if groupID == "" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Group ID is required")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req model.AssignRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid JSON body")
		return
	}
	if err := h.roles.AssignToGroup(groupID, req.RoleID); err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, "NOT_FOUND", err.Error())
			return
		}
		logger.Error("assign group role", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to assign role")
		return
	}
	writeJSON(w, http.StatusOK, model.APIResponse{Message: "Role assigned to group"})
}

// RemoveGroupRole handles DELETE /v1/groups/{id}/roles/{role_id} (admin only)
func (h *Handler) RemoveGroupRole(w http.ResponseWriter, r *http.Request) {
	if !h.rolesCheck(w) {
		return
	}
	groupID := pathSegment(r.URL.Path, 3)
	roleID := pathSegment(r.URL.Path, 5)
	if groupID == "" || roleID == "" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Group ID and Role ID are required")
		return
	}
	if err := h.roles.RemoveFromGroup(groupID, roleID); err != nil {
		logger.Error("remove group role", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to remove role")
		return
	}
	writeJSON(w, http.StatusOK, model.APIResponse{Message: "Role removed from group"})
}

// ROTATION / VERSIONING
// RotateSecret handles POST /v1/secrets/{namespace}/{key}/rotate (write permission)
func (h *Handler) RotateSecret(w http.ResponseWriter, r *http.Request) {
	if h.rotation == nil {
		writeError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "Rotation is not enabled")
		return
	}
	namespace := pathSegment(r.URL.Path, 3)
	key := pathSegment(r.URL.Path, 4)
	if namespace == "" || key == "" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "namespace and key are required")
		return
	}

	token := middleware.TokenFromContext(r.Context())
	createdBy := ""
	if token != nil {
		createdBy = token.ID
	}

	meta, err := h.rotation.Rotate(namespace, key, createdBy)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, "NOT_FOUND", "Secret not found")
			return
		}
		logger.Error("rotate secret", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Rotation failed")
		return
	}

	writeJSON(w, http.StatusOK, model.APIResponse{Message: "Secret rotated", Data: meta})
}

// SetRotationPolicy handles PUT /v1/secrets/{namespace}/{key}/rotation-policy (write permission)
func (h *Handler) SetRotationPolicy(w http.ResponseWriter, r *http.Request) {
	if h.rotation == nil {
		writeError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "Rotation is not enabled")
		return
	}
	namespace := pathSegment(r.URL.Path, 3)
	key := pathSegment(r.URL.Path, 4)
	if namespace == "" || key == "" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "namespace and key are required")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req model.SetRotationPolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid JSON body")
		return
	}

	policy, err := h.rotation.SetPolicy(namespace, key, &req)
	if err != nil {
		if strings.Contains(err.Error(), "at least") || strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", err.Error())
			return
		}
		logger.Error("set rotation policy", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to set rotation policy")
		return
	}

	writeJSON(w, http.StatusOK, model.APIResponse{Message: "Rotation policy set", Data: policy})
}

// ListSecretVersions handles GET /v1/secrets/{namespace}/{key}/versions (read permission)
func (h *Handler) ListSecretVersions(w http.ResponseWriter, r *http.Request) {
	if h.rotation == nil {
		writeError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "Versioning is not enabled")
		return
	}
	namespace := pathSegment(r.URL.Path, 3)
	key := pathSegment(r.URL.Path, 4)
	if namespace == "" || key == "" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "namespace and key are required")
		return
	}

	versions, err := h.rotation.ListVersions(namespace, key)
	if err != nil {
		logger.Error("list secret versions", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list versions")
		return
	}
	if versions == nil {
		versions = []*model.SecretVersionMeta{}
	}

	writeJSON(w, http.StatusOK, model.APIResponse{Data: versions})
}

// GetSecretVersion handles GET /v1/secrets/{namespace}/{key}/versions/{version} (read permission)
func (h *Handler) GetSecretVersion(w http.ResponseWriter, r *http.Request) {
	if h.rotation == nil {
		writeError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "Versioning is not enabled")
		return
	}
	namespace := pathSegment(r.URL.Path, 3)
	key := pathSegment(r.URL.Path, 4)
	versionStr := pathSegment(r.URL.Path, 6)

	if namespace == "" || key == "" || versionStr == "" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "namespace, key, and version are required")
		return
	}

	versionNum, err := strconv.Atoi(versionStr)
	if err != nil || versionNum < 1 {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "version must be a positive integer")
		return
	}

	v, err := h.rotation.GetVersion(namespace, key, versionNum)
	if err != nil {
		logger.Error("get secret version", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to get version")
		return
	}
	if v == nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "Version not found")
		return
	}

	writeJSON(w, http.StatusOK, model.APIResponse{Data: v})
}

// HELPERS
func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		logger.Error("json encode", "error", err)
	}
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(model.APIError{Error: message, Code: code})
}

// pathSegment returns the path segment at the given index (0-indexed, split by "/").
// The leading "/" produces an empty element at index 0.
// e.g. /v1/secrets/myapp/DB_PASSWORD → ["", "v1", "secrets", "myapp", "DB_PASSWORD"]
//
//	index 3 = "myapp", index 4 = "DB_PASSWORD"
func pathSegment(path string, index int) string {
	parts := strings.Split(path, "/")
	if index >= len(parts) {
		return ""
	}
	return parts[index]
}

// isValidIdentifier checks that a namespace or key only contains safe characters.
// This prevents path traversal and injection in URL segments.
func isValidIdentifier(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for _, r := range s {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.') {
			return false
		}
	}
	return true
}
