// Package rotation provides secret rotation and versioning for Burrow
package rotation

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/mariamills/burrow/internal/crypto"
	"github.com/mariamills/burrow/internal/domain"
	"github.com/mariamills/burrow/internal/model"
	"github.com/mariamills/burrow/pkg/logger"
)

// Service handles secret rotation and versioning
type Service struct {
	secrets  domain.SecretStore
	versions domain.VersionStore
	policies domain.RotationStore
	enc      domain.Encryptor
	audit    domain.AuditStore
}

// New creates a new rotation Service.
func New(s domain.SecretStore, v domain.VersionStore, p domain.RotationStore, enc domain.Encryptor, a domain.AuditStore) *Service {
	return &Service{secrets: s, versions: v, policies: p, enc: enc, audit: a}
}

// Rotate performs a manual rotation of a secret. If the secret has a callback URL
// in its rotation policy, it calls the URL to get a new value. Otherwise, it generates a random 32-byte value.
func (svc *Service) Rotate(namespace, key, createdBy string) (*model.SecretVersionMeta, error) {
	// Get the current secret.
	secret, err := svc.secrets.GetSecret(namespace, key)
	if err != nil {
		return nil, fmt.Errorf("rotation: failed to get secret: %w", err)
	}
	if secret == nil {
		return nil, fmt.Errorf("rotation: secret not found")
	}

	// Determine the new value.
	newValue, err := svc.getNewValue(namespace, key)
	if err != nil {
		return nil, fmt.Errorf("rotation: failed to get new value: %w", err)
	}

	// Encrypt the new value
	ciphertext, err := svc.enc.Encrypt(newValue)
	if err != nil {
		return nil, fmt.Errorf("rotation: encryption failed: %w", err)
	}

	// Archive the current version
	latestVersion, err := svc.versions.GetLatestVersionNumber(namespace, key)
	if err != nil {
		return nil, err
	}
	newVersionNum := latestVersion + 1

	versionID, _ := crypto.GenerateID()
	now := time.Now()

	// Store the OLD value as a version before overwriting
	if err := svc.versions.CreateSecretVersion(&model.SecretVersion{
		ID:        versionID,
		Namespace: namespace,
		Key:       key,
		Value:     secret.Value, // store the existing (encrypted) value in the version history
		Version:   newVersionNum,
		CreatedAt: now,
		CreatedBy: createdBy,
	}); err != nil {
		return nil, fmt.Errorf("rotation: failed to archive version: %w", err)
	}

	// Update the primary secret with the new value
	secret.Value = ciphertext
	secret.UpdatedAt = now
	if err := svc.secrets.UpsertSecret(secret); err != nil {
		return nil, fmt.Errorf("rotation: failed to update secret: %w", err)
	}

	// Update rotation timestamps if a policy exists
	policy, _ := svc.policies.GetRotationPolicy(namespace, key)
	if policy != nil {
		next := now.Add(time.Duration(policy.IntervalSecs) * time.Second)
		_ = svc.policies.UpdateRotationTimestamps(policy.ID, now, next)
	}

	// Audit event.
	_ = svc.audit.WriteAuditEvent(&model.AuditEvent{
		TokenID: createdBy, TokenName: "rotation",
		Action: "rotate", Namespace: namespace, SecretKey: key,
		StatusCode: 200, Timestamp: now,
	})

	return &model.SecretVersionMeta{
		ID: versionID, Version: newVersionNum,
		CreatedAt: now, CreatedBy: createdBy,
	}, nil
}

// SetPolicy creates or updates a rotation policy for a secret
func (svc *Service) SetPolicy(namespace, key string, req *model.SetRotationPolicyRequest) (*model.RotationPolicy, error) {
	if req.IntervalSecs < 60 {
		return nil, fmt.Errorf("rotation: interval must be at least 60 seconds")
	}

	// Verify the secret exists
	secret, err := svc.secrets.GetSecret(namespace, key)
	if err != nil {
		return nil, err
	}
	if secret == nil {
		return nil, fmt.Errorf("rotation: secret not found")
	}

	id, _ := crypto.GenerateID()
	now := time.Now()
	next := now.Add(time.Duration(req.IntervalSecs) * time.Second)

	rp := &model.RotationPolicy{
		ID:           id,
		Namespace:    namespace,
		Key:          key,
		IntervalSecs: req.IntervalSecs,
		CallbackURL:  req.CallbackURL,
		LastRotated:  nil,
		NextRotation: &next,
		Active:       true,
	}

	if err := svc.policies.UpsertRotationPolicy(rp); err != nil {
		return nil, err
	}
	return rp, nil
}

// GetPolicy returns the rotation policy for a secret
func (svc *Service) GetPolicy(namespace, key string) (*model.RotationPolicy, error) {
	return svc.policies.GetRotationPolicy(namespace, key)
}

// ListVersions returns all versions of a secret (metadata only)
func (svc *Service) ListVersions(namespace, key string) ([]*model.SecretVersionMeta, error) {
	return svc.versions.GetSecretVersions(namespace, key)
}

// GetVersion returns a specific version of a secret (decrypted)
func (svc *Service) GetVersion(namespace, key string, version int) (*model.SecretVersion, error) {
	v, err := svc.versions.GetSecretVersion(namespace, key, version)
	if err != nil {
		return nil, err
	}
	if v == nil {
		return nil, nil
	}

	// Decrypt the version's value
	plaintext, err := svc.enc.Decrypt(v.Value)
	if err != nil {
		return nil, fmt.Errorf("rotation: failed to decrypt version: %w", err)
	}
	v.Value = plaintext
	return v, nil
}

// StartWorker begins the background rotation check loop
func (svc *Service) StartWorker(interval time.Duration) {
	logger.Info("rotation worker started", "interval", interval.String())
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		svc.checkDueRotations()
	}
}

func (svc *Service) checkDueRotations() {
	due, err := svc.policies.GetDueRotations()
	if err != nil {
		logger.Error("rotation: failed to check due rotations", "error", err)
		return
	}
	for _, policy := range due {
		logger.Info("rotating secret", "namespace", policy.Namespace, "key", policy.Key)
		if _, err := svc.Rotate(policy.Namespace, policy.Key, "rotation-worker"); err != nil {
			logger.Error("rotation failed", "namespace", policy.Namespace, "key", policy.Key, "error", err)
		}
	}
}

// getNewValue either calls the callback URL or generates a random value
func (svc *Service) getNewValue(namespace, key string) (string, error) {
	policy, _ := svc.policies.GetRotationPolicy(namespace, key)
	if policy != nil && policy.CallbackURL != "" {
		return svc.callCallback(policy.CallbackURL)
	}
	// Generate a random 32-byte value (base64-encoded).
	return crypto.GenerateToken(32)
}

type callbackResponse struct {
	Value string `json:"value"`
}

var callbackClient = &http.Client{Timeout: 10 * time.Second}

func (svc *Service) callCallback(callbackURL string) (string, error) {
	if err := validateCallbackURL(callbackURL); err != nil {
		return "", fmt.Errorf("rotation: %w", err)
	}
	resp, err := callbackClient.Get(callbackURL)
	if err != nil {
		return "", fmt.Errorf("rotation: callback request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("rotation: callback returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("rotation: failed to read callback response: %w", err)
	}

	var cr callbackResponse
	if err := json.Unmarshal(body, &cr); err != nil {
		return "", fmt.Errorf("rotation: invalid callback response: %w", err)
	}
	if cr.Value == "" {
		return "", fmt.Errorf("rotation: callback returned empty value")
	}
	return cr.Value, nil
}

func validateCallbackURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid callback URL: %w", err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return fmt.Errorf("callback URL must use http or https")
	}
	host := u.Hostname()
	if host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "0.0.0.0" {
		return fmt.Errorf("callback URL must not point to localhost")
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
			return fmt.Errorf("callback URL must not point to private/internal networks")
		}
	}
	return nil
}
