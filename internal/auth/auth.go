// Package auth handles token creation, validation, and bcrypt hashing
//
// Security model:
//   - Raw tokens are generated with 32 bytes of crypto/rand entropy (256 bits).
//   - Only the bcrypt hash is stored, the raw token is shown once and discarded.
//   - bcrypt cost factor 12: ~250ms per hash on modern hardware.
//     This makes brute-forcing a stolen hash database impractical.
//   - Token format: "vlt_" prefix + base64url(32 random bytes)
//     The prefix makes tokens identifiable in logs and grep-able in code.
//   - The root token (from BURROW_ROOT_TOKEN env var) is treated specially:
//     it's compared directly (constant-time) rather than going through bcrypt,
//     because it's set by the operator, and we don't bcrypt it at startup.
package auth

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/mariamills/burrow/internal/crypto"
	"github.com/mariamills/burrow/internal/model"
	"github.com/mariamills/burrow/internal/store"
)

const (
	bcryptCost   = 12
	tokenPrefix  = "vlt_"
	tokenByteLen = 32 // 256 bits of entropy
)

// Service handles all authentication logic
type Service struct {
	store         *store.Store
	rootTokenHash []byte // pre-computed bcrypt hash of root token (avoids 250ms per auth)
	mu            sync.RWMutex
	tokenCache    map[string]*model.Token // in-memory cache: token ID > Token
}

// New creates a new auth Service and seeds the root token.
func New(s *store.Store, rootToken string) (*Service, error) {
	// Pre-compute the bcrypt hash of the root token once at startup
	// This avoids calling bcrypt.GenerateFromPassword (~250ms) on every auth request
	rootHash, err := bcrypt.GenerateFromPassword([]byte(rootToken), bcryptCost)
	if err != nil {
		return nil, fmt.Errorf("auth: failed to hash root token: %w", err)
	}

	svc := &Service{
		store:         s,
		rootTokenHash: rootHash,
		tokenCache:    make(map[string]*model.Token),
	}

	// Seed root token into DB if not already there
	if err := svc.ensureRootToken(rootToken); err != nil {
		return nil, fmt.Errorf("auth: failed to seed root token: %w", err)
	}

	// Load all tokens into the in-memory cache for fast auth.
	if err := svc.refreshCache(); err != nil {
		return nil, fmt.Errorf("auth: failed to load token cache: %w", err)
	}

	return svc, nil
}

// ValidateToken authenticates a raw bearer token from the Authorization header
// Returns the associated Token model on success, or an error on failure.
//
// The process:
//  1. Strip the "Bearer " prefix.
//  2. If it matches the root token (constant-time compare), return root token.
//  3. Otherwise, iterate cached tokens and bcrypt-compare the hash.
//  4. Check token is active, not expired, and update last_used_at.
func (s *Service) ValidateToken(rawToken string) (*model.Token, error) {
	rawToken = strings.TrimPrefix(rawToken, "Bearer ")
	rawToken = strings.TrimSpace(rawToken)

	if rawToken == "" {
		return nil, fmt.Errorf("auth: missing token")
	}

	// Root token check (constant-time string comparison via bcrypt).
	// We use the same bcrypt path to avoid timing attacks.
	if s.isRootToken(rawToken) {
		return s.getRootTokenModel(), nil
	}

	// Check token has the right prefix (fast pre-filter to avoid bcrypt on garbage input).
	if !strings.HasPrefix(rawToken, tokenPrefix) {
		return nil, fmt.Errorf("auth: invalid token format")
	}

	s.mu.RLock()
	tokens := make([]*model.Token, 0, len(s.tokenCache))
	for _, t := range s.tokenCache {
		tokens = append(tokens, t)
	}
	s.mu.RUnlock()

	for _, t := range tokens {
		if !t.Active {
			continue
		}
		// bcrypt.CompareHashAndPassword is constant-time
		if err := bcrypt.CompareHashAndPassword([]byte(t.Hash), []byte(rawToken)); err != nil {
			continue // not a match, try next token
		}

		// Found a match - now validate it
		if t.IsExpired() {
			return nil, fmt.Errorf("auth: token has expired")
		}

		// Update last_used_at asynchronously (non-blocking)
		go func(id string) {
			_ = s.store.TouchToken(id)
		}(t.ID)

		return t, nil
	}

	return nil, fmt.Errorf("auth: invalid or revoked token")
}

// CreateToken mints a new API token, stores its bcrypt hash, and returns
// the raw token string ONCE. The caller must present this to the user
// immediately - it cannot be retrieved again
func (s *Service) CreateToken(req *model.CreateTokenRequest) (*model.CreateTokenResponse, error) {
	// Generate the raw token: prefix + cryptographic random bytes.
	randomPart, err := crypto.GenerateToken(tokenByteLen)
	if err != nil {
		return nil, fmt.Errorf("auth: failed to generate token: %w", err)
	}
	rawToken := tokenPrefix + randomPart

	// Bcrypt the raw token for storage.
	hash, err := bcrypt.GenerateFromPassword([]byte(rawToken), bcryptCost)
	if err != nil {
		return nil, fmt.Errorf("auth: failed to hash token: %w", err)
	}

	// Generate a unique ID for this token.
	id, err := crypto.GenerateID()
	if err != nil {
		return nil, fmt.Errorf("auth: failed to generate token ID: %w", err)
	}

	now := time.Now()
	token := &model.Token{
		ID:          id,
		Name:        req.Name,
		Hash:        string(hash),
		Namespaces:  req.Namespaces,
		Permissions: req.Permissions,
		ExpiresAt:   req.ExpiresAt,
		CreatedAt:   now,
		Active:      true,
	}

	if err := s.store.CreateToken(token); err != nil {
		return nil, fmt.Errorf("auth: failed to store token: %w", err)
	}

	// Add to in-memory cache
	s.mu.Lock()
	s.tokenCache[id] = token
	s.mu.Unlock()

	return &model.CreateTokenResponse{
		Token:     rawToken,
		TokenID:   id,
		Name:      req.Name,
		CreatedAt: now,
	}, nil
}

// RevokeToken marks a token as inactive
func (s *Service) RevokeToken(id string) (bool, error) {
	revoked, err := s.store.RevokeToken(id)
	if err != nil {
		return false, err
	}
	if revoked {
		s.mu.Lock()
		if t, ok := s.tokenCache[id]; ok {
			t.Active = false
		}
		s.mu.Unlock()
	}
	return revoked, nil
}

// ListTokens returns all tokens for admin inspection.
func (s *Service) ListTokens() ([]*model.Token, error) {
	return s.store.ListTokens()
}

// refreshCache reloads all active tokens from the database into memory.
func (s *Service) refreshCache() error {
	tokens, err := s.store.GetAllActiveTokens()
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokenCache = make(map[string]*model.Token, len(tokens))
	for _, t := range tokens {
		s.tokenCache[t.ID] = t
	}
	return nil
}

// ensureRootToken seeds the root token into the DB on first run.
// If a root token record already exists, it's replaced atomically via UpsertRootToken.
func (s *Service) ensureRootToken(rawToken string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(rawToken), bcryptCost)
	if err != nil {
		return err
	}

	rootToken := &model.Token{
		ID:          "root",
		Name:        "Root Token",
		Hash:        string(hash),
		Namespaces:  []string{"*"},
		Permissions: []string{model.PermAdmin},
		CreatedAt:   time.Now(),
		Active:      true,
	}

	return s.store.UpsertRootToken(rootToken)
}

// isRootToken does a constant-time comparison against the configured root token.
// Uses the pre-computed bcrypt hash cached at startup (avoids ~250ms per call).
func (s *Service) isRootToken(rawToken string) bool {
	return bcrypt.CompareHashAndPassword(s.rootTokenHash, []byte(rawToken)) == nil
}

// getRootTokenModel returns the in-memory root token model.
func (s *Service) getRootTokenModel() *model.Token {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if t, ok := s.tokenCache["root"]; ok {
		return t
	}
	// Fallback in case cache miss
	return &model.Token{
		ID:          "root",
		Name:        "Root Token",
		Namespaces:  []string{"*"},
		Permissions: []string{model.PermAdmin},
		Active:      true,
	}
}
