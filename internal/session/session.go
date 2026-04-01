// Package session provides session management
//
// Session tokens are SHA-256 hashed before storage (not bcrypt) because:
//   - Sessions are short-lived (24h default) and revocable
//   - SHA-256 is sufficient for tokens with 256 bits of entropy
//   - The threat model differs from long-lived API tokens
package session

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/mariamills/burrow/internal/crypto"
	"github.com/mariamills/burrow/internal/domain"
	"github.com/mariamills/burrow/internal/model"
	"github.com/mariamills/burrow/pkg/logger"
)

const (
	tokenByteLen    = 32 // 256 bits of entropy
	defaultTTL      = 24 * time.Hour
	cleanupInterval = 15 * time.Minute
)

// Service handles session lifecycle.
type Service struct {
	store domain.SessionStore
	users domain.UserStore
	ttl   time.Duration
}

// New creates a new session Service and starts the background cleanup goroutine
func New(s domain.SessionStore, u domain.UserStore) *Service {
	svc := &Service{
		store: s,
		users: u,
		ttl:   defaultTTL,
	}

	// Background goroutine to clean expired sessions.
	go svc.cleanupLoop()

	return svc
}

// Create generates a new session for the given user
// Returns the raw session token (shown once) and the session metadata
func (s *Service) Create(userID, ipAddress, userAgent string) (*model.LoginResponse, error) {
	rawToken, err := crypto.GenerateToken(tokenByteLen)
	if err != nil {
		return nil, fmt.Errorf("session: failed to generate token: %w", err)
	}

	tokenHash := hashToken(rawToken)

	id, err := crypto.GenerateID()
	if err != nil {
		return nil, fmt.Errorf("session: failed to generate ID: %w", err)
	}

	now := time.Now()
	sess := &model.Session{
		ID:        id,
		UserID:    userID,
		TokenHash: tokenHash,
		ExpiresAt: now.Add(s.ttl),
		CreatedAt: now,
		IPAddress: ipAddress,
		UserAgent: userAgent,
	}

	if err := s.store.CreateSession(sess); err != nil {
		return nil, fmt.Errorf("session: failed to store session: %w", err)
	}

	// Fetch the user for the response.
	user, err := s.users.GetUserByID(userID)
	if err != nil {
		return nil, fmt.Errorf("session: failed to fetch user: %w", err)
	}
	if user != nil {
		user.Password = ""
	}

	return &model.LoginResponse{
		Token:     rawToken,
		ExpiresAt: sess.ExpiresAt,
		User:      user,
	}, nil
}

// Validate checks a raw session token and returns the associated session
// Returns nil if the token is invalid or expired
func (s *Service) Validate(rawToken string) (*model.Session, error) {
	if rawToken == "" {
		return nil, fmt.Errorf("session: empty token")
	}

	tokenHash := hashToken(rawToken)
	sess, err := s.store.GetSessionByHash(tokenHash)
	if err != nil {
		return nil, fmt.Errorf("session: validation failed: %w", err)
	}
	if sess == nil {
		return nil, fmt.Errorf("session: invalid token")
	}

	if time.Now().After(sess.ExpiresAt) {
		_ = s.store.DeleteSession(sess.ID)
		return nil, fmt.Errorf("session: expired")
	}

	// Verify the user is still active.
	u, err := s.users.GetUserByID(sess.UserID)
	if err != nil || u == nil || !u.Active {
		_ = s.store.DeleteSession(sess.ID)
		return nil, fmt.Errorf("session: user inactive or not found")
	}

	return sess, nil
}

// Destroy deletes a session by ID.
func (s *Service) Destroy(sessionID string) error {
	return s.store.DeleteSession(sessionID)
}

// cleanupLoop periodically removes expired sessions
func (s *Service) cleanupLoop() {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()
	for range ticker.C {
		count, err := s.store.CleanExpiredSessions()
		if err != nil {
			logger.Error("session cleanup failed", "error", err)
			continue
		}
		if count > 0 {
			logger.Info("cleaned expired sessions", "count", count)
		}
	}
}

// hashToken returns the hex-encoded SHA-256 hash of a session token
func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}
