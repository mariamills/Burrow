// Package user provides user account management
package user

import (
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/mariamills/burrow/internal/crypto"
	"github.com/mariamills/burrow/internal/domain"
	"github.com/mariamills/burrow/internal/model"
)

const bcryptCost = 12

// dummyHash is a valid bcrypt hash used for constant-time comparison
// when a user doesn't exist (prevents email enumeration via timing)
var dummyHash []byte

func init() {
	dummyHash, _ = bcrypt.GenerateFromPassword([]byte("burrow-dummy-password"), bcryptCost)
}

// Service handles user account operations
type Service struct {
	store    domain.UserStore
	sessions domain.SessionStore
}

// New creates a new user Service.
func New(s domain.UserStore, sessions domain.SessionStore) *Service {
	return &Service{store: s, sessions: sessions}
}

// Register creates a new user account. Returns the created user (without password)
func (s *Service) Register(req *model.RegisterRequest) (*model.User, error) {
	email := strings.ToLower(strings.TrimSpace(req.Email))
	if email == "" {
		return nil, fmt.Errorf("user: email is required")
	}
	if !strings.Contains(email, "@") || len(email) > 254 {
		return nil, fmt.Errorf("user: invalid email format")
	}
	if req.Password == "" {
		return nil, fmt.Errorf("user: password is required")
	}
	if len(req.Password) < 8 {
		return nil, fmt.Errorf("user: password must be at least 8 characters")
	}
	if len(req.Password) > 72 {
		return nil, fmt.Errorf("user: password must be at most 72 characters")
	}

	// Check if email is already taken.
	existing, err := s.store.GetUserByEmail(email)
	if err != nil {
		return nil, fmt.Errorf("user: failed to check existing email: %w", err)
	}
	if existing != nil {
		return nil, fmt.Errorf("user: email already registered")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcryptCost)
	if err != nil {
		return nil, fmt.Errorf("user: failed to hash password: %w", err)
	}

	id, err := crypto.GenerateID()
	if err != nil {
		return nil, fmt.Errorf("user: failed to generate ID: %w", err)
	}

	now := time.Now()
	user := &model.User{
		ID:        id,
		Email:     email,
		Password:  string(hash),
		Name:      strings.TrimSpace(req.Name),
		Active:    true,
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := s.store.CreateUser(user); err != nil {
		return nil, fmt.Errorf("user: failed to create user: %w", err)
	}

	user.Password = "" // never return hash
	return user, nil
}

// Authenticate validates email/password credentials and returns the user on success
func (s *Service) Authenticate(email, password string) (*model.User, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" || password == "" {
		return nil, fmt.Errorf("user: email and password are required")
	}

	user, err := s.store.GetUserByEmail(email)
	if err != nil {
		return nil, fmt.Errorf("user: authentication failed")
	}
	if user == nil || !user.Active {
		// Constant-time: run bcrypt even if user doesn't exist to prevent timing attacks
		bcrypt.CompareHashAndPassword(dummyHash, []byte(password))
		return nil, fmt.Errorf("user: invalid credentials")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return nil, fmt.Errorf("user: invalid credentials")
	}

	user.Password = "" // never return hash
	return user, nil
}

// GetByID retrieves a user by ID
func (s *Service) GetByID(id string) (*model.User, error) {
	user, err := s.store.GetUserByID(id)
	if err != nil {
		return nil, err
	}
	if user != nil {
		user.Password = ""
	}
	return user, nil
}

// List returns all users
func (s *Service) List() ([]*model.User, error) {
	return s.store.ListUsers()
}

// Deactivate marks a user as inactive and invalidates all their sessions
func (s *Service) Deactivate(id string) error {
	if err := s.store.DeactivateUser(id); err != nil {
		return err
	}
	// Invalidate all active sessions for this user.
	if s.sessions != nil {
		_ = s.sessions.DeleteUserSessions(id)
	}
	return nil
}
