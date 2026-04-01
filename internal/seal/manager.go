package seal

import (
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/mariamills/burrow/internal/crypto"
	"github.com/mariamills/burrow/pkg/logger"
)

// Manager manages the seal/unseal lifecycle of the vault
// When sealed, the encryption key is not available and most API endpoints return 503
type Manager struct {
	mu        sync.RWMutex
	db        *sql.DB
	sealed    bool
	masterKey []byte // nil when sealed

	// Unseal progress: collected key shares
	threshold    int
	shares       int
	unsealShares [][]byte
}

// SealConfig represents the persisted seal configuration
type SealConfig struct {
	Shares        int
	Threshold     int
	EncryptedKey  string // base64-encoded encrypted master key (not used in Shamir mode - placeholder for future envelope encryption)
	RootTokenHash string
	InitializedAt time.Time
}

// InitResponse is returned when the vault is first initialized
type InitResponse struct {
	Keys      []string `json:"keys"`       // base64-encoded Shamir shares
	RootToken string   `json:"root_token"` // raw root token, shown ONCE
}

// SealStatus represents the current seal state.
type SealStatus struct {
	Sealed      bool `json:"sealed"`
	Initialized bool `json:"initialized"`
	Threshold   int  `json:"threshold"`
	Shares      int  `json:"shares"`
	Progress    int  `json:"progress"` // number of unseal shares provided so far
}

// NewManager creates a new seal Manager.
func NewManager(db *sql.DB) *Manager {
	return &Manager{
		db:     db,
		sealed: true,
	}
}

// IsSealed returns true if the vault is currently sealed.
func (m *Manager) IsSealed() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.sealed
}

// MasterKey returns the reconstructed master key. Returns nil if sealed.
func (m *Manager) MasterKey() []byte {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.sealed {
		return nil
	}
	// Return a copy to prevent external mutation.
	key := make([]byte, len(m.masterKey))
	copy(key, m.masterKey)
	return key
}

// IsInitialized checks if the vault has been initialized (seal_config exists).
func (m *Manager) IsInitialized() (bool, error) {
	var count int
	err := m.db.QueryRow(`SELECT COUNT(*) FROM seal_config`).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// Status returns the current seal status.
func (m *Manager) Status() (*SealStatus, error) {
	initialized, err := m.IsInitialized()
	if err != nil {
		return nil, err
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	status := &SealStatus{
		Sealed:      m.sealed,
		Initialized: initialized,
		Progress:    len(m.unsealShares),
	}

	if initialized {
		cfg, err := m.getConfig()
		if err == nil && cfg != nil {
			status.Threshold = cfg.Threshold
			status.Shares = cfg.Shares
		}
	}

	return status, nil
}

// Init initializes the vault for the first time.
// Generates a master key, splits it into Shamir shares, and returns the shares + a root token.
func (m *Manager) Init(numShares, threshold int) (*InitResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	initialized, err := m.IsInitialized()
	if err != nil {
		return nil, err
	}
	if initialized {
		return nil, fmt.Errorf("seal: vault is already initialized")
	}

	if numShares < 2 || numShares > 255 {
		return nil, fmt.Errorf("seal: shares must be between 2 and 255")
	}
	if threshold < 2 || threshold > numShares {
		return nil, fmt.Errorf("seal: threshold must be between 2 and shares")
	}

	// Generate a random 32-byte master key.
	masterKeyRaw, err := crypto.GenerateToken(32)
	if err != nil {
		return nil, fmt.Errorf("seal: failed to generate master key: %w", err)
	}
	masterKeyBytes := []byte(masterKeyRaw)

	// Generate a root token.
	rootToken, err := crypto.GenerateToken(32)
	if err != nil {
		return nil, fmt.Errorf("seal: failed to generate root token: %w", err)
	}

	rootHash, err := bcrypt.GenerateFromPassword([]byte(rootToken), 12)
	if err != nil {
		return nil, fmt.Errorf("seal: failed to hash root token: %w", err)
	}

	// Split the master key into Shamir shares (threshold >= 2 enforced above).
	keyShares, err := Split(masterKeyBytes, numShares, threshold)
	if err != nil {
		return nil, fmt.Errorf("seal: failed to split key: %w", err)
	}

	// Store the config (NOT the key — only metadata).
	_, err = m.db.Exec(`
		INSERT INTO seal_config (id, shares, threshold, encrypted_key, root_token_hash, initialized_at)
		VALUES (1, ?, ?, ?, ?, ?)
	`, numShares, threshold, "", string(rootHash), time.Now())
	if err != nil {
		return nil, fmt.Errorf("seal: failed to store config: %w", err)
	}

	// Unseal immediately with the generated key (lock already held).
	m.masterKey = masterKeyBytes
	m.sealed = false
	m.threshold = threshold
	m.shares = numShares

	// Encode shares as base64 for the response.
	encodedShares := make([]string, len(keyShares))
	for i, s := range keyShares {
		encodedShares[i] = base64.StdEncoding.EncodeToString(s)
	}

	logger.Info("vault initialized", "shares", numShares, "threshold", threshold)

	return &InitResponse{
		Keys:      encodedShares,
		RootToken: rootToken,
	}, nil
}

// SubmitUnsealShare accepts one Shamir share for the unseal process.
// Returns true if the vault is now unsealed, false if more shares are needed.
func (m *Manager) SubmitUnsealShare(shareBase64 string) (bool, error) {
	if !m.IsSealed() {
		return true, nil // already unsealed
	}

	initialized, err := m.IsInitialized()
	if err != nil {
		return false, err
	}
	if !initialized {
		return false, fmt.Errorf("seal: vault is not initialized")
	}

	share, err := base64.StdEncoding.DecodeString(shareBase64)
	if err != nil {
		return false, fmt.Errorf("seal: invalid share encoding")
	}

	cfg, err := m.getConfig()
	if err != nil {
		return false, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.threshold = cfg.Threshold
	m.shares = cfg.Shares

	// Check for duplicate share (same x-coordinate = first byte).
	xCoord := share[0]
	for _, existing := range m.unsealShares {
		if existing[0] == xCoord {
			return false, fmt.Errorf("seal: duplicate share (already submitted)")
		}
	}

	m.unsealShares = append(m.unsealShares, share)

	if len(m.unsealShares) < cfg.Threshold {
		logger.Info("unseal share submitted", "progress", len(m.unsealShares), "threshold", cfg.Threshold)
		return false, nil
	}

	// Attempt to reconstruct the master key.
	masterKey, err := Combine(m.unsealShares)
	if err != nil {
		m.unsealShares = nil // reset on failure
		return false, fmt.Errorf("seal: failed to reconstruct key: %w", err)
	}

	m.masterKey = masterKey
	m.sealed = false
	m.unsealShares = nil

	logger.Info("vault unsealed successfully")
	return true, nil
}

// Seal re-seals the vault, wiping the master key from memory.
func (m *Manager) Seal() {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Zero the master key.
	for i := range m.masterKey {
		m.masterKey[i] = 0
	}
	m.masterKey = nil
	m.sealed = true

	// Zero unseal share memory before releasing.
	for _, share := range m.unsealShares {
		for i := range share {
			share[i] = 0
		}
	}
	m.unsealShares = nil

	logger.Info("vault sealed")
}

// AutoUnseal unseals the vault using a provided master key directly (no Shamir).
// Used in development mode with BURROW_ENCRYPTION_KEY.
func (m *Manager) AutoUnseal(masterKey []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.masterKey = masterKey
	m.sealed = false
	logger.Info("vault auto-unsealed (development mode)")
}

// GetRootTokenHash returns the stored root token hash (for auth service initialization after unseal).
func (m *Manager) GetRootTokenHash() (string, error) {
	cfg, err := m.getConfig()
	if err != nil {
		return "", err
	}
	if cfg == nil {
		return "", fmt.Errorf("seal: not initialized")
	}
	return cfg.RootTokenHash, nil
}

func (m *Manager) getConfig() (*SealConfig, error) {
	cfg := &SealConfig{}
	err := m.db.QueryRow(
		`SELECT shares, threshold, encrypted_key, root_token_hash, initialized_at FROM seal_config WHERE id = 1`,
	).Scan(&cfg.Shares, &cfg.Threshold, &cfg.EncryptedKey, &cfg.RootTokenHash, &cfg.InitializedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("seal: failed to read config: %w", err)
	}
	return cfg, nil
}
