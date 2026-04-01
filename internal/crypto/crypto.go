// Package crypto provides AES-256-GCM encryption for secrets at rest
//
// Design decisions:
//   - Each secret gets its own random 12-byte nonce (never reused).
//   - Ciphertext is stored as: base64(nonce || ciphertext || tag).
//   - The encryption key is derived from BURROW_ENCRYPTION_KEY env variable
//     using HKDF-SHA256, so you can safely rotate the env var in future
//     by re-encrypting all secrets (key rotation endpoint is a natural next step).
//   - We use GCM (authenticated encryption) so tampering with ciphertext
//     is detected on decryption - no separate MAC needed.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	keyLen   = 32 // AES-256 requires a 32-byte key
	nonceLen = 12 // GCM standard nonce size
)

// Encryptor holds the derived AES-256-GCM key.
// It is initialised once at startup and reused for all encrypt/decrypt ops.
type Encryptor struct {
	key []byte
}

// New derives a 32-byte AES key from the supplied master key material using
// HKDF-SHA256.  The info parameter acts as a domain separator - changing it
// produces a completely different derived key, so pass the same string
// ("burrow-secret-encryption") on every startup.
func New(masterKey []byte) (*Encryptor, error) {
	if len(masterKey) < 32 {
		return nil, errors.New("crypto: master key must be at least 32 bytes")
	}

	// Use a fixed, application-specific salt for HKDF.
	// This is superior to nil: it provides domain separation even if the master key
	// is accidentally reused across applications. A random salt would require storage,
	// which adds complexity without meaningful benefit when the master key has good entropy.
	salt := sha256.Sum256([]byte("burrow-hkdf-salt-v1"))

	derived := make([]byte, keyLen)
	r := hkdf.New(sha256.New, masterKey, salt[:], []byte("burrow-secret-encryption-v1"))
	if _, err := io.ReadFull(r, derived); err != nil {
		return nil, fmt.Errorf("crypto: key derivation failed: %w", err)
	}

	return &Encryptor{key: derived}, nil
}

// Encrypt encrypts plaintext using AES-256-GCM with a random nonce.
// Returns base64-encoded(nonce || ciphertext+tag).
// The nonce is prepended so Decrypt can extract it without any extra storage.
func (e *Encryptor) Encrypt(plaintext string) (string, error) {
	if plaintext == "" {
		return "", errors.New("crypto: cannot encrypt empty value")
	}

	block, err := aes.NewCipher(e.key)
	if err != nil {
		return "", fmt.Errorf("crypto: failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("crypto: failed to create GCM: %w", err)
	}

	// Generate a cryptographically random nonce.
	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("crypto: failed to generate nonce: %w", err)
	}

	// Seal appends ciphertext+GCM tag to nonce.
	sealed := gcm.Seal(nonce, nonce, []byte(plaintext), nil)

	// Base64-encode the whole blob for storage.
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// Decrypt decrypts a value produced by Encrypt.
func (e *Encryptor) Decrypt(encoded string) (string, error) {
	if encoded == "" {
		return "", errors.New("crypto: cannot decrypt empty value")
	}

	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("crypto: base64 decode failed: %w", err)
	}

	block, err := aes.NewCipher(e.key)
	if err != nil {
		return "", fmt.Errorf("crypto: failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("crypto: failed to create GCM: %w", err)
	}

	minLen := nonceLen + gcm.Overhead()
	if len(data) < minLen {
		return "", errors.New("crypto: ciphertext too short - data may be corrupt or tampered")
	}

	// Split nonce from ciphertext.
	nonce, ciphertext := data[:nonceLen], data[nonceLen:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		// This is the authentication check - if the tag doesn't match,
		// the data has been tampered with or the wrong key was used
		return "", errors.New("crypto: decryption failed - invalid key or tampered data")
	}

	return string(plaintext), nil
}

// GenerateToken generates a cryptographically random token of the given byte
// length and returns it base64-URL-encoded (safe for HTTP headers).
// Use this for minting new API tokens - NOT for encryption keys.
func GenerateToken(byteLen int) (string, error) {
	b := make([]byte, byteLen)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", fmt.Errorf("crypto: failed to generate random token: %w", err)
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// GenerateID generates a short random ID for use as primary keys
func GenerateID() (string, error) {
	b := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", fmt.Errorf("crypto: failed to generate ID: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
