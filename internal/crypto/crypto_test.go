package crypto

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestNew_ValidKey(t *testing.T) {
	enc, err := New([]byte("this-is-a-test-key-at-least-32ch"))
	if err != nil {
		t.Fatalf("New() returned error: %v", err)
	}
	if enc == nil {
		t.Fatal("New() returned nil encryptor")
	}
	if len(enc.key) != keyLen {
		t.Fatalf("derived key length = %d, want %d", len(enc.key), keyLen)
	}
}

func TestNew_ShortKey(t *testing.T) {
	_, err := New([]byte("short"))
	if err == nil {
		t.Fatal("New() should fail with short key")
	}
	if !strings.Contains(err.Error(), "at least 32 bytes") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNew_EmptyKey(t *testing.T) {
	_, err := New([]byte{})
	if err == nil {
		t.Fatal("New() should fail with empty key")
	}
}

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	enc, _ := New([]byte("test-master-key-with-enough-length"))

	tests := []string{
		"hello",
		"super-secret-api-key-12345",
		strings.Repeat("a", 10000), // large value
		"special chars: !@#$%^&*()_+-=[]{}|;':\",./<>?",
		"\x00\x01\x02binary\xff\xfe",
	}

	for _, plaintext := range tests {
		ciphertext, err := enc.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("Encrypt(%q) error: %v", plaintext[:min(len(plaintext), 20)], err)
		}

		// Ciphertext should be base64 and different from plaintext.
		if ciphertext == plaintext {
			t.Error("ciphertext equals plaintext")
		}

		decrypted, err := enc.Decrypt(ciphertext)
		if err != nil {
			t.Fatalf("Decrypt() error: %v", err)
		}
		if decrypted != plaintext {
			t.Errorf("Decrypt() = %q, want %q", decrypted[:min(len(decrypted), 20)], plaintext[:min(len(plaintext), 20)])
		}
	}
}

func TestEncrypt_UniqueNonces(t *testing.T) {
	enc, _ := New([]byte("test-master-key-with-enough-length"))

	// Same plaintext should produce different ciphertext each time (random nonce).
	ct1, _ := enc.Encrypt("same-value")
	ct2, _ := enc.Encrypt("same-value")
	if ct1 == ct2 {
		t.Error("two encryptions of same plaintext produced identical ciphertext — nonce reuse!")
	}
}

func TestEncrypt_EmptyValue(t *testing.T) {
	enc, _ := New([]byte("test-master-key-with-enough-length"))
	_, err := enc.Encrypt("")
	if err == nil {
		t.Fatal("Encrypt('') should fail")
	}
}

func TestDecrypt_EmptyValue(t *testing.T) {
	enc, _ := New([]byte("test-master-key-with-enough-length"))
	_, err := enc.Decrypt("")
	if err == nil {
		t.Fatal("Decrypt('') should fail")
	}
}

func TestDecrypt_InvalidBase64(t *testing.T) {
	enc, _ := New([]byte("test-master-key-with-enough-length"))
	_, err := enc.Decrypt("not-valid-base64!!!")
	if err == nil {
		t.Fatal("Decrypt() should fail with invalid base64")
	}
}

func TestDecrypt_TamperedCiphertext(t *testing.T) {
	enc, _ := New([]byte("test-master-key-with-enough-length"))
	ct, _ := enc.Encrypt("secret")

	// Decode, tamper, re-encode.
	data, _ := base64.StdEncoding.DecodeString(ct)
	data[len(data)-1] ^= 0xff // flip last byte (GCM tag)
	tampered := base64.StdEncoding.EncodeToString(data)

	_, err := enc.Decrypt(tampered)
	if err == nil {
		t.Fatal("Decrypt() should fail on tampered ciphertext")
	}
	if !strings.Contains(err.Error(), "tampered") {
		t.Fatalf("expected tamper error, got: %v", err)
	}
}

func TestDecrypt_WrongKey(t *testing.T) {
	enc1, _ := New([]byte("key-one-is-long-enough-for-test!"))
	enc2, _ := New([]byte("key-two-is-long-enough-for-test!"))

	ct, _ := enc1.Encrypt("secret")
	_, err := enc2.Decrypt(ct)
	if err == nil {
		t.Fatal("Decrypt() with wrong key should fail")
	}
}

func TestDecrypt_TooShort(t *testing.T) {
	enc, _ := New([]byte("test-master-key-with-enough-length"))
	// 10 bytes is shorter than nonce (12) + GCM overhead (16).
	short := base64.StdEncoding.EncodeToString(make([]byte, 10))
	_, err := enc.Decrypt(short)
	if err == nil {
		t.Fatal("Decrypt() should fail on too-short data")
	}
}

func TestNew_DeterministicDerivation(t *testing.T) {
	// Same master key should produce the same derived key.
	enc1, _ := New([]byte("deterministic-test-key-32-chars!"))
	enc2, _ := New([]byte("deterministic-test-key-32-chars!"))

	if string(enc1.key) != string(enc2.key) {
		t.Error("same master key produced different derived keys")
	}
}

func TestGenerateToken(t *testing.T) {
	tok, err := GenerateToken(32)
	if err != nil {
		t.Fatalf("GenerateToken() error: %v", err)
	}
	// 32 bytes → 44 chars in base64.
	if len(tok) == 0 {
		t.Fatal("GenerateToken() returned empty string")
	}
	// Should be valid base64.
	_, err = base64.URLEncoding.DecodeString(tok)
	if err != nil {
		t.Fatalf("GenerateToken() produced invalid base64: %v", err)
	}
}

func TestGenerateToken_Unique(t *testing.T) {
	t1, _ := GenerateToken(32)
	t2, _ := GenerateToken(32)
	if t1 == t2 {
		t.Error("two GenerateToken calls produced identical output")
	}
}

func TestGenerateID(t *testing.T) {
	id, err := GenerateID()
	if err != nil {
		t.Fatalf("GenerateID() error: %v", err)
	}
	if len(id) == 0 {
		t.Fatal("GenerateID() returned empty string")
	}
	// 12 bytes → 16 chars in base64 raw URL.
	_, err = base64.RawURLEncoding.DecodeString(id)
	if err != nil {
		t.Fatalf("GenerateID() produced invalid base64: %v", err)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
