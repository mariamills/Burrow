package seal

import (
	"bytes"
	"testing"
)

func TestSplit_And_Combine(t *testing.T) {
	secret := []byte("this-is-my-super-secret-master-key!")

	shares, err := Split(secret, 5, 3)
	if err != nil {
		t.Fatalf("Split failed: %v", err)
	}
	if len(shares) != 5 {
		t.Fatalf("got %d shares, want 5", len(shares))
	}

	// Reconstruct with exactly 3 shares (threshold).
	reconstructed, err := Combine(shares[:3])
	if err != nil {
		t.Fatalf("Combine failed: %v", err)
	}
	if !bytes.Equal(reconstructed, secret) {
		t.Errorf("reconstructed = %q, want %q", reconstructed, secret)
	}
}

func TestSplit_And_Combine_DifferentSubsets(t *testing.T) {
	secret := []byte("another-secret-key")

	shares, err := Split(secret, 5, 3)
	if err != nil {
		t.Fatalf("Split failed: %v", err)
	}

	// Try different combinations of 3 shares.
	subsets := [][]int{
		{0, 1, 2},
		{0, 2, 4},
		{1, 3, 4},
		{2, 3, 4},
		{0, 1, 4},
	}

	for _, subset := range subsets {
		selected := make([][]byte, 3)
		for i, idx := range subset {
			selected[i] = shares[idx]
		}
		reconstructed, err := Combine(selected)
		if err != nil {
			t.Fatalf("Combine(%v) failed: %v", subset, err)
		}
		if !bytes.Equal(reconstructed, secret) {
			t.Errorf("Combine(%v): got %q, want %q", subset, reconstructed, secret)
		}
	}
}

func TestSplit_And_Combine_AllShares(t *testing.T) {
	secret := []byte("use-all-shares")

	shares, err := Split(secret, 3, 3)
	if err != nil {
		t.Fatalf("Split failed: %v", err)
	}

	reconstructed, err := Combine(shares)
	if err != nil {
		t.Fatalf("Combine failed: %v", err)
	}
	if !bytes.Equal(reconstructed, secret) {
		t.Errorf("reconstructed = %q, want %q", reconstructed, secret)
	}
}

func TestSplit_And_Combine_TwoOfTwo(t *testing.T) {
	secret := []byte("two-of-two-secret")

	shares, err := Split(secret, 2, 2)
	if err != nil {
		t.Fatalf("Split failed: %v", err)
	}

	reconstructed, err := Combine(shares)
	if err != nil {
		t.Fatalf("Combine failed: %v", err)
	}
	if !bytes.Equal(reconstructed, secret) {
		t.Errorf("reconstructed = %q, want %q", reconstructed, secret)
	}
}

func TestCombine_InsufficientShares(t *testing.T) {
	secret := []byte("need-three")

	shares, _ := Split(secret, 5, 3)

	// Only 2 shares — should produce wrong result (not an error, just wrong data).
	reconstructed, err := Combine(shares[:2])
	if err != nil {
		t.Fatalf("Combine should not error with 2 shares: %v", err)
	}
	// With fewer shares than threshold, reconstruction gives garbage.
	if bytes.Equal(reconstructed, secret) {
		t.Error("2 shares should NOT reconstruct the correct secret (threshold=3)")
	}
}

func TestSplit_EmptySecret(t *testing.T) {
	_, err := Split([]byte{}, 3, 2)
	if err == nil {
		t.Fatal("expected error for empty secret")
	}
}

func TestSplit_InvalidParams(t *testing.T) {
	secret := []byte("test")

	_, err := Split(secret, 1, 2)
	if err == nil {
		t.Fatal("expected error when n < threshold")
	}

	_, err = Split(secret, 3, 1)
	if err == nil {
		t.Fatal("expected error when threshold < 2")
	}

	_, err = Split(secret, 256, 2)
	if err == nil {
		t.Fatal("expected error when n > 255")
	}
}

func TestCombine_DuplicateShares(t *testing.T) {
	secret := []byte("test")
	shares, _ := Split(secret, 3, 2)

	_, err := Combine([][]byte{shares[0], shares[0]})
	if err == nil {
		t.Fatal("expected error for duplicate shares")
	}
}

func TestSplit_LargeSecret(t *testing.T) {
	// 64-byte key (512 bits).
	secret := make([]byte, 64)
	for i := range secret {
		secret[i] = byte(i)
	}

	shares, err := Split(secret, 5, 3)
	if err != nil {
		t.Fatalf("Split failed: %v", err)
	}

	reconstructed, err := Combine(shares[:3])
	if err != nil {
		t.Fatalf("Combine failed: %v", err)
	}
	if !bytes.Equal(reconstructed, secret) {
		t.Error("large secret reconstruction failed")
	}
}
