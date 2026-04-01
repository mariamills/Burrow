// Package seal implements Shamir's Secret Sharing over GF(256) for Burrow's
// unsealing mechanism.
//
// The algorithm splits a secret byte slice into N shares, any K of which can
// reconstruct the original. This uses polynomial interpolation over GF(2^8)
// with the irreducible polynomial x^8 + x^4 + x^3 + x + 1 (0x11B).
//
// Each share is a byte slice of len(secret)+1, where the first byte is the
// share's x-coordinate (1..255) and the remaining bytes are y-values.
package seal

import (
	"crypto/rand"
	"fmt"
)

// Split divides secret into n shares, requiring threshold shares to reconstruct.
// n must be >= threshold, threshold >= 2, n <= 255.
func Split(secret []byte, n, threshold int) ([][]byte, error) {
	if len(secret) == 0 {
		return nil, fmt.Errorf("shamir: secret is empty")
	}
	if threshold < 2 {
		return nil, fmt.Errorf("shamir: threshold must be at least 2")
	}
	if n < threshold {
		return nil, fmt.Errorf("shamir: n must be >= threshold")
	}
	if n > 255 {
		return nil, fmt.Errorf("shamir: n must be <= 255")
	}

	// For each byte of the secret, create a random polynomial of degree (threshold-1)
	// where the constant term is the secret byte.
	shares := make([][]byte, n)
	for i := range shares {
		shares[i] = make([]byte, len(secret)+1)
		shares[i][0] = byte(i + 1) // x-coordinate: 1..n
	}

	for byteIdx, secretByte := range secret {
		// Generate random polynomial coefficients.
		// p(x) = secret + a1*x + a2*x^2 + ... + a_{k-1}*x^{k-1}
		coeffs := make([]byte, threshold)
		coeffs[0] = secretByte

		// Random coefficients for a1..a_{k-1}
		if _, err := rand.Read(coeffs[1:]); err != nil {
			return nil, fmt.Errorf("shamir: random generation failed: %w", err)
		}

		// Evaluate polynomial at each x-coordinate.
		for i := 0; i < n; i++ {
			x := byte(i + 1)
			shares[i][byteIdx+1] = evalPolynomial(coeffs, x)
		}
	}

	return shares, nil
}

// Combine reconstructs the secret from threshold or more shares.
func Combine(shares [][]byte) ([]byte, error) {
	if len(shares) < 2 {
		return nil, fmt.Errorf("shamir: need at least 2 shares")
	}

	// All shares must be the same length.
	shareLen := len(shares[0])
	for _, s := range shares {
		if len(s) != shareLen {
			return nil, fmt.Errorf("shamir: shares have different lengths")
		}
	}

	// Check for duplicate x-coordinates.
	seen := make(map[byte]bool)
	for _, s := range shares {
		if seen[s[0]] {
			return nil, fmt.Errorf("shamir: duplicate share")
		}
		seen[s[0]] = true
	}

	secretLen := shareLen - 1
	secret := make([]byte, secretLen)

	// For each byte position, use Lagrange interpolation to find p(0).
	for byteIdx := 0; byteIdx < secretLen; byteIdx++ {
		points := make([][2]byte, len(shares))
		for i, s := range shares {
			points[i] = [2]byte{s[0], s[byteIdx+1]}
		}
		secret[byteIdx] = lagrangeInterpolate(points)
	}

	return secret, nil
}

// evalPolynomial evaluates a polynomial with the given coefficients at x in GF(256).
// coeffs[0] is the constant term, coeffs[1] is the x coefficient, etc.
func evalPolynomial(coeffs []byte, x byte) byte {
	result := byte(0)
	xPow := byte(1) // x^0 = 1

	for _, c := range coeffs {
		result = gfAdd(result, gfMul(c, xPow))
		xPow = gfMul(xPow, x)
	}
	return result
}

// lagrangeInterpolate finds p(0) from a set of (x, y) points using Lagrange interpolation in GF(256).
func lagrangeInterpolate(points [][2]byte) byte {
	result := byte(0)

	for i, pi := range points {
		// Calculate Lagrange basis polynomial L_i(0)
		num := byte(1)
		den := byte(1)

		for j, pj := range points {
			if i == j {
				continue
			}
			// L_i(0) = product of (0 - x_j) / (x_i - x_j)
			// In GF(256): 0 - x_j = x_j (additive inverse = identity in char 2)
			num = gfMul(num, pj[0])
			den = gfMul(den, gfAdd(pi[0], pj[0]))
		}

		// y_i * L_i(0)
		term := gfMul(pi[1], gfMul(num, gfInv(den)))
		result = gfAdd(result, term)
	}

	return result
}

// GF(256) arithmetic with irreducible polynomial x^8 + x^4 + x^3 + x + 1 (0x11B).

func gfAdd(a, b byte) byte {
	return a ^ b // addition in GF(2^n) is XOR
}

func gfMul(a, b byte) byte {
	var result byte
	for b > 0 {
		if b&1 != 0 {
			result ^= a
		}
		carry := a & 0x80
		a <<= 1
		if carry != 0 {
			a ^= 0x1B // reduce by x^8 + x^4 + x^3 + x + 1
		}
		b >>= 1
	}
	return result
}

func gfInv(a byte) byte {
	if a == 0 {
		return 0 // 0 has no inverse, but we should never hit this
	}
	// Use exponentiation: a^254 = a^(-1) in GF(256) since a^255 = 1
	result := a
	for i := 0; i < 6; i++ {
		result = gfMul(result, result)
		result = gfMul(result, a)
	}
	result = gfMul(result, result)
	return result
}
