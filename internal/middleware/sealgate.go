package middleware

import (
	"net/http"
)

// SealChecker is implemented by the seal manager
type SealChecker interface {
	IsSealed() bool
}

// SealGate blocks requests when the vault is sealed, returning 503 Service Unavailable
// Only health, root, and seal-related endpoints bypass this check
func SealGate(checker SealChecker) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if checker.IsSealed() {
				writeError(w, http.StatusServiceUnavailable, "SEALED", "Vault is sealed")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
