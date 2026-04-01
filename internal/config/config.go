// Package config loads and validates Burrow configuration from environment variables
//
// All sensitive values (encryption key, root token) are read from env vars
// never from config files, flags, or source code.
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Config holds all runtime configuration:
type Config struct {
	// Server
	Host        string
	Port        int
	TLSCertFile string
	TLSKeyFile  string
	Environment string // "development" | "production"

	// Security
	EncryptionKey string // BURROW_ENCRYPTION_KEY: master secret, min 32 chars
	RootToken     string // BURROW_ROOT_TOKEN: admin token, set once at init

	// Storage
	DBPath string // path to SQLite file (or ":memory:" for tests)

	// Behaviour
	RateLimitPerMin int  // requests per minute per IP
	AuditEnabled    bool // write audit log to DB
	LogLevel        string
	AllowedOrigins  string // CORS allowed origins (comma-separated, or "*")
	TrustProxy      bool   // trust X-Forwarded-For / X-Real-IP headers

	// Expiry
	ExpiryCheckInterval string // e.g. "5m" (default)
	ExpiryWarnBefore    string // e.g. "24h" (default)
	ExpiryWebhookURL    string // optional webhook URL for expiry notifications

	// Seal
	UnsealMode string // "auto" (default, uses BURROW_ENCRYPTION_KEY) or "shamir"

	// Storage backend
	StorageBackend string // "sqlite" (default) or "postgres"
	PostgresURL    string // connection string for postgres backend

	// Cluster
	ClusterEnabled       bool
	ClusterNodeID        string
	ClusterAdvertiseAddr string
}

// Load reads configuration from environment variables.
// Returns a validated Config or a descriptive error.
func Load() (*Config, error) {
	cfg := &Config{
		Host:                 getEnv("BURROW_HOST", "127.0.0.1"),
		Port:                 getEnvInt("BURROW_PORT", 8080),
		TLSCertFile:          getEnv("BURROW_TLS_CERT", ""),
		TLSKeyFile:           getEnv("BURROW_TLS_KEY", ""),
		Environment:          getEnv("BURROW_ENV", "development"),
		EncryptionKey:        getEnv("BURROW_ENCRYPTION_KEY", ""),
		RootToken:            getEnv("BURROW_ROOT_TOKEN", ""),
		DBPath:               getEnv("BURROW_DB_PATH", "./burrow.db"),
		RateLimitPerMin:      getEnvInt("BURROW_RATE_LIMIT", 60),
		AuditEnabled:         getEnvBool("BURROW_AUDIT_ENABLED", true),
		LogLevel:             getEnv("BURROW_LOG_LEVEL", "info"),
		AllowedOrigins:       getEnv("BURROW_ALLOWED_ORIGINS", ""),
		TrustProxy:           getEnvBool("BURROW_TRUST_PROXY", false),
		ExpiryCheckInterval:  getEnv("BURROW_EXPIRY_CHECK_INTERVAL", "5m"),
		ExpiryWarnBefore:     getEnv("BURROW_EXPIRY_WARN_BEFORE", "24h"),
		ExpiryWebhookURL:     getEnv("BURROW_EXPIRY_WEBHOOK_URL", ""),
		UnsealMode:           getEnv("BURROW_UNSEAL_MODE", "auto"),
		StorageBackend:       getEnv("BURROW_STORAGE_BACKEND", "sqlite"),
		PostgresURL:          getEnv("BURROW_POSTGRES_URL", ""),
		ClusterEnabled:       getEnvBool("BURROW_CLUSTER_ENABLED", false),
		ClusterNodeID:        getEnv("BURROW_CLUSTER_NODE_ID", ""),
		ClusterAdvertiseAddr: getEnv("BURROW_CLUSTER_ADVERTISE_ADDR", ""),
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// validate checks all required fields and security constraints
func (c *Config) validate() error {
	var errs []string

	// In auto mode (default), BURROW_ENCRYPTION_KEY and BURROW_ROOT_TOKEN are required.
	// In shamir mode, provided during vault initialization via the API.
	if c.UnsealMode == "auto" {
		if c.EncryptionKey == "" {
			errs = append(errs, "BURROW_ENCRYPTION_KEY is required (or set BURROW_UNSEAL_MODE=shamir)")
		} else if len(c.EncryptionKey) < 32 {
			errs = append(errs, "BURROW_ENCRYPTION_KEY must be at least 32 characters")
		}

		if c.RootToken == "" {
			errs = append(errs, "BURROW_ROOT_TOKEN is required (or set BURROW_UNSEAL_MODE=shamir)")
		} else if len(c.RootToken) < 32 {
			errs = append(errs, "BURROW_ROOT_TOKEN must be at least 32 characters")
		}
	} else if c.UnsealMode != "shamir" {
		errs = append(errs, "BURROW_UNSEAL_MODE must be 'auto' or 'shamir'")
	}

	// Storage backend validation
	if c.StorageBackend != "sqlite" && c.StorageBackend != "postgres" {
		errs = append(errs, "BURROW_STORAGE_BACKEND must be 'sqlite' or 'postgres'")
	}
	if c.StorageBackend == "postgres" && c.PostgresURL == "" {
		errs = append(errs, "BURROW_POSTGRES_URL is required when using postgres backend")
	}

	// Cluster validation
	if c.ClusterEnabled {
		if c.ClusterNodeID == "" {
			errs = append(errs, "BURROW_CLUSTER_NODE_ID is required when cluster is enabled")
		}
		if c.ClusterAdvertiseAddr == "" {
			errs = append(errs, "BURROW_CLUSTER_ADVERTISE_ADDR is required when cluster is enabled")
		}
	}

	// TLS is mandatory in prod
	if c.IsProduction() && (c.TLSCertFile == "" || c.TLSKeyFile == "") {
		errs = append(errs, "BURROW_TLS_CERT and BURROW_TLS_KEY are required in production")
	}

	if c.Port < 1 || c.Port > 65535 {
		errs = append(errs, fmt.Sprintf("BURROW_PORT %d is out of range (1-65535)", c.Port))
	}

	if len(errs) > 0 {
		return errors.New("config validation failed:\n  - " + strings.Join(errs, "\n  - "))
	}

	return nil
}

// IsProduction returns true when running in production mode
func (c *Config) IsProduction() bool {
	return strings.ToLower(c.Environment) == "production"
}

// Addr returns the host:port string for the HTTP server.
func (c *Config) Addr() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}

// TLSEnabled returns true if both TLS cert and key are configured.
func (c *Config) TLSEnabled() bool {
	return c.TLSCertFile != "" && c.TLSKeyFile != ""
}

// ---- helpers ----
func getEnv(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}

func getEnvBool(key string, fallback bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return fallback
	}
	return b
}
