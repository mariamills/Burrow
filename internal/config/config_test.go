package config

import (
	"os"
	"strings"
	"testing"
)

func setEnv(t *testing.T, key, value string) {
	t.Helper()
	t.Setenv(key, value)
}

func setRequiredEnv(t *testing.T) {
	t.Helper()
	setEnv(t, "BURROW_ENCRYPTION_KEY", strings.Repeat("a", 32))
	setEnv(t, "BURROW_ROOT_TOKEN", strings.Repeat("b", 32))
}

func TestLoad_ValidConfig(t *testing.T) {
	setRequiredEnv(t)
	setEnv(t, "BURROW_PORT", "9090")
	setEnv(t, "BURROW_ENV", "development")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.Port != 9090 {
		t.Errorf("Port = %d, want 9090", cfg.Port)
	}
	if cfg.EncryptionKey == "" {
		t.Error("EncryptionKey is empty")
	}
}

func TestLoad_MissingEncryptionKey(t *testing.T) {
	os.Unsetenv("BURROW_ENCRYPTION_KEY")
	setEnv(t, "BURROW_ROOT_TOKEN", strings.Repeat("b", 32))

	_, err := Load()
	if err == nil {
		t.Fatal("Load() should fail without BURROW_ENCRYPTION_KEY")
	}
	if !strings.Contains(err.Error(), "BURROW_ENCRYPTION_KEY") {
		t.Fatalf("error should mention BURROW_ENCRYPTION_KEY: %v", err)
	}
}

func TestLoad_MissingRootToken(t *testing.T) {
	setEnv(t, "BURROW_ENCRYPTION_KEY", strings.Repeat("a", 32))
	os.Unsetenv("BURROW_ROOT_TOKEN")

	_, err := Load()
	if err == nil {
		t.Fatal("Load() should fail without BURROW_ROOT_TOKEN")
	}
	if !strings.Contains(err.Error(), "BURROW_ROOT_TOKEN") {
		t.Fatalf("error should mention BURROW_ROOT_TOKEN: %v", err)
	}
}

func TestLoad_ShortEncryptionKey(t *testing.T) {
	setEnv(t, "BURROW_ENCRYPTION_KEY", "short")
	setEnv(t, "BURROW_ROOT_TOKEN", strings.Repeat("b", 32))

	_, err := Load()
	if err == nil {
		t.Fatal("Load() should fail with short encryption key")
	}
}

func TestLoad_ShortRootToken(t *testing.T) {
	setEnv(t, "BURROW_ENCRYPTION_KEY", strings.Repeat("a", 32))
	setEnv(t, "BURROW_ROOT_TOKEN", "short")

	_, err := Load()
	if err == nil {
		t.Fatal("Load() should fail with short root token")
	}
}

func TestLoad_ProductionRequiresTLS(t *testing.T) {
	setRequiredEnv(t)
	setEnv(t, "BURROW_ENV", "production")

	_, err := Load()
	if err == nil {
		t.Fatal("Load() should fail in production without TLS")
	}
	if !strings.Contains(err.Error(), "TLS") {
		t.Fatalf("error should mention TLS: %v", err)
	}
}

func TestLoad_ProductionWithTLS(t *testing.T) {
	setRequiredEnv(t)
	setEnv(t, "BURROW_ENV", "production")
	setEnv(t, "BURROW_TLS_CERT", "/path/to/cert.pem")
	setEnv(t, "BURROW_TLS_KEY", "/path/to/key.pem")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if !cfg.IsProduction() {
		t.Error("IsProduction() should be true")
	}
	if !cfg.TLSEnabled() {
		t.Error("TLSEnabled() should be true")
	}
}

func TestLoad_InvalidPort(t *testing.T) {
	setRequiredEnv(t)
	setEnv(t, "BURROW_PORT", "99999")

	_, err := Load()
	if err == nil {
		t.Fatal("Load() should fail with out-of-range port")
	}
}

func TestLoad_Defaults(t *testing.T) {
	setRequiredEnv(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if cfg.Host != "127.0.0.1" {
		t.Errorf("Host = %q, want '127.0.0.1'", cfg.Host)
	}
	if cfg.Port != 8080 {
		t.Errorf("Port = %d, want 8080", cfg.Port)
	}
	if cfg.Environment != "development" {
		t.Errorf("Environment = %q, want 'development'", cfg.Environment)
	}
	if cfg.RateLimitPerMin != 60 {
		t.Errorf("RateLimitPerMin = %d, want 60", cfg.RateLimitPerMin)
	}
	if !cfg.AuditEnabled {
		t.Error("AuditEnabled should default to true")
	}
	if cfg.LogLevel != "info" {
		t.Errorf("LogLevel = %q, want 'info'", cfg.LogLevel)
	}
	if cfg.TrustProxy {
		t.Error("TrustProxy should default to false")
	}
}

func TestConfig_Addr(t *testing.T) {
	cfg := &Config{Host: "127.0.0.1", Port: 3000}
	if got := cfg.Addr(); got != "127.0.0.1:3000" {
		t.Errorf("Addr() = %q, want '127.0.0.1:3000'", got)
	}
}

func TestConfig_IsProduction(t *testing.T) {
	tests := []struct {
		env    string
		expect bool
	}{
		{"production", true},
		{"Production", true},
		{"PRODUCTION", true},
		{"development", false},
		{"", false},
	}

	for _, tt := range tests {
		cfg := &Config{Environment: tt.env}
		if got := cfg.IsProduction(); got != tt.expect {
			t.Errorf("IsProduction(%q) = %v, want %v", tt.env, got, tt.expect)
		}
	}
}
