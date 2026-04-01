package model

import (
	"testing"
	"time"
)

func TestToken_HasPermission(t *testing.T) {
	tests := []struct {
		name   string
		perms  []string
		check  string
		expect bool
	}{
		{"has read", []string{"read"}, "read", true},
		{"missing write", []string{"read"}, "write", false},
		{"admin grants all", []string{"admin"}, "read", true},
		{"admin grants write", []string{"admin"}, "write", true},
		{"admin grants delete", []string{"admin"}, "delete", true},
		{"admin grants admin", []string{"admin"}, "admin", true},
		{"empty perms", []string{}, "read", false},
		{"multiple perms", []string{"read", "write"}, "write", true},
		{"multiple perms miss", []string{"read", "write"}, "delete", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tok := &Token{Permissions: tt.perms}
			if got := tok.HasPermission(tt.check); got != tt.expect {
				t.Errorf("HasPermission(%q) = %v, want %v", tt.check, got, tt.expect)
			}
		})
	}
}

func TestToken_CanAccessNamespace(t *testing.T) {
	tests := []struct {
		name       string
		namespaces []string
		check      string
		expect     bool
	}{
		{"wildcard", []string{"*"}, "production", true},
		{"exact match", []string{"production"}, "production", true},
		{"no match", []string{"staging"}, "production", false},
		{"multiple ns", []string{"staging", "production"}, "production", true},
		{"empty ns", []string{}, "production", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tok := &Token{Namespaces: tt.namespaces}
			if got := tok.CanAccessNamespace(tt.check); got != tt.expect {
				t.Errorf("CanAccessNamespace(%q) = %v, want %v", tt.check, got, tt.expect)
			}
		})
	}
}

func TestToken_IsExpired(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	future := time.Now().Add(time.Hour)

	tests := []struct {
		name      string
		expiresAt *time.Time
		expect    bool
	}{
		{"nil expiry (never expires)", nil, false},
		{"expired", &past, true},
		{"not expired", &future, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tok := &Token{ExpiresAt: tt.expiresAt}
			if got := tok.IsExpired(); got != tt.expect {
				t.Errorf("IsExpired() = %v, want %v", got, tt.expect)
			}
		})
	}
}
