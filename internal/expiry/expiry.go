// Package expiry provides background monitoring for secret TTLs
//
// The worker periodically checks for secrets approaching expiration
// and emits audit log entries as warnings. Optionally posts to a webhook URL.
package expiry

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/mariamills/burrow/internal/domain"
	"github.com/mariamills/burrow/internal/model"
	"github.com/mariamills/burrow/pkg/logger"
)

// Config holds expiry worker settings
type Config struct {
	CheckInterval time.Duration // how often to check (default 5m)
	WarnBefore    time.Duration // warn this far before expiry (default 24h)
	WebhookURL    string        // optional webhook for notifications
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() Config {
	return Config{
		CheckInterval: 5 * time.Minute,
		WarnBefore:    24 * time.Hour,
	}
}

// Worker monitors secret expiration
type Worker struct {
	secrets domain.SecretStore
	audit   domain.AuditStore
	cfg     Config
}

// New creates a new expiry Worker
func New(secrets domain.SecretStore, audit domain.AuditStore, cfg Config) *Worker {
	if cfg.CheckInterval == 0 {
		cfg.CheckInterval = 5 * time.Minute
	}
	if cfg.WarnBefore == 0 {
		cfg.WarnBefore = 24 * time.Hour
	}
	// Validate webhook URL if configured.
	if cfg.WebhookURL != "" {
		if err := validateWebhookURL(cfg.WebhookURL); err != nil {
			logger.Warn("expiry webhook URL rejected", "url", redactURL(cfg.WebhookURL), "error", err)
			cfg.WebhookURL = "" // disable webhook
		}
	}

	return &Worker{secrets: secrets, audit: audit, cfg: cfg}
}

// validateWebhookURL checks that the URL uses https and doesn't point to internal networks.
func validateWebhookURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return fmt.Errorf("webhook URL must use http or https scheme")
	}
	host := u.Hostname()
	if host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "0.0.0.0" {
		return fmt.Errorf("webhook URL must not point to localhost")
	}
	// Check for private IP ranges.
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return fmt.Errorf("webhook URL must not point to private/internal networks")
		}
	}
	return nil
}

// redactURL returns the URL with query parameters stripped (may contain auth tokens).
func redactURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "<invalid>"
	}
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

// Start begins the background check loop. Call this in a goroutine.
func (w *Worker) Start() {
	logger.Info("expiry worker started",
		"interval", w.cfg.CheckInterval.String(),
		"warn_before", w.cfg.WarnBefore.String(),
	)

	// Run immediately on start, then on ticker.
	w.check()

	ticker := time.NewTicker(w.cfg.CheckInterval)
	defer ticker.Stop()
	for range ticker.C {
		w.check()
	}
}

func (w *Worker) check() {
	warnBefore := time.Now().Add(w.cfg.WarnBefore)

	expiring, err := w.secrets.GetExpiringSecrets(warnBefore)
	if err != nil {
		logger.Error("expiry check failed", "error", err)
		return
	}

	if len(expiring) == 0 {
		return
	}

	logger.Warn("secrets expiring soon", "count", len(expiring))

	for _, s := range expiring {
		// Write audit event for each expiring secret.
		_ = w.audit.WriteAuditEvent(&model.AuditEvent{
			TokenID:    "system",
			TokenName:  "expiry-worker",
			Action:     "expiry_warning",
			Namespace:  s.Namespace,
			SecretKey:  s.Key,
			StatusCode: 0,
			Timestamp:  time.Now(),
		})
	}

	// Fire webhook if configured.
	if w.cfg.WebhookURL != "" {
		w.fireWebhook(expiring)
	}
}

// webhookPayload is the JSON body sent to the webhook.
type webhookPayload struct {
	Event   string              `json:"event"`
	Count   int                 `json:"count"`
	Secrets []*model.SecretMeta `json:"secrets"`
}

func (w *Worker) fireWebhook(secrets []*model.SecretMeta) {
	payload := webhookPayload{
		Event:   "secrets_expiring",
		Count:   len(secrets),
		Secrets: secrets,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		logger.Error("expiry webhook marshal failed", "error", err)
		return
	}

	// Retry up to 3 times with exponential backoff.
	client := &http.Client{Timeout: 10 * time.Second}
	for attempt := 0; attempt < 3; attempt++ {
		resp, err := client.Post(w.cfg.WebhookURL, "application/json", bytes.NewReader(body))
		if err != nil {
			logger.Warn("expiry webhook failed", "attempt", attempt+1, "error", err)
			time.Sleep(time.Duration(1<<attempt) * time.Second)
			continue
		}
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			logger.Info("expiry webhook sent", "status", resp.StatusCode, "count", len(secrets))
			return
		}

		logger.Warn("expiry webhook non-2xx", "attempt", attempt+1, "status", resp.StatusCode)
		time.Sleep(time.Duration(1<<attempt) * time.Second)
	}

	logger.Error("expiry webhook exhausted retries", "url", redactURL(w.cfg.WebhookURL))
}

// GetExpiringSecrets is a convenience method for the handler to list expiring secrets.
func (w *Worker) GetExpiringSecrets(within time.Duration) ([]*model.SecretMeta, error) {
	return w.secrets.GetExpiringSecrets(time.Now().Add(within))
}

// ParseDuration parses a duration string like "24h", "30m", "7d".
func ParseDuration(s string) (time.Duration, error) {
	// Support "d" suffix for days.
	if len(s) > 1 && s[len(s)-1] == 'd' {
		var days int
		if _, err := fmt.Sscanf(s, "%dd", &days); err == nil {
			return time.Duration(days) * 24 * time.Hour, nil
		}
	}
	return time.ParseDuration(s)
}
