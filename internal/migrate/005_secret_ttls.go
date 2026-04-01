package migrate

func init() {
	Register(Migration{
		Version:     5,
		Description: "add expires_at to secrets for TTL support",
		SQL: `
		ALTER TABLE secrets ADD COLUMN expires_at DATETIME;
		CREATE INDEX IF NOT EXISTS idx_secrets_expires ON secrets(expires_at);
		`,
	})
}
