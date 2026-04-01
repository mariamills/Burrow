package migrate

func init() {
	Register(Migration{
		Version:     1,
		Description: "baseline schema: secrets, tokens, audit_log",
		SQL: `
		CREATE TABLE IF NOT EXISTS secrets (
			id          TEXT PRIMARY KEY,
			namespace   TEXT NOT NULL,
			key         TEXT NOT NULL,
			value       TEXT NOT NULL,
			description TEXT NOT NULL DEFAULT '',
			created_at  DATETIME NOT NULL,
			updated_at  DATETIME NOT NULL,
			created_by  TEXT NOT NULL DEFAULT '',
			UNIQUE(namespace, key)
		);
		CREATE INDEX IF NOT EXISTS idx_secrets_namespace ON secrets(namespace);
		CREATE INDEX IF NOT EXISTS idx_secrets_ns_key    ON secrets(namespace, key);

		CREATE TABLE IF NOT EXISTS tokens (
			id           TEXT PRIMARY KEY,
			name         TEXT NOT NULL,
			hash         TEXT NOT NULL,
			namespaces   TEXT NOT NULL,
			permissions  TEXT NOT NULL,
			expires_at   DATETIME,
			created_at   DATETIME NOT NULL,
			last_used_at DATETIME,
			active       INTEGER NOT NULL DEFAULT 1
		);
		CREATE INDEX IF NOT EXISTS idx_tokens_active ON tokens(active);

		CREATE TABLE IF NOT EXISTS audit_log (
			id          INTEGER PRIMARY KEY AUTOINCREMENT,
			token_id    TEXT NOT NULL DEFAULT '',
			token_name  TEXT NOT NULL DEFAULT '',
			action      TEXT NOT NULL,
			namespace   TEXT NOT NULL DEFAULT '',
			secret_key  TEXT NOT NULL DEFAULT '',
			status_code INTEGER NOT NULL,
			ip_address  TEXT NOT NULL DEFAULT '',
			user_agent  TEXT NOT NULL DEFAULT '',
			timestamp   DATETIME NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_audit_timestamp  ON audit_log(timestamp);
		CREATE INDEX IF NOT EXISTS idx_audit_token_id   ON audit_log(token_id);
		CREATE INDEX IF NOT EXISTS idx_audit_namespace  ON audit_log(namespace);
		`,
	})
}
