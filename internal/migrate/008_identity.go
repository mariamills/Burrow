package migrate

func init() {
	Register(Migration{
		Version:     8,
		Description: "add identity_providers and user_identities tables for SSO/LDAP/OIDC",
		SQL: `
		CREATE TABLE IF NOT EXISTS identity_providers (
			id         TEXT PRIMARY KEY,
			name       TEXT NOT NULL UNIQUE,
			type       TEXT NOT NULL,
			config     TEXT NOT NULL,
			active     INTEGER NOT NULL DEFAULT 1,
			created_at DATETIME NOT NULL
		);

		CREATE TABLE IF NOT EXISTS user_identities (
			id          TEXT PRIMARY KEY,
			user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			provider_id TEXT NOT NULL REFERENCES identity_providers(id) ON DELETE CASCADE,
			external_id TEXT NOT NULL,
			email       TEXT NOT NULL DEFAULT '',
			created_at  DATETIME NOT NULL,
			UNIQUE(provider_id, external_id)
		);
		CREATE INDEX IF NOT EXISTS idx_ui_user ON user_identities(user_id);
		CREATE INDEX IF NOT EXISTS idx_ui_provider ON user_identities(provider_id);
		`,
	})
}
