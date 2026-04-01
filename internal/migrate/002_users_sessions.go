package migrate

func init() {
	Register(Migration{
		Version:     2,
		Description: "add users and sessions tables, link tokens to users",
		SQL: `
		CREATE TABLE IF NOT EXISTS users (
			id         TEXT PRIMARY KEY,
			email      TEXT NOT NULL UNIQUE,
			password   TEXT NOT NULL,
			name       TEXT NOT NULL DEFAULT '',
			active     INTEGER NOT NULL DEFAULT 1,
			created_at DATETIME NOT NULL,
			updated_at DATETIME NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

		CREATE TABLE IF NOT EXISTS sessions (
			id         TEXT PRIMARY KEY,
			user_id    TEXT NOT NULL REFERENCES users(id),
			token_hash TEXT NOT NULL,
			expires_at DATETIME NOT NULL,
			created_at DATETIME NOT NULL,
			ip_address TEXT NOT NULL DEFAULT '',
			user_agent TEXT NOT NULL DEFAULT ''
		);
		CREATE INDEX IF NOT EXISTS idx_sessions_user    ON sessions(user_id);
		CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
		CREATE INDEX IF NOT EXISTS idx_sessions_hash    ON sessions(token_hash);
		`,
	})
}
