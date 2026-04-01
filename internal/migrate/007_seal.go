package migrate

func init() {
	Register(Migration{
		Version:     7,
		Description: "add seal_config table for Shamir unsealing",
		SQL: `
		CREATE TABLE IF NOT EXISTS seal_config (
			id             INTEGER PRIMARY KEY CHECK (id = 1),
			shares         INTEGER NOT NULL,
			threshold      INTEGER NOT NULL,
			encrypted_key  TEXT NOT NULL,
			root_token_hash TEXT NOT NULL,
			initialized_at DATETIME NOT NULL
		);
		`,
	})
}
