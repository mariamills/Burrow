package migrate

func init() {
	Register(Migration{
		Version:     6,
		Description: "add secret_versions and rotation_policies tables",
		SQL: `
		CREATE TABLE IF NOT EXISTS secret_versions (
			id         TEXT PRIMARY KEY,
			namespace  TEXT NOT NULL,
			key        TEXT NOT NULL,
			value      TEXT NOT NULL,
			version    INTEGER NOT NULL,
			created_at DATETIME NOT NULL,
			created_by TEXT NOT NULL DEFAULT '',
			UNIQUE(namespace, key, version)
		);
		CREATE INDEX IF NOT EXISTS idx_sv_ns_key ON secret_versions(namespace, key);

		CREATE TABLE IF NOT EXISTS rotation_policies (
			id             TEXT PRIMARY KEY,
			namespace      TEXT NOT NULL,
			key            TEXT NOT NULL,
			interval_secs  INTEGER NOT NULL,
			callback_url   TEXT NOT NULL DEFAULT '',
			last_rotated   DATETIME,
			next_rotation  DATETIME,
			active         INTEGER NOT NULL DEFAULT 1,
			UNIQUE(namespace, key)
		);
		CREATE INDEX IF NOT EXISTS idx_rp_next ON rotation_policies(next_rotation);
		`,
	})
}
