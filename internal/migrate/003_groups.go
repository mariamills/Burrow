package migrate

func init() {
	Register(Migration{
		Version:     3,
		Description: "add groups, group_members, group_permissions tables",
		SQL: `
		CREATE TABLE IF NOT EXISTS groups (
			id          TEXT PRIMARY KEY,
			name        TEXT NOT NULL UNIQUE,
			description TEXT NOT NULL DEFAULT '',
			created_at  DATETIME NOT NULL,
			updated_at  DATETIME NOT NULL
		);

		CREATE TABLE IF NOT EXISTS group_members (
			group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
			user_id  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			role     TEXT NOT NULL DEFAULT 'member',
			added_at DATETIME NOT NULL,
			PRIMARY KEY (group_id, user_id)
		);
		CREATE INDEX IF NOT EXISTS idx_gm_user ON group_members(user_id);

		CREATE TABLE IF NOT EXISTS group_permissions (
			id          TEXT PRIMARY KEY,
			group_id    TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
			namespace   TEXT NOT NULL,
			permissions TEXT NOT NULL,
			UNIQUE(group_id, namespace)
		);
		CREATE INDEX IF NOT EXISTS idx_gp_group ON group_permissions(group_id);
		`,
	})
}
