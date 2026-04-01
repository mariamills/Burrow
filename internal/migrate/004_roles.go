package migrate

func init() {
	Register(Migration{
		Version:     4,
		Description: "add roles, user_roles, group_roles tables",
		SQL: `
		CREATE TABLE IF NOT EXISTS roles (
			id          TEXT PRIMARY KEY,
			name        TEXT NOT NULL UNIQUE,
			description TEXT NOT NULL DEFAULT '',
			permissions TEXT NOT NULL,
			namespaces  TEXT NOT NULL,
			created_at  DATETIME NOT NULL,
			updated_at  DATETIME NOT NULL
		);

		CREATE TABLE IF NOT EXISTS user_roles (
			user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			role_id TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
			PRIMARY KEY (user_id, role_id)
		);
		CREATE INDEX IF NOT EXISTS idx_ur_user ON user_roles(user_id);

		CREATE TABLE IF NOT EXISTS group_roles (
			group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
			role_id  TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
			PRIMARY KEY (group_id, role_id)
		);
		CREATE INDEX IF NOT EXISTS idx_gr_group ON group_roles(group_id);
		`,
	})
}
