package migrate

func init() {
	Register(Migration{
		Version:     9,
		Description: "add cluster_nodes table for HA clustering",
		SQL: `
		CREATE TABLE IF NOT EXISTS cluster_nodes (
			id             TEXT PRIMARY KEY,
			address        TEXT NOT NULL,
			is_leader      INTEGER NOT NULL DEFAULT 0,
			last_heartbeat DATETIME NOT NULL,
			joined_at      DATETIME NOT NULL
		);
		`,
	})
}
