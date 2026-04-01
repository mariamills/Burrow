// Package migrate provides a simple numbered migration framework
//
// Migrations are registered in order and applied once.
// The schema_migrations table tracks which migrations have already run, so each migration executes at most once per database
package migrate

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/mariamills/burrow/pkg/logger"
)

// Migration represents a single schema migration
type Migration struct {
	Version     int
	Description string
	SQL         string
}

// registry holds all registered migrations in order
var registry []Migration

// Register adds a migration to the global registry.
// Migrations must be registered in ascending version order
func Register(m Migration) {
	registry = append(registry, m)
}

// Run applies all pending migrations to the given database
// It creates the schema_migrations tracking table if it doesn't exist,
// then applies each migration whose version hasn't been recorded yet
func Run(db *sql.DB) error {
	// Create the tracking table if it doesn't exist.
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version    INTEGER PRIMARY KEY,
			applied_at DATETIME NOT NULL
		)
	`)
	if err != nil {
		return fmt.Errorf("migrate: failed to create schema_migrations table: %w", err)
	}

	for _, m := range registry {
		applied, err := isApplied(db, m.Version)
		if err != nil {
			return fmt.Errorf("migrate: failed to check version %d: %w", m.Version, err)
		}
		if applied {
			continue
		}

		logger.Info("applying migration",
			"version", m.Version,
			"description", m.Description,
		)

		if _, err := db.Exec(m.SQL); err != nil {
			return fmt.Errorf("migrate: version %d (%s) failed: %w", m.Version, m.Description, err)
		}

		if _, err := db.Exec(
			`INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)`,
			m.Version, time.Now(),
		); err != nil {
			return fmt.Errorf("migrate: failed to record version %d: %w", m.Version, err)
		}

		logger.Info("migration applied", "version", m.Version)
	}

	return nil
}

// isApplied checks whether a migration version has already been applied
func isApplied(db *sql.DB, version int) (bool, error) {
	var count int
	err := db.QueryRow(
		`SELECT COUNT(*) FROM schema_migrations WHERE version = ?`,
		version,
	).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}
