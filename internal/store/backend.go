package store

import (
	"fmt"

	"github.com/mariamills/burrow/pkg/logger"
)

// BackendType identifies the storage backend
type BackendType string

const (
	BackendSQLite   BackendType = "sqlite"
	BackendPostgres BackendType = "postgres"
)

// Config holds storage backend configuration
type Config struct {
	Backend     BackendType
	SQLitePath  string // path to SQLite file (for sqlite backend)
	PostgresURL string // connection string (for postgres backend)
}

// NewFromConfig creates a Store from the given configuration.
// Currently supports SQLite. Postgres support is structured but requires
// the pgx driver to be added as a dependency
func NewFromConfig(cfg Config) (*Store, error) {
	switch cfg.Backend {
	case BackendSQLite, "":
		path := cfg.SQLitePath
		if path == "" {
			path = "./burrow.db"
		}
		logger.Info("using SQLite storage backend", "path", path)
		return New(path)

	case BackendPostgres:
		if cfg.PostgresURL == "" {
			return nil, fmt.Errorf("store: BURROW_POSTGRES_URL is required for postgres backend")
		}
		// Postgres backend is architecturally ready but requires the pgx driver
		// The Store interface is identical - swap the driver and SQL dialect
		return nil, fmt.Errorf("store: postgres backend requires github.com/jackc/pgx/v5, add it as a dependency and implement internal/store/postgres/")

	default:
		return nil, fmt.Errorf("store: unknown backend %q (use 'sqlite' or 'postgres')", cfg.Backend)
	}
}
