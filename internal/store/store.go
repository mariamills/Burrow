// Package store provides the SQLite-backed persistence layer
//
// Schema design:
//   - secrets: stores encrypted values (plaintext NEVER touches this table)
//   - tokens:  stores bcrypt-hashed tokens with scoped permissions
//   - audit:   append-only log of every access attempt
//
// All writes use prepared statements to prevent SQL injection.
// The database file uses WAL mode for better concurrent read performance.
package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver, no CGo required

	"github.com/mariamills/burrow/internal/migrate"
	"github.com/mariamills/burrow/internal/model"
)

// Store is the primary data access object
type Store struct {
	db *sql.DB
}

// New opens (or creates) the SQLite database at the given path,
// applies the schema, and configures pragmas for durability and performance.
func New(dbPath string) (*Store, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("store: failed to open database: %w", err)
	}

	// Validate the connection is actually usable.
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("store: database ping failed: %w", err)
	}

	s := &Store{db: db}
	if err := s.applyPragmas(); err != nil {
		return nil, fmt.Errorf("store: pragma setup failed: %w", err)
	}
	if err := migrate.Run(db); err != nil {
		return nil, fmt.Errorf("store: migration failed: %w", err)
	}

	return s, nil
}

// Close closes the database connection
func (s *Store) Close() error {
	return s.db.Close()
}

// DB returns the underlying *sql.DB for use by the seal manager
func (s *Store) DB() *sql.DB {
	return s.db
}

// Ping checks the database connection is still alive
func (s *Store) Ping() error {
	return s.db.Ping()
}

// applyPragmas sets SQLite performance and durability options.
func (s *Store) applyPragmas() error {
	pragmas := []string{
		`PRAGMA journal_mode = WAL`,   // Write-Ahead Logging for concurrency
		`PRAGMA synchronous = NORMAL`, // Balance durability vs performance
		`PRAGMA foreign_keys = ON`,    // Enforce FK constraints
		`PRAGMA busy_timeout = 5000`,  // Wait up to 5s on locked DB
		`PRAGMA cache_size = -8000`,   // 8MB page cache
	}

	for _, p := range pragmas {
		if _, err := s.db.Exec(p); err != nil {
			return fmt.Errorf("pragma %q failed: %w", p, err)
		}
	}

	return nil
}

// ============================================================
// SECRET OPERATIONS
// ============================================================

// UpsertSecret inserts or replaces a secret
// The value parameter must already be encrypted by the caller
func (s *Store) UpsertSecret(secret *model.Secret) error {
	query := `
		INSERT INTO secrets (id, namespace, key, value, description, expires_at, created_at, updated_at, created_by)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(namespace, key) DO UPDATE SET
			value       = excluded.value,
			description = excluded.description,
			expires_at  = excluded.expires_at,
			updated_at  = excluded.updated_at
	`
	_, err := s.db.Exec(query,
		secret.ID,
		secret.Namespace,
		secret.Key,
		secret.Value, // ciphertext
		secret.Description,
		secret.ExpiresAt,
		secret.CreatedAt,
		secret.UpdatedAt,
		secret.CreatedBy,
	)
	if err != nil {
		return fmt.Errorf("store: upsert secret failed: %w", err)
	}
	return nil
}

// GetSecret retrieves a single secret by namespace and key
// Returns the encrypted value - the caller is responsible for decryption
func (s *Store) GetSecret(namespace, key string) (*model.Secret, error) {
	query := `
		SELECT id, namespace, key, value, description, expires_at, created_at, updated_at, created_by
		FROM secrets
		WHERE namespace = ? AND key = ?
	`
	row := s.db.QueryRow(query, namespace, key)
	secret := &model.Secret{}
	err := row.Scan(
		&secret.ID,
		&secret.Namespace,
		&secret.Key,
		&secret.Value,
		&secret.Description,
		&secret.ExpiresAt,
		&secret.CreatedAt,
		&secret.UpdatedAt,
		&secret.CreatedBy,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil // not found - caller checks for nil
	}
	if err != nil {
		return nil, fmt.Errorf("store: get secret failed: %w", err)
	}
	return secret, nil
}

// ListSecrets returns metadata for all secrets in a namespace.
// Value (ciphertext) is intentionally excluded from list results.
func (s *Store) ListSecrets(namespace string) ([]*model.SecretMeta, error) {
	query := `
		SELECT id, namespace, key, description, expires_at, created_at, updated_at
		FROM secrets
		WHERE namespace = ? AND (expires_at IS NULL OR expires_at > ?)
		ORDER BY key ASC
	`
	rows, err := s.db.Query(query, namespace, time.Now())
	if err != nil {
		return nil, fmt.Errorf("store: list secrets failed: %w", err)
	}
	defer rows.Close()

	var secrets []*model.SecretMeta
	for rows.Next() {
		m := &model.SecretMeta{}
		if err := rows.Scan(&m.ID, &m.Namespace, &m.Key, &m.Description, &m.ExpiresAt, &m.CreatedAt, &m.UpdatedAt); err != nil {
			return nil, fmt.Errorf("store: scan secret meta failed: %w", err)
		}
		secrets = append(secrets, m)
	}
	return secrets, rows.Err()
}

// ListNamespaces returns all distinct namespaces in the vault.
func (s *Store) ListNamespaces() ([]string, error) {
	rows, err := s.db.Query(`SELECT DISTINCT namespace FROM secrets ORDER BY namespace ASC`)
	if err != nil {
		return nil, fmt.Errorf("store: list namespaces failed: %w", err)
	}
	defer rows.Close()

	var namespaces []string
	for rows.Next() {
		var ns string
		if err := rows.Scan(&ns); err != nil {
			return nil, err
		}
		namespaces = append(namespaces, ns)
	}
	return namespaces, rows.Err()
}

// DeleteSecret removes a secret by namespace and key.
// Returns true if a row was actually deleted.
func (s *Store) DeleteSecret(namespace, key string) (bool, error) {
	result, err := s.db.Exec(
		`DELETE FROM secrets WHERE namespace = ? AND key = ?`,
		namespace, key,
	)
	if err != nil {
		return false, fmt.Errorf("store: delete secret failed: %w", err)
	}
	affected, _ := result.RowsAffected()
	return affected > 0, nil
}

// DeleteNamespace removes all secrets in a namespace.
func (s *Store) DeleteNamespace(namespace string) (int64, error) {
	result, err := s.db.Exec(`DELETE FROM secrets WHERE namespace = ?`, namespace)
	if err != nil {
		return 0, fmt.Errorf("store: delete namespace failed: %w", err)
	}
	return result.RowsAffected()
}

// ============================================================
// TOKEN OPERATIONS
// ============================================================

// CreateToken inserts a new token record.
// The hash field must be a bcrypt hash of the raw token - never the raw token.
func (s *Store) CreateToken(t *model.Token) error {
	nsJSON, err := json.Marshal(t.Namespaces)
	if err != nil {
		return fmt.Errorf("store: marshal namespaces: %w", err)
	}
	permJSON, err := json.Marshal(t.Permissions)
	if err != nil {
		return fmt.Errorf("store: marshal permissions: %w", err)
	}

	query := `
		INSERT INTO tokens (id, name, hash, namespaces, permissions, expires_at, created_at, active)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`
	_, err = s.db.Exec(query,
		t.ID, t.Name, t.Hash,
		string(nsJSON), string(permJSON),
		t.ExpiresAt, t.CreatedAt, 1,
	)
	if err != nil {
		return fmt.Errorf("store: create token failed: %w", err)
	}
	return nil
}

// UpsertRootToken atomically inserts or replaces the root token record.
// This avoids the race condition of separate revoke + create operations.
func (s *Store) UpsertRootToken(t *model.Token) error {
	nsJSON, err := json.Marshal(t.Namespaces)
	if err != nil {
		return fmt.Errorf("store: marshal namespaces: %w", err)
	}
	permJSON, err := json.Marshal(t.Permissions)
	if err != nil {
		return fmt.Errorf("store: marshal permissions: %w", err)
	}

	query := `
		INSERT INTO tokens (id, name, hash, namespaces, permissions, expires_at, created_at, active)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			hash       = excluded.hash,
			namespaces = excluded.namespaces,
			permissions = excluded.permissions,
			active     = 1
	`
	_, err = s.db.Exec(query,
		t.ID, t.Name, t.Hash,
		string(nsJSON), string(permJSON),
		t.ExpiresAt, t.CreatedAt, 1,
	)
	if err != nil {
		return fmt.Errorf("store: upsert root token failed: %w", err)
	}
	return nil
}

// GetAllActiveTokens returns all active (non-revoked) tokens for auth lookup.
// This is used by the auth middleware to find a token by prefix-matching.
func (s *Store) GetAllActiveTokens() ([]*model.Token, error) {
	query := `
		SELECT id, name, hash, namespaces, permissions, expires_at, created_at, last_used_at, active
		FROM tokens
		WHERE active = 1
	`
	rows, err := s.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("store: get active tokens failed: %w", err)
	}
	defer rows.Close()

	var tokens []*model.Token
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return nil, err
		}
		tokens = append(tokens, t)
	}
	return tokens, rows.Err()
}

// GetTokenByID retrieves a single token by ID
func (s *Store) GetTokenByID(id string) (*model.Token, error) {
	query := `
		SELECT id, name, hash, namespaces, permissions, expires_at, created_at, last_used_at, active
		FROM tokens WHERE id = ?
	`
	row := s.db.QueryRow(query, id)
	t, err := scanTokenRow(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return t, err
}

// ListTokens returns all tokens (active and revoked) for admin inspection.
// Hashes are excluded from the result.
func (s *Store) ListTokens() ([]*model.Token, error) {
	rows, err := s.db.Query(`SELECT id, name, hash, namespaces, permissions, expires_at, created_at, last_used_at, active FROM tokens ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("store: list tokens failed: %w", err)
	}
	defer rows.Close()

	var tokens []*model.Token
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return nil, err
		}
		t.Hash = "" // never leak hashes in list responses
		tokens = append(tokens, t)
	}
	return tokens, rows.Err()
}

// RevokeToken marks a token as inactive (soft delete - keeps audit trail).
func (s *Store) RevokeToken(id string) (bool, error) {
	result, err := s.db.Exec(`UPDATE tokens SET active = 0 WHERE id = ?`, id)
	if err != nil {
		return false, fmt.Errorf("store: revoke token failed: %w", err)
	}
	affected, _ := result.RowsAffected()
	return affected > 0, nil
}

// TouchToken updates the last_used_at timestamp for a token.
func (s *Store) TouchToken(id string) error {
	_, err := s.db.Exec(`UPDATE tokens SET last_used_at = ? WHERE id = ?`, time.Now(), id)
	return err
}

// scanToken scans a token from sql.Rows.
func scanToken(rows *sql.Rows) (*model.Token, error) {
	t := &model.Token{}
	var nsJSON, permJSON string
	err := rows.Scan(
		&t.ID, &t.Name, &t.Hash,
		&nsJSON, &permJSON,
		&t.ExpiresAt, &t.CreatedAt, &t.LastUsedAt, &t.Active,
	)
	if err != nil {
		return nil, fmt.Errorf("store: scan token: %w", err)
	}
	if err := json.Unmarshal([]byte(nsJSON), &t.Namespaces); err != nil {
		return nil, fmt.Errorf("store: unmarshal namespaces: %w", err)
	}
	if err := json.Unmarshal([]byte(permJSON), &t.Permissions); err != nil {
		return nil, fmt.Errorf("store: unmarshal permissions: %w", err)
	}
	return t, nil
}

// scanTokenRow scans a token from sql.Row (single row query).
func scanTokenRow(row *sql.Row) (*model.Token, error) {
	t := &model.Token{}
	var nsJSON, permJSON string
	err := row.Scan(
		&t.ID, &t.Name, &t.Hash,
		&nsJSON, &permJSON,
		&t.ExpiresAt, &t.CreatedAt, &t.LastUsedAt, &t.Active,
	)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(nsJSON), &t.Namespaces); err != nil {
		return nil, fmt.Errorf("store: unmarshal namespaces: %w", err)
	}
	if err := json.Unmarshal([]byte(permJSON), &t.Permissions); err != nil {
		return nil, fmt.Errorf("store: unmarshal permissions: %w", err)
	}
	return t, nil
}

// ============================================================
// AUDIT LOG
// ============================================================

// WriteAuditEvent appends an event to the audit log.
// This must never fail silently - log the error but don't block the response.
func (s *Store) WriteAuditEvent(e *model.AuditEvent) error {
	query := `
		INSERT INTO audit_log
			(token_id, token_name, action, namespace, secret_key, status_code, ip_address, user_agent, timestamp)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	_, err := s.db.Exec(query,
		e.TokenID, e.TokenName, e.Action,
		e.Namespace, e.SecretKey,
		e.StatusCode, e.IPAddress, e.UserAgent,
		e.Timestamp,
	)
	if err != nil {
		return fmt.Errorf("store: write audit event: %w", err)
	}
	return nil
}

// GetAuditLog returns recent audit events, optionally filtered by namespace.
func (s *Store) GetAuditLog(namespace string, limit int) ([]*model.AuditEvent, error) {
	var (
		query string
		args  []interface{}
	)

	if namespace != "" {
		query = `SELECT id, token_id, token_name, action, namespace, secret_key, status_code, ip_address, user_agent, timestamp FROM audit_log WHERE namespace = ? ORDER BY timestamp DESC LIMIT ?`
		args = []interface{}{namespace, limit}
	} else {
		query = `SELECT id, token_id, token_name, action, namespace, secret_key, status_code, ip_address, user_agent, timestamp FROM audit_log ORDER BY timestamp DESC LIMIT ?`
		args = []interface{}{limit}
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: get audit log: %w", err)
	}
	defer rows.Close()

	var events []*model.AuditEvent
	for rows.Next() {
		e := &model.AuditEvent{}
		if err := rows.Scan(&e.ID, &e.TokenID, &e.TokenName, &e.Action, &e.Namespace, &e.SecretKey, &e.StatusCode, &e.IPAddress, &e.UserAgent, &e.Timestamp); err != nil {
			return nil, err
		}
		// Redact secret keys in audit responses for non-admin callers -
		// the handler layer enforces this; we return full data here.
		events = append(events, e)
	}
	return events, rows.Err()
}

// ============================================================
// SEARCH / UTILITY
// ============================================================

// SearchSecrets finds secrets by key pattern within a namespace.
func (s *Store) SearchSecrets(namespace, pattern string) ([]*model.SecretMeta, error) {
	// Escape both LIKE wildcards: % and _ (both are special in SQL LIKE).
	escaped := strings.ReplaceAll(pattern, "\\", "\\\\")
	escaped = strings.ReplaceAll(escaped, "%", "\\%")
	escaped = strings.ReplaceAll(escaped, "_", "\\_")
	likePattern := "%" + escaped + "%"
	query := `
		SELECT id, namespace, key, description, expires_at, created_at, updated_at
		FROM secrets
		WHERE namespace = ? AND key LIKE ? ESCAPE '\' AND (expires_at IS NULL OR expires_at > ?)
		ORDER BY key ASC
	`
	rows, err := s.db.Query(query, namespace, likePattern, time.Now())
	if err != nil {
		return nil, fmt.Errorf("store: search secrets: %w", err)
	}
	defer rows.Close()

	var results []*model.SecretMeta
	for rows.Next() {
		m := &model.SecretMeta{}
		if err := rows.Scan(&m.ID, &m.Namespace, &m.Key, &m.Description, &m.ExpiresAt, &m.CreatedAt, &m.UpdatedAt); err != nil {
			return nil, err
		}
		results = append(results, m)
	}
	return results, rows.Err()
}

// GetExpiringSecrets returns secrets that will expire before the given time but haven't yet.
func (s *Store) GetExpiringSecrets(before time.Time) ([]*model.SecretMeta, error) {
	query := `
		SELECT id, namespace, key, description, expires_at, created_at, updated_at
		FROM secrets
		WHERE expires_at IS NOT NULL AND expires_at <= ? AND expires_at > ?
		ORDER BY expires_at ASC
	`
	rows, err := s.db.Query(query, before, time.Now())
	if err != nil {
		return nil, fmt.Errorf("store: get expiring secrets: %w", err)
	}
	defer rows.Close()
	return s.scanSecretMetas(rows)
}

// GetExpiredSecrets returns secrets that have already expired.
func (s *Store) GetExpiredSecrets() ([]*model.SecretMeta, error) {
	query := `
		SELECT id, namespace, key, description, expires_at, created_at, updated_at
		FROM secrets
		WHERE expires_at IS NOT NULL AND expires_at <= ?
		ORDER BY expires_at ASC
	`
	rows, err := s.db.Query(query, time.Now())
	if err != nil {
		return nil, fmt.Errorf("store: get expired secrets: %w", err)
	}
	defer rows.Close()
	return s.scanSecretMetas(rows)
}

func (s *Store) scanSecretMetas(rows *sql.Rows) ([]*model.SecretMeta, error) {
	var results []*model.SecretMeta
	for rows.Next() {
		m := &model.SecretMeta{}
		if err := rows.Scan(&m.ID, &m.Namespace, &m.Key, &m.Description, &m.ExpiresAt, &m.CreatedAt, &m.UpdatedAt); err != nil {
			return nil, err
		}
		results = append(results, m)
	}
	return results, rows.Err()
}

// ============================================================
// USER OPERATIONS
// ============================================================

// CreateUser inserts a new user record.
func (s *Store) CreateUser(u *model.User) error {
	query := `INSERT INTO users (id, email, password, name, active, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)`
	_, err := s.db.Exec(query, u.ID, u.Email, u.Password, u.Name, u.Active, u.CreatedAt, u.UpdatedAt)
	if err != nil {
		return fmt.Errorf("store: create user failed: %w", err)
	}
	return nil
}

// GetUserByEmail retrieves a user by email address.
func (s *Store) GetUserByEmail(email string) (*model.User, error) {
	query := `SELECT id, email, password, name, active, created_at, updated_at FROM users WHERE email = ?`
	u := &model.User{}
	err := s.db.QueryRow(query, email).Scan(&u.ID, &u.Email, &u.Password, &u.Name, &u.Active, &u.CreatedAt, &u.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store: get user by email failed: %w", err)
	}
	return u, nil
}

// GetUserByID retrieves a user by ID.
func (s *Store) GetUserByID(id string) (*model.User, error) {
	query := `SELECT id, email, password, name, active, created_at, updated_at FROM users WHERE id = ?`
	u := &model.User{}
	err := s.db.QueryRow(query, id).Scan(&u.ID, &u.Email, &u.Password, &u.Name, &u.Active, &u.CreatedAt, &u.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store: get user by id failed: %w", err)
	}
	return u, nil
}

// ListUsers returns all users (password hashes excluded from query).
func (s *Store) ListUsers() ([]*model.User, error) {
	query := `SELECT id, email, name, active, created_at, updated_at FROM users ORDER BY created_at DESC`
	rows, err := s.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("store: list users failed: %w", err)
	}
	defer rows.Close()

	var users []*model.User
	for rows.Next() {
		u := &model.User{}
		if err := rows.Scan(&u.ID, &u.Email, &u.Name, &u.Active, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

// DeactivateUser marks a user as inactive.
func (s *Store) DeactivateUser(id string) error {
	_, err := s.db.Exec(`UPDATE users SET active = 0, updated_at = ? WHERE id = ?`, time.Now(), id)
	if err != nil {
		return fmt.Errorf("store: deactivate user failed: %w", err)
	}
	return nil
}

// ============================================================
// SESSION OPERATIONS
// ============================================================

// CreateSession inserts a new session record.
func (s *Store) CreateSession(sess *model.Session) error {
	query := `INSERT INTO sessions (id, user_id, token_hash, expires_at, created_at, ip_address, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?)`
	_, err := s.db.Exec(query, sess.ID, sess.UserID, sess.TokenHash, sess.ExpiresAt, sess.CreatedAt, sess.IPAddress, sess.UserAgent)
	if err != nil {
		return fmt.Errorf("store: create session failed: %w", err)
	}
	return nil
}

// GetSessionByHash retrieves a session by the SHA-256 hash of the session token.
func (s *Store) GetSessionByHash(tokenHash string) (*model.Session, error) {
	query := `SELECT id, user_id, token_hash, expires_at, created_at, ip_address, user_agent FROM sessions WHERE token_hash = ?`
	sess := &model.Session{}
	err := s.db.QueryRow(query, tokenHash).Scan(&sess.ID, &sess.UserID, &sess.TokenHash, &sess.ExpiresAt, &sess.CreatedAt, &sess.IPAddress, &sess.UserAgent)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store: get session by hash failed: %w", err)
	}
	return sess, nil
}

// DeleteSession removes a single session by ID.
func (s *Store) DeleteSession(id string) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE id = ?`, id)
	return err
}

// DeleteUserSessions removes all sessions for a user (e.g., on deactivation).
func (s *Store) DeleteUserSessions(userID string) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE user_id = ?`, userID)
	return err
}

// CleanExpiredSessions removes all expired sessions and returns the count deleted.
func (s *Store) CleanExpiredSessions() (int64, error) {
	result, err := s.db.Exec(`DELETE FROM sessions WHERE expires_at < ?`, time.Now())
	if err != nil {
		return 0, fmt.Errorf("store: clean expired sessions failed: %w", err)
	}
	return result.RowsAffected()
}

// ============================================================
// GROUP OPERATIONS
// ============================================================

// CreateGroup inserts a new group.
func (s *Store) CreateGroup(g *model.Group) error {
	_, err := s.db.Exec(
		`INSERT INTO groups (id, name, description, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`,
		g.ID, g.Name, g.Description, g.CreatedAt, g.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("store: create group failed: %w", err)
	}
	return nil
}

// GetGroupByID retrieves a group by ID.
func (s *Store) GetGroupByID(id string) (*model.Group, error) {
	g := &model.Group{}
	err := s.db.QueryRow(
		`SELECT id, name, description, created_at, updated_at FROM groups WHERE id = ?`, id,
	).Scan(&g.ID, &g.Name, &g.Description, &g.CreatedAt, &g.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store: get group by id failed: %w", err)
	}
	return g, nil
}

// GetGroupByName retrieves a group by name.
func (s *Store) GetGroupByName(name string) (*model.Group, error) {
	g := &model.Group{}
	err := s.db.QueryRow(
		`SELECT id, name, description, created_at, updated_at FROM groups WHERE name = ?`, name,
	).Scan(&g.ID, &g.Name, &g.Description, &g.CreatedAt, &g.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store: get group by name failed: %w", err)
	}
	return g, nil
}

// ListGroups returns all groups.
func (s *Store) ListGroups() ([]*model.Group, error) {
	rows, err := s.db.Query(`SELECT id, name, description, created_at, updated_at FROM groups ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("store: list groups failed: %w", err)
	}
	defer rows.Close()

	var groups []*model.Group
	for rows.Next() {
		g := &model.Group{}
		if err := rows.Scan(&g.ID, &g.Name, &g.Description, &g.CreatedAt, &g.UpdatedAt); err != nil {
			return nil, err
		}
		groups = append(groups, g)
	}
	return groups, rows.Err()
}

// UpdateGroup updates a group's name and description.
func (s *Store) UpdateGroup(g *model.Group) error {
	_, err := s.db.Exec(
		`UPDATE groups SET name = ?, description = ?, updated_at = ? WHERE id = ?`,
		g.Name, g.Description, g.UpdatedAt, g.ID,
	)
	if err != nil {
		return fmt.Errorf("store: update group failed: %w", err)
	}
	return nil
}

// DeleteGroup removes a group (cascades to members and permissions via FK).
func (s *Store) DeleteGroup(id string) error {
	_, err := s.db.Exec(`DELETE FROM groups WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("store: delete group failed: %w", err)
	}
	return nil
}

// AddGroupMember adds a user to a group.
func (s *Store) AddGroupMember(groupID, userID, role string) error {
	if role == "" {
		role = "member"
	}
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO group_members (group_id, user_id, role, added_at) VALUES (?, ?, ?, ?)`,
		groupID, userID, role, time.Now(),
	)
	if err != nil {
		return fmt.Errorf("store: add group member failed: %w", err)
	}
	return nil
}

// RemoveGroupMember removes a user from a group.
func (s *Store) RemoveGroupMember(groupID, userID string) error {
	_, err := s.db.Exec(`DELETE FROM group_members WHERE group_id = ? AND user_id = ?`, groupID, userID)
	if err != nil {
		return fmt.Errorf("store: remove group member failed: %w", err)
	}
	return nil
}

// GetGroupMembers returns all members of a group with user info.
func (s *Store) GetGroupMembers(groupID string) ([]*model.GroupMemberInfo, error) {
	rows, err := s.db.Query(`
		SELECT gm.user_id, u.email, u.name, gm.role, gm.added_at
		FROM group_members gm
		JOIN users u ON u.id = gm.user_id
		WHERE gm.group_id = ?
		ORDER BY gm.added_at
	`, groupID)
	if err != nil {
		return nil, fmt.Errorf("store: get group members failed: %w", err)
	}
	defer rows.Close()

	var members []*model.GroupMemberInfo
	for rows.Next() {
		m := &model.GroupMemberInfo{}
		if err := rows.Scan(&m.UserID, &m.Email, &m.Name, &m.Role, &m.AddedAt); err != nil {
			return nil, err
		}
		members = append(members, m)
	}
	return members, rows.Err()
}

// GetUserGroups returns all groups a user belongs to.
func (s *Store) GetUserGroups(userID string) ([]*model.Group, error) {
	rows, err := s.db.Query(`
		SELECT g.id, g.name, g.description, g.created_at, g.updated_at
		FROM groups g
		JOIN group_members gm ON gm.group_id = g.id
		WHERE gm.user_id = ?
		ORDER BY g.name
	`, userID)
	if err != nil {
		return nil, fmt.Errorf("store: get user groups failed: %w", err)
	}
	defer rows.Close()

	var groups []*model.Group
	for rows.Next() {
		g := &model.Group{}
		if err := rows.Scan(&g.ID, &g.Name, &g.Description, &g.CreatedAt, &g.UpdatedAt); err != nil {
			return nil, err
		}
		groups = append(groups, g)
	}
	return groups, rows.Err()
}

// SetGroupPermission sets a group's permissions for a namespace (upsert).
func (s *Store) SetGroupPermission(gp *model.GroupPermission) error {
	permsJSON, err := json.Marshal(gp.Permissions)
	if err != nil {
		return fmt.Errorf("store: marshal group permissions failed: %w", err)
	}
	_, err = s.db.Exec(`
		INSERT INTO group_permissions (id, group_id, namespace, permissions) VALUES (?, ?, ?, ?)
		ON CONFLICT(group_id, namespace) DO UPDATE SET permissions = excluded.permissions
	`, gp.ID, gp.GroupID, gp.Namespace, string(permsJSON))
	if err != nil {
		return fmt.Errorf("store: set group permission failed: %w", err)
	}
	return nil
}

// GetGroupPermissions returns all permission entries for a group.
func (s *Store) GetGroupPermissions(groupID string) ([]*model.GroupPermission, error) {
	rows, err := s.db.Query(
		`SELECT id, group_id, namespace, permissions FROM group_permissions WHERE group_id = ?`, groupID,
	)
	if err != nil {
		return nil, fmt.Errorf("store: get group permissions failed: %w", err)
	}
	defer rows.Close()

	var perms []*model.GroupPermission
	for rows.Next() {
		gp := &model.GroupPermission{}
		var permsJSON string
		if err := rows.Scan(&gp.ID, &gp.GroupID, &gp.Namespace, &permsJSON); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(permsJSON), &gp.Permissions); err != nil {
			return nil, fmt.Errorf("store: unmarshal group permissions failed: %w", err)
		}
		perms = append(perms, gp)
	}
	return perms, rows.Err()
}

// ============================================================
// ROLE OPERATIONS
// ============================================================

// CreateRole inserts a new role.
func (s *Store) CreateRole(r *model.Role) error {
	permsJSON, err := json.Marshal(r.Permissions)
	if err != nil {
		return fmt.Errorf("store: marshal role permissions: %w", err)
	}
	nsJSON, err := json.Marshal(r.Namespaces)
	if err != nil {
		return fmt.Errorf("store: marshal role namespaces: %w", err)
	}
	_, err = s.db.Exec(
		`INSERT INTO roles (id, name, description, permissions, namespaces, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		r.ID, r.Name, r.Description, string(permsJSON), string(nsJSON), r.CreatedAt, r.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("store: create role failed: %w", err)
	}
	return nil
}

// GetRoleByID retrieves a role by ID.
func (s *Store) GetRoleByID(id string) (*model.Role, error) {
	return s.scanRole(s.db.QueryRow(
		`SELECT id, name, description, permissions, namespaces, created_at, updated_at FROM roles WHERE id = ?`, id,
	))
}

// GetRoleByName retrieves a role by name.
func (s *Store) GetRoleByName(name string) (*model.Role, error) {
	return s.scanRole(s.db.QueryRow(
		`SELECT id, name, description, permissions, namespaces, created_at, updated_at FROM roles WHERE name = ?`, name,
	))
}

func (s *Store) scanRole(row *sql.Row) (*model.Role, error) {
	r := &model.Role{}
	var permsJSON, nsJSON string
	err := row.Scan(&r.ID, &r.Name, &r.Description, &permsJSON, &nsJSON, &r.CreatedAt, &r.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store: scan role failed: %w", err)
	}
	if err := json.Unmarshal([]byte(permsJSON), &r.Permissions); err != nil {
		return nil, fmt.Errorf("store: unmarshal role permissions: %w", err)
	}
	if err := json.Unmarshal([]byte(nsJSON), &r.Namespaces); err != nil {
		return nil, fmt.Errorf("store: unmarshal role namespaces: %w", err)
	}
	return r, nil
}

// ListRoles returns all roles.
func (s *Store) ListRoles() ([]*model.Role, error) {
	rows, err := s.db.Query(`SELECT id, name, description, permissions, namespaces, created_at, updated_at FROM roles ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("store: list roles failed: %w", err)
	}
	defer rows.Close()
	return s.scanRoles(rows)
}

// UpdateRole updates a role.
func (s *Store) UpdateRole(r *model.Role) error {
	permsJSON, err := json.Marshal(r.Permissions)
	if err != nil {
		return fmt.Errorf("store: marshal role permissions: %w", err)
	}
	nsJSON, err := json.Marshal(r.Namespaces)
	if err != nil {
		return fmt.Errorf("store: marshal role namespaces: %w", err)
	}
	_, err = s.db.Exec(
		`UPDATE roles SET name = ?, description = ?, permissions = ?, namespaces = ?, updated_at = ? WHERE id = ?`,
		r.Name, r.Description, string(permsJSON), string(nsJSON), r.UpdatedAt, r.ID,
	)
	if err != nil {
		return fmt.Errorf("store: update role failed: %w", err)
	}
	return nil
}

// DeleteRole removes a role (cascades to user_roles and group_roles via FK).
func (s *Store) DeleteRole(id string) error {
	_, err := s.db.Exec(`DELETE FROM roles WHERE id = ?`, id)
	return err
}

// AssignUserRole assigns a role to a user.
func (s *Store) AssignUserRole(userID, roleID string) error {
	_, err := s.db.Exec(`INSERT OR IGNORE INTO user_roles (user_id, role_id) VALUES (?, ?)`, userID, roleID)
	return err
}

// RemoveUserRole removes a role from a user.
func (s *Store) RemoveUserRole(userID, roleID string) error {
	_, err := s.db.Exec(`DELETE FROM user_roles WHERE user_id = ? AND role_id = ?`, userID, roleID)
	return err
}

// GetUserRoles returns roles directly assigned to a user.
func (s *Store) GetUserRoles(userID string) ([]*model.Role, error) {
	rows, err := s.db.Query(`
		SELECT r.id, r.name, r.description, r.permissions, r.namespaces, r.created_at, r.updated_at
		FROM roles r JOIN user_roles ur ON ur.role_id = r.id WHERE ur.user_id = ?
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return s.scanRoles(rows)
}

// AssignGroupRole assigns a role to a group.
func (s *Store) AssignGroupRole(groupID, roleID string) error {
	_, err := s.db.Exec(`INSERT OR IGNORE INTO group_roles (group_id, role_id) VALUES (?, ?)`, groupID, roleID)
	return err
}

// RemoveGroupRole removes a role from a group.
func (s *Store) RemoveGroupRole(groupID, roleID string) error {
	_, err := s.db.Exec(`DELETE FROM group_roles WHERE group_id = ? AND role_id = ?`, groupID, roleID)
	return err
}

// GetGroupRoles returns roles assigned to a group.
func (s *Store) GetGroupRoles(groupID string) ([]*model.Role, error) {
	rows, err := s.db.Query(`
		SELECT r.id, r.name, r.description, r.permissions, r.namespaces, r.created_at, r.updated_at
		FROM roles r JOIN group_roles gr ON gr.role_id = r.id WHERE gr.group_id = ?
	`, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return s.scanRoles(rows)
}

// GetUserEffectiveRoles returns all roles for a user: direct + via group membership.
func (s *Store) GetUserEffectiveRoles(userID string) ([]*model.Role, error) {
	rows, err := s.db.Query(`
		SELECT DISTINCT r.id, r.name, r.description, r.permissions, r.namespaces, r.created_at, r.updated_at
		FROM roles r
		LEFT JOIN user_roles ur ON ur.role_id = r.id AND ur.user_id = ?
		LEFT JOIN group_roles gr ON gr.role_id = r.id
		LEFT JOIN group_members gm ON gm.group_id = gr.group_id AND gm.user_id = ?
		WHERE ur.user_id IS NOT NULL OR gm.user_id IS NOT NULL
	`, userID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return s.scanRoles(rows)
}

func (s *Store) scanRoles(rows *sql.Rows) ([]*model.Role, error) {
	var roles []*model.Role
	for rows.Next() {
		r := &model.Role{}
		var permsJSON, nsJSON string
		if err := rows.Scan(&r.ID, &r.Name, &r.Description, &permsJSON, &nsJSON, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(permsJSON), &r.Permissions); err != nil {
			return nil, fmt.Errorf("store: unmarshal role permissions: %w", err)
		}
		if err := json.Unmarshal([]byte(nsJSON), &r.Namespaces); err != nil {
			return nil, fmt.Errorf("store: unmarshal role namespaces: %w", err)
		}
		roles = append(roles, r)
	}
	return roles, rows.Err()
}

// GetUserGroupPermissions returns all group permissions for a user across all their groups.
func (s *Store) GetUserGroupPermissions(userID string) ([]*model.GroupPermission, error) {
	rows, err := s.db.Query(`
		SELECT gp.id, gp.group_id, gp.namespace, gp.permissions
		FROM group_permissions gp
		JOIN group_members gm ON gm.group_id = gp.group_id
		WHERE gm.user_id = ?
	`, userID)
	if err != nil {
		return nil, fmt.Errorf("store: get user group permissions failed: %w", err)
	}
	defer rows.Close()

	var perms []*model.GroupPermission
	for rows.Next() {
		gp := &model.GroupPermission{}
		var permsJSON string
		if err := rows.Scan(&gp.ID, &gp.GroupID, &gp.Namespace, &permsJSON); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(permsJSON), &gp.Permissions); err != nil {
			return nil, fmt.Errorf("store: unmarshal group permissions failed: %w", err)
		}
		perms = append(perms, gp)
	}
	return perms, rows.Err()
}

// ============================================================
// SECRET VERSION OPERATIONS
// ============================================================

func (s *Store) CreateSecretVersion(v *model.SecretVersion) error {
	_, err := s.db.Exec(
		`INSERT INTO secret_versions (id, namespace, key, value, version, created_at, created_by) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		v.ID, v.Namespace, v.Key, v.Value, v.Version, v.CreatedAt, v.CreatedBy,
	)
	return err
}

func (s *Store) GetSecretVersions(namespace, key string) ([]*model.SecretVersionMeta, error) {
	rows, err := s.db.Query(
		`SELECT id, version, created_at, created_by FROM secret_versions WHERE namespace = ? AND key = ? ORDER BY version DESC`,
		namespace, key,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var versions []*model.SecretVersionMeta
	for rows.Next() {
		v := &model.SecretVersionMeta{}
		if err := rows.Scan(&v.ID, &v.Version, &v.CreatedAt, &v.CreatedBy); err != nil {
			return nil, err
		}
		versions = append(versions, v)
	}
	return versions, rows.Err()
}

func (s *Store) GetSecretVersion(namespace, key string, version int) (*model.SecretVersion, error) {
	v := &model.SecretVersion{}
	err := s.db.QueryRow(
		`SELECT id, namespace, key, value, version, created_at, created_by FROM secret_versions WHERE namespace = ? AND key = ? AND version = ?`,
		namespace, key, version,
	).Scan(&v.ID, &v.Namespace, &v.Key, &v.Value, &v.Version, &v.CreatedAt, &v.CreatedBy)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return v, err
}

func (s *Store) GetLatestVersionNumber(namespace, key string) (int, error) {
	var version int
	err := s.db.QueryRow(
		`SELECT COALESCE(MAX(version), 0) FROM secret_versions WHERE namespace = ? AND key = ?`,
		namespace, key,
	).Scan(&version)
	return version, err
}

// ============================================================
// ROTATION POLICY OPERATIONS
// ============================================================

func (s *Store) UpsertRotationPolicy(rp *model.RotationPolicy) error {
	_, err := s.db.Exec(`
		INSERT INTO rotation_policies (id, namespace, key, interval_secs, callback_url, last_rotated, next_rotation, active)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(namespace, key) DO UPDATE SET
			interval_secs = excluded.interval_secs, callback_url = excluded.callback_url,
			next_rotation = excluded.next_rotation, active = excluded.active
	`, rp.ID, rp.Namespace, rp.Key, rp.IntervalSecs, rp.CallbackURL, rp.LastRotated, rp.NextRotation, rp.Active)
	return err
}

func (s *Store) GetRotationPolicy(namespace, key string) (*model.RotationPolicy, error) {
	rp := &model.RotationPolicy{}
	err := s.db.QueryRow(
		`SELECT id, namespace, key, interval_secs, callback_url, last_rotated, next_rotation, active FROM rotation_policies WHERE namespace = ? AND key = ?`,
		namespace, key,
	).Scan(&rp.ID, &rp.Namespace, &rp.Key, &rp.IntervalSecs, &rp.CallbackURL, &rp.LastRotated, &rp.NextRotation, &rp.Active)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return rp, err
}

func (s *Store) GetDueRotations() ([]*model.RotationPolicy, error) {
	rows, err := s.db.Query(
		`SELECT id, namespace, key, interval_secs, callback_url, last_rotated, next_rotation, active FROM rotation_policies WHERE active = 1 AND next_rotation <= ?`,
		time.Now(),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var policies []*model.RotationPolicy
	for rows.Next() {
		rp := &model.RotationPolicy{}
		if err := rows.Scan(&rp.ID, &rp.Namespace, &rp.Key, &rp.IntervalSecs, &rp.CallbackURL, &rp.LastRotated, &rp.NextRotation, &rp.Active); err != nil {
			return nil, err
		}
		policies = append(policies, rp)
	}
	return policies, rows.Err()
}

func (s *Store) UpdateRotationTimestamps(id string, lastRotated, nextRotation time.Time) error {
	_, err := s.db.Exec(`UPDATE rotation_policies SET last_rotated = ?, next_rotation = ? WHERE id = ?`, lastRotated, nextRotation, id)
	return err
}

// ============================================================
// IDENTITY PROVIDER OPERATIONS
// ============================================================

func (s *Store) CreateIdentityProvider(p *model.IdentityProvider) error {
	_, err := s.db.Exec(
		`INSERT INTO identity_providers (id, name, type, config, active, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		p.ID, p.Name, p.Type, p.Config, p.Active, p.CreatedAt,
	)
	return err
}

func (s *Store) GetIdentityProvider(id string) (*model.IdentityProvider, error) {
	p := &model.IdentityProvider{}
	err := s.db.QueryRow(
		`SELECT id, name, type, config, active, created_at FROM identity_providers WHERE id = ?`, id,
	).Scan(&p.ID, &p.Name, &p.Type, &p.Config, &p.Active, &p.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return p, err
}

func (s *Store) GetIdentityProviderByName(name string) (*model.IdentityProvider, error) {
	p := &model.IdentityProvider{}
	err := s.db.QueryRow(
		`SELECT id, name, type, config, active, created_at FROM identity_providers WHERE name = ?`, name,
	).Scan(&p.ID, &p.Name, &p.Type, &p.Config, &p.Active, &p.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return p, err
}

func (s *Store) ListIdentityProviders() ([]*model.IdentityProvider, error) {
	rows, err := s.db.Query(`SELECT id, name, type, config, active, created_at FROM identity_providers ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var providers []*model.IdentityProvider
	for rows.Next() {
		p := &model.IdentityProvider{}
		if err := rows.Scan(&p.ID, &p.Name, &p.Type, &p.Config, &p.Active, &p.CreatedAt); err != nil {
			return nil, err
		}
		p.Config = "" // never leak config in list responses
		providers = append(providers, p)
	}
	return providers, rows.Err()
}

func (s *Store) DeleteIdentityProvider(id string) error {
	_, err := s.db.Exec(`DELETE FROM identity_providers WHERE id = ?`, id)
	return err
}

func (s *Store) CreateUserIdentity(ui *model.UserIdentity) error {
	_, err := s.db.Exec(
		`INSERT INTO user_identities (id, user_id, provider_id, external_id, email, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		ui.ID, ui.UserID, ui.ProviderID, ui.ExternalID, ui.Email, ui.CreatedAt,
	)
	return err
}

func (s *Store) GetUserIdentityByExternal(providerID, externalID string) (*model.UserIdentity, error) {
	ui := &model.UserIdentity{}
	err := s.db.QueryRow(
		`SELECT id, user_id, provider_id, external_id, email, created_at FROM user_identities WHERE provider_id = ? AND external_id = ?`,
		providerID, externalID,
	).Scan(&ui.ID, &ui.UserID, &ui.ProviderID, &ui.ExternalID, &ui.Email, &ui.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return ui, err
}

func (s *Store) GetUserIdentities(userID string) ([]*model.UserIdentity, error) {
	rows, err := s.db.Query(
		`SELECT id, user_id, provider_id, external_id, email, created_at FROM user_identities WHERE user_id = ?`, userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var identities []*model.UserIdentity
	for rows.Next() {
		ui := &model.UserIdentity{}
		if err := rows.Scan(&ui.ID, &ui.UserID, &ui.ProviderID, &ui.ExternalID, &ui.Email, &ui.CreatedAt); err != nil {
			return nil, err
		}
		identities = append(identities, ui)
	}
	return identities, rows.Err()
}
