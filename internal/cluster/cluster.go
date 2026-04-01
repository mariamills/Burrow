// Package cluster provides multi-node coordination for HA deployments
//
// Architecture:
//   - Each node registers itself in a cluster_nodes table
//   - Leader election uses database advisory locks (Postgres) or a simple
//     "oldest active heartbeat" strategy (SQLite, for development)
//   - The leader runs background workers (expiry, rotation, session cleanup)
//   - Followers serve API requests but defer background work to the leader
//
// This package is designed to work with both SQLite (single-node, for dev/testing)
// and Postgres (multi-node, for production). Full distributed locking requires
// Postgres advisory locks, which will be implemented when the pgx driver is added.
package cluster

import (
	"database/sql"
	"fmt"
	"sync"
	"time"

	"github.com/mariamills/burrow/pkg/logger"
)

// Node represents a cluster member
type Node struct {
	ID            string    `json:"id"`
	Address       string    `json:"address"`
	IsLeader      bool      `json:"is_leader"`
	LastHeartbeat time.Time `json:"last_heartbeat"`
	JoinedAt      time.Time `json:"joined_at"`
}

// Config holds cluster configuration
type Config struct {
	Enabled           bool
	NodeID            string
	AdvertiseAddr     string
	HeartbeatInterval time.Duration
}

// Manager handles cluster membership and leader election
type Manager struct {
	mu       sync.RWMutex
	db       *sql.DB
	cfg      Config
	isLeader bool
	nodes    []Node
}

// New creates a new cluster Manager
func New(db *sql.DB, cfg Config) (*Manager, error) {
	if !cfg.Enabled {
		return &Manager{db: db, cfg: cfg, isLeader: true}, nil // single-node = always leader
	}

	if cfg.NodeID == "" {
		return nil, fmt.Errorf("cluster: node_id is required")
	}
	if cfg.AdvertiseAddr == "" {
		return nil, fmt.Errorf("cluster: advertise_addr is required")
	}
	if cfg.HeartbeatInterval == 0 {
		cfg.HeartbeatInterval = 10 * time.Second
	}
	if cfg.HeartbeatInterval < time.Second {
		cfg.HeartbeatInterval = time.Second
	}
	if cfg.HeartbeatInterval > 60*time.Second {
		cfg.HeartbeatInterval = 60 * time.Second
	}

	// The cluster_nodes table is created by migration 009
	mgr := &Manager{
		db:  db,
		cfg: cfg,
	}

	// Register this node
	if err := mgr.register(); err != nil {
		return nil, err
	}

	// Start heartbeat and leader election
	go mgr.heartbeatLoop()

	return mgr, nil
}

// IsLeader returns true if this node is the current leader
func (m *Manager) IsLeader() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.isLeader
}

// Nodes returns the list of known cluster nodes
func (m *Manager) Nodes() []Node {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]Node, len(m.nodes))
	copy(result, m.nodes)
	return result
}

// Status returns the cluster status for the API
func (m *Manager) Status() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return map[string]interface{}{
		"enabled":   m.cfg.Enabled,
		"node_id":   m.cfg.NodeID,
		"is_leader": m.isLeader,
		"nodes":     m.nodes,
	}
}

func (m *Manager) register() error {
	now := time.Now()
	_, err := m.db.Exec(`
		INSERT INTO cluster_nodes (id, address, is_leader, last_heartbeat, joined_at)
		VALUES (?, ?, 0, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			address = excluded.address,
			last_heartbeat = excluded.last_heartbeat
	`, m.cfg.NodeID, m.cfg.AdvertiseAddr, now, now)
	if err != nil {
		return fmt.Errorf("cluster: failed to register node: %w", err)
	}
	logger.Info("cluster node registered", "node_id", m.cfg.NodeID, "address", m.cfg.AdvertiseAddr)
	return nil
}

func (m *Manager) heartbeatLoop() {
	ticker := time.NewTicker(m.cfg.HeartbeatInterval)
	defer ticker.Stop()

	for range ticker.C {
		m.heartbeat()
		m.electLeader()
		m.refreshNodes()
	}
}

func (m *Manager) heartbeat() {
	_, err := m.db.Exec(
		`UPDATE cluster_nodes SET last_heartbeat = ? WHERE id = ?`,
		time.Now(), m.cfg.NodeID,
	)
	if err != nil {
		logger.Error("cluster heartbeat failed", "error", err)
	}
}

func (m *Manager) electLeader() {
	// Simple leader election: the node with the oldest active heartbeat
	// (within 3x heartbeat interval) becomes the leader.
	// For production Postgres, replace this with advisory locks.
	cutoff := time.Now().Add(-3 * m.cfg.HeartbeatInterval)

	tx, err := m.db.Begin()
	if err != nil {
		logger.Error("cluster election: failed to begin transaction", "error", err)
		return
	}
	defer tx.Rollback()

	// Remove stale nodes.
	if _, err := tx.Exec(`DELETE FROM cluster_nodes WHERE last_heartbeat < ?`, cutoff); err != nil {
		logger.Error("cluster election: failed to remove stale nodes", "error", err)
		return
	}

	// Find the oldest active node.
	var leaderID string
	err = tx.QueryRow(
		`SELECT id FROM cluster_nodes WHERE last_heartbeat >= ? ORDER BY joined_at ASC LIMIT 1`,
		cutoff,
	).Scan(&leaderID)
	if err != nil {
		return
	}

	// Atomic leadership update (single statement).
	if _, err := tx.Exec(
		`UPDATE cluster_nodes SET is_leader = CASE WHEN id = ? THEN 1 ELSE 0 END`,
		leaderID,
	); err != nil {
		logger.Error("cluster election: failed to update leadership", "error", err)
		return
	}

	if err := tx.Commit(); err != nil {
		logger.Error("cluster election: commit failed", "error", err)
		return
	}

	m.mu.Lock()
	wasLeader := m.isLeader
	m.isLeader = leaderID == m.cfg.NodeID
	m.mu.Unlock()

	if m.isLeader && !wasLeader {
		logger.Info("this node became cluster leader", "node_id", m.cfg.NodeID)
	} else if !m.isLeader && wasLeader {
		logger.Info("this node lost cluster leadership", "node_id", m.cfg.NodeID)
	}
}

func (m *Manager) refreshNodes() {
	rows, err := m.db.Query(
		`SELECT id, address, is_leader, last_heartbeat, joined_at FROM cluster_nodes ORDER BY joined_at`,
	)
	if err != nil {
		return
	}
	defer rows.Close()

	var nodes []Node
	for rows.Next() {
		var n Node
		if err := rows.Scan(&n.ID, &n.Address, &n.IsLeader, &n.LastHeartbeat, &n.JoinedAt); err != nil {
			continue
		}
		nodes = append(nodes, n)
	}

	m.mu.Lock()
	m.nodes = nodes
	m.mu.Unlock()
}
