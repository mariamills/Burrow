package cluster

import (
	"testing"

	"github.com/mariamills/burrow/internal/store"
)

func newTestDB(t *testing.T) *store.Store {
	t.Helper()
	db, err := store.New(":memory:")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	return db
}

func TestCluster_Disabled_AlwaysLeader(t *testing.T) {
	db := newTestDB(t)
	mgr, err := New(db.DB(), Config{Enabled: false})
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	if !mgr.IsLeader() {
		t.Error("disabled cluster should always be leader")
	}
}

func TestCluster_SingleNode_BecomesLeader(t *testing.T) {
	db := newTestDB(t)
	mgr, err := New(db.DB(), Config{
		Enabled:       true,
		NodeID:        "node-1",
		AdvertiseAddr: "https://node1:8080",
	})
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	// Force a leader election cycle.
	mgr.heartbeat()
	mgr.electLeader()
	mgr.refreshNodes()

	if !mgr.IsLeader() {
		t.Error("single node should become leader")
	}

	nodes := mgr.Nodes()
	if len(nodes) != 1 {
		t.Errorf("got %d nodes, want 1", len(nodes))
	}
	if nodes[0].ID != "node-1" {
		t.Errorf("node ID = %q, want node-1", nodes[0].ID)
	}
}

func TestCluster_Status(t *testing.T) {
	db := newTestDB(t)
	mgr, _ := New(db.DB(), Config{
		Enabled:       true,
		NodeID:        "node-1",
		AdvertiseAddr: "https://node1:8080",
	})

	mgr.heartbeat()
	mgr.electLeader()

	status := mgr.Status()
	if status["enabled"] != true {
		t.Error("status should show enabled=true")
	}
	if status["node_id"] != "node-1" {
		t.Errorf("status node_id = %v, want node-1", status["node_id"])
	}
}

func TestCluster_MissingNodeID(t *testing.T) {
	db := newTestDB(t)
	_, err := New(db.DB(), Config{Enabled: true, AdvertiseAddr: "https://node1:8080"})
	if err == nil {
		t.Fatal("expected error for missing node_id")
	}
}

func TestCluster_MissingAdvertiseAddr(t *testing.T) {
	db := newTestDB(t)
	_, err := New(db.DB(), Config{Enabled: true, NodeID: "node-1"})
	if err == nil {
		t.Fatal("expected error for missing advertise_addr")
	}
}
