package seal

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

func TestManager_StartsSealed(t *testing.T) {
	db := newTestDB(t)
	mgr := NewManager(db.DB())

	if !mgr.IsSealed() {
		t.Error("manager should start sealed")
	}
	if key := mgr.MasterKey(); key != nil {
		t.Error("master key should be nil when sealed")
	}
}

func TestManager_Init_And_Unseal(t *testing.T) {
	db := newTestDB(t)
	mgr := NewManager(db.DB())

	// Initialize with 3 shares, threshold 2.
	resp, err := mgr.Init(3, 2)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	if len(resp.Keys) != 3 {
		t.Errorf("got %d keys, want 3", len(resp.Keys))
	}
	if resp.RootToken == "" {
		t.Error("root token should not be empty")
	}

	// After init, vault should be unsealed (auto-unseal on init).
	if mgr.IsSealed() {
		t.Error("vault should be unsealed after init")
	}

	// Master key should be available.
	key := mgr.MasterKey()
	if key == nil {
		t.Fatal("master key should not be nil after init")
	}
}

func TestManager_Seal_And_Unseal_With_Shares(t *testing.T) {
	db := newTestDB(t)
	mgr := NewManager(db.DB())

	resp, _ := mgr.Init(3, 2)

	// Seal it.
	mgr.Seal()
	if !mgr.IsSealed() {
		t.Fatal("vault should be sealed after Seal()")
	}

	// Submit first share — not enough.
	unsealed, err := mgr.SubmitUnsealShare(resp.Keys[0])
	if err != nil {
		t.Fatalf("SubmitUnsealShare(0) failed: %v", err)
	}
	if unsealed {
		t.Error("should not be unsealed with 1 share (threshold=2)")
	}

	// Submit second share — should unseal.
	unsealed, err = mgr.SubmitUnsealShare(resp.Keys[1])
	if err != nil {
		t.Fatalf("SubmitUnsealShare(1) failed: %v", err)
	}
	if !unsealed {
		t.Error("should be unsealed with 2 shares (threshold=2)")
	}

	if mgr.IsSealed() {
		t.Error("vault should be unsealed")
	}
}

func TestManager_Init_AlreadyInitialized(t *testing.T) {
	db := newTestDB(t)
	mgr := NewManager(db.DB())

	_, _ = mgr.Init(3, 2)

	_, err := mgr.Init(3, 2)
	if err == nil {
		t.Fatal("expected error for double init")
	}
}

func TestManager_Status(t *testing.T) {
	db := newTestDB(t)
	mgr := NewManager(db.DB())

	// Before init.
	status, _ := mgr.Status()
	if status.Initialized {
		t.Error("should not be initialized")
	}
	if !status.Sealed {
		t.Error("should be sealed")
	}

	// After init.
	mgr.Init(5, 3)
	status, _ = mgr.Status()
	if !status.Initialized {
		t.Error("should be initialized")
	}
	if status.Sealed {
		t.Error("should not be sealed after init")
	}
	if status.Threshold != 3 {
		t.Errorf("threshold = %d, want 3", status.Threshold)
	}
	if status.Shares != 5 {
		t.Errorf("shares = %d, want 5", status.Shares)
	}
}

func TestManager_AutoUnseal(t *testing.T) {
	db := newTestDB(t)
	mgr := NewManager(db.DB())

	masterKey := []byte("auto-unseal-key-for-dev-mode!!!!")
	mgr.AutoUnseal(masterKey)

	if mgr.IsSealed() {
		t.Error("should not be sealed after AutoUnseal")
	}

	key := mgr.MasterKey()
	if string(key) != string(masterKey) {
		t.Error("master key mismatch")
	}
}

func TestManager_SealWipesKey(t *testing.T) {
	db := newTestDB(t)
	mgr := NewManager(db.DB())

	mgr.AutoUnseal([]byte("test-key-to-be-wiped!!!!!!!!!!!!!"))

	mgr.Seal()
	if key := mgr.MasterKey(); key != nil {
		t.Error("master key should be nil after seal")
	}
}
