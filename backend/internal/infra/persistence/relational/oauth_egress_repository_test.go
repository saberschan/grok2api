package relational

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/chenyme/grok2api/backend/internal/domain/egress"
	"github.com/chenyme/grok2api/backend/internal/repository"
)

func TestOAuthScopeBindingPersistsAcrossDatabaseReopen(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "oauth-scope.db")
	database, err := OpenSQLite(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.InitializeSchema(ctx); err != nil {
		t.Fatal(err)
	}
	nodes := NewEgressRepository(database)
	accounts := NewAccountRepository(database)
	cipher := egressOperationsCipher(t)
	first := createHealthyEgressNodeForScope(t, ctx, nodes, cipher, "oauth-first", egress.ScopeBuildOAuth, 0)
	second := createHealthyEgressNodeForScope(t, ctx, nodes, cipher, "oauth-second", egress.ScopeBuildOAuth, 0)
	credential := createEgressOperationsAccount(t, ctx, accounts, "oauth-scope-persist")

	selected, err := nodes.SelectOAuthEgressNode(ctx, credential.ID)
	if err != nil {
		t.Fatal(err)
	}
	if selected != first.ID && selected != second.ID {
		t.Fatalf("selected OAuth node %d outside dedicated scope", selected)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	database, err = OpenSQLite(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	if err := database.InitializeSchema(ctx); err != nil {
		t.Fatal(err)
	}
	nodes = NewEgressRepository(database)
	reopened, err := nodes.SelectOAuthEgressNode(ctx, credential.ID)
	if err != nil {
		t.Fatal(err)
	}
	if reopened != selected {
		t.Fatalf("selection after DB reopen = %d, want %d", reopened, selected)
	}

	remaining := second.ID
	if selected == second.ID {
		remaining = first.ID
	}
	changed, err := nodes.GetEgressNode(ctx, selected)
	if err != nil {
		t.Fatal(err)
	}
	changed.Scope = egress.ScopeBuild
	if _, err := nodes.UpdateEgressNode(ctx, changed); err != nil {
		t.Fatal(err)
	}
	newSelection, err := nodes.SelectOAuthEgressNode(ctx, credential.ID)
	if err != nil {
		t.Fatal(err)
	}
	if newSelection != remaining {
		t.Fatalf("reclassified node retained selection: got %d want %d", newSelection, remaining)
	}

	if err := nodes.DeleteEgressNode(ctx, remaining); err != nil {
		t.Fatal(err)
	}
	if _, err := nodes.SelectOAuthEgressNode(ctx, credential.ID); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("empty OAuth scope selection error = %v, want ErrNotFound", err)
	}
}

func TestOAuthNodePlacementBalancesAccountsAcrossTenNodes(t *testing.T) {
	nodeIDs := []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	counts := make(map[uint64]int, len(nodeIDs))
	movedAfterExpansion := 0
	for accountID := uint64(1); accountID <= 1000; accountID++ {
		selected := oauthNodeForAccount(accountID, nodeIDs)
		counts[selected]++
		if oauthNodeForAccount(accountID, []uint64{nodeIDs[0]}) != selected {
			movedAfterExpansion++
		}
	}
	for _, nodeID := range nodeIDs {
		if counts[nodeID] < 70 || counts[nodeID] > 130 {
			t.Fatalf("node %d received %d of 1000 accounts; expected a balanced spread", nodeID, counts[nodeID])
		}
	}
	if movedAfterExpansion < 800 {
		t.Fatalf("adding nodes moved only %d of 1000 accounts off the original single node", movedAfterExpansion)
	}
}

func TestOAuthAssignmentsRebalanceWhenPoolExpands(t *testing.T) {
	ctx := context.Background()
	database := openTestDatabase(t)
	nodes := NewEgressRepository(database)
	accounts := NewAccountRepository(database)
	cipher := egressOperationsCipher(t)
	first := createHealthyEgressNodeForScope(t, ctx, nodes, cipher, "oauth-pool-first", egress.ScopeBuildOAuth, 0)
	accountIDs := make([]uint64, 0, 100)
	for index := 0; index < 100; index++ {
		account := createEgressOperationsAccount(t, ctx, accounts, fmt.Sprintf("oauth-pool-account-%03d", index))
		selected, err := nodes.SelectOAuthEgressNode(ctx, account.ID)
		if err != nil {
			t.Fatal(err)
		}
		if selected != first.ID {
			t.Fatalf("single-node pool selected %d, want %d", selected, first.ID)
		}
		accountIDs = append(accountIDs, account.ID)
	}

	for index := 1; index < 10; index++ {
		createHealthyEgressNodeForScope(t, ctx, nodes, cipher, fmt.Sprintf("oauth-pool-%02d", index), egress.ScopeBuildOAuth, 0)
	}
	selected, err := nodes.SelectOAuthEgressNode(ctx, accountIDs[0])
	if err != nil {
		t.Fatal(err)
	}
	if selected == first.ID {
		t.Fatalf("expanded pool retained first account on the original node %d", first.ID)
	}

	var distribution []struct {
		NodeID uint64
		Count  int64
	}
	if err := database.db.Model(&buildOAuthEgressAssignmentModel{}).
		Select("node_id, COUNT(*) AS count").Group("node_id").Scan(&distribution).Error; err != nil {
		t.Fatal(err)
	}
	if len(distribution) != 10 {
		t.Fatalf("expanded pool uses %d nodes, want all 10: %#v", len(distribution), distribution)
	}
	for _, node := range distribution {
		if node.Count < 1 || node.Count > 25 {
			t.Fatalf("node %d received %d of 100 accounts after rebalance", node.NodeID, node.Count)
		}
	}
	if again, err := nodes.SelectOAuthEgressNode(ctx, accountIDs[0]); err != nil || again != selected {
		t.Fatalf("stable pool changed account assignment: got %d, err=%v; want %d", again, err, selected)
	}
}

func TestInitializeSchemaAddsOAuthPoolFingerprintToExistingAssignments(t *testing.T) {
	ctx := context.Background()
	database, err := OpenSQLite(ctx, filepath.Join(t.TempDir(), "oauth-assignment-upgrade.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	legacyModels := make([]any, 0, len(schemaModels)-1)
	for _, model := range schemaModels {
		if _, isOAuthAssignment := model.(*buildOAuthEgressAssignmentModel); !isOAuthAssignment {
			legacyModels = append(legacyModels, model)
		}
	}
	if err := database.db.WithContext(ctx).AutoMigrate(legacyModels...); err != nil {
		t.Fatal(err)
	}
	if err := database.db.WithContext(ctx).AutoMigrate(&legacyBuildOAuthEgressAssignmentModel{}); err != nil {
		t.Fatal(err)
	}
	if database.db.Migrator().HasColumn(&buildOAuthEgressAssignmentModel{}, "PoolFingerprint") {
		t.Fatal("legacy OAuth assignment unexpectedly has pool_fingerprint before upgrade")
	}
	if err := database.InitializeSchema(ctx); err != nil {
		t.Fatal(err)
	}
	if !database.db.Migrator().HasColumn(&buildOAuthEgressAssignmentModel{}, "PoolFingerprint") {
		t.Fatal("schema initialization did not add pool_fingerprint")
	}
}

type legacyBuildOAuthEgressAssignmentModel struct {
	AccountID uint64    `gorm:"primaryKey"`
	NodeID    uint64    `gorm:"not null;index"`
	CreatedAt time.Time `gorm:"not null"`
	UpdatedAt time.Time `gorm:"not null"`
}

func (legacyBuildOAuthEgressAssignmentModel) TableName() string {
	return "build_oauth_egress_assignments"
}
