package relational

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"sort"
	"time"

	"github.com/chenyme/grok2api/backend/internal/domain/egress"
	"github.com/chenyme/grok2api/backend/internal/repository"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// SelectOAuthEgressNode returns one persistent account-to-node binding from
// the OAuth-only node scope. The physical proxy configuration remains on the
// existing egress_nodes row; request failures never change this assignment.
func (r *EgressRepository) SelectOAuthEgressNode(ctx context.Context, accountID uint64) (uint64, error) {
	if accountID == 0 {
		return 0, repository.ErrNotFound
	}

	var selected uint64
	err := r.db.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var eligible []uint64
		if err := tx.Model(&egressNodeModel{}).
			Where("scope = ? AND enabled = ? AND encrypted_proxy_url <> ''", egress.ScopeBuildOAuth, true).
			Order("id ASC").Pluck("id", &eligible).Error; err != nil {
			return err
		}
		if len(eligible) == 0 {
			return repository.ErrNotFound
		}

		poolFingerprint := oauthEgressPoolFingerprint(eligible)
		if err := rebalanceOAuthEgressAssignments(tx, eligible, poolFingerprint); err != nil {
			return err
		}
		selected = oauthNodeForAccount(accountID, eligible)

		var assignment buildOAuthEgressAssignmentModel
		err := tx.Where("account_id = ?", accountID).First(&assignment).Error
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		if err == nil && assignment.NodeID == selected && assignment.PoolFingerprint == poolFingerprint {
			return nil
		}

		now := time.Now().UTC()
		assignment = buildOAuthEgressAssignmentModel{
			AccountID: accountID, NodeID: selected, PoolFingerprint: poolFingerprint, CreatedAt: now, UpdatedAt: now,
		}
		return tx.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "account_id"}},
			DoUpdates: clause.AssignmentColumns([]string{"node_id", "pool_fingerprint", "updated_at"}),
		}).Create(&assignment).Error
	})
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return 0, err
		}
		return 0, mapError(err)
	}
	return selected, nil

}

// rebalanceOAuthEgressAssignments updates persisted account placements only
// when the eligible node set changes. A stable pool keeps account stickiness.
func rebalanceOAuthEgressAssignments(tx *gorm.DB, eligible []uint64, poolFingerprint string) error {
	var first buildOAuthEgressAssignmentModel
	err := tx.Order("account_id ASC").First(&first).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if first.PoolFingerprint == poolFingerprint {
		return nil
	}
	var assignments []buildOAuthEgressAssignmentModel
	if err := tx.Order("account_id ASC").Find(&assignments).Error; err != nil {
		return err
	}
	if len(assignments) == 0 {
		return nil
	}
	now := time.Now().UTC()
	for index := range assignments {
		assignments[index].NodeID = oauthNodeForAccount(assignments[index].AccountID, eligible)
		assignments[index].PoolFingerprint = poolFingerprint
		assignments[index].UpdatedAt = now
	}
	return tx.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "account_id"}},
		DoUpdates: clause.AssignmentColumns([]string{"node_id", "pool_fingerprint", "updated_at"}),
	}).CreateInBatches(&assignments, 100).Error
}

func oauthNodeForAccount(accountID uint64, nodeIDs []uint64) uint64 {
	var selected uint64
	var best [sha256.Size]byte
	for index, nodeID := range nodeIDs {
		var key [16]byte
		binary.BigEndian.PutUint64(key[:8], accountID)
		binary.BigEndian.PutUint64(key[8:], nodeID)
		score := sha256.Sum256(key[:])
		if index == 0 || bytes.Compare(score[:], best[:]) > 0 {
			selected, best = nodeID, score
		}
	}
	return selected
}

func oauthEgressPoolFingerprint(nodeIDs []uint64) string {
	hasher := sha256.New()
	_, _ = hasher.Write([]byte("grok_build_oauth_pool_v1"))
	var encoded [8]byte
	for _, nodeID := range nodeIDs {
		binary.BigEndian.PutUint64(encoded[:], nodeID)
		_, _ = hasher.Write(encoded[:])
	}
	return hex.EncodeToString(hasher.Sum(nil))
}
func containsOAuthNodeID(values []uint64, nodeID uint64) bool {
	index := sort.Search(len(values), func(i int) bool { return values[i] >= nodeID })
	return index < len(values) && values[index] == nodeID
}
