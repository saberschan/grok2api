package relational

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/chenyme/grok2api/backend/internal/domain/egress"
	"github.com/chenyme/grok2api/backend/internal/repository"
)

func TestOAuthScopeSelectionUsesOnlyDedicatedNodeClassification(t *testing.T) {
	ctx := context.Background()
	database := openTestDatabase(t)
	nodes := NewEgressRepository(database)
	cipher := egressOperationsCipher(t)
	ordinary := createHealthyEgressNode(t, ctx, nodes, cipher, "ordinary-build", 0)
	oauthOne := createHealthyEgressNodeForScope(t, ctx, nodes, cipher, "oauth-build-one", egress.ScopeBuildOAuth, 0)
	oauthTwo := createHealthyEgressNodeForScope(t, ctx, nodes, cipher, "oauth-build-two", egress.ScopeBuildOAuth, 0)
	oauthThree := createHealthyEgressNodeForScope(t, ctx, nodes, cipher, "oauth-build-three", egress.ScopeBuildOAuth, 0)
	account := createEgressOperationsAccount(t, ctx, NewAccountRepository(database), "oauth-scope-selection")

	selected, err := nodes.SelectOAuthEgressNode(ctx, account.ID)
	if err != nil {
		t.Fatal(err)
	}
	if selected != oauthOne.ID && selected != oauthTwo.ID && selected != oauthThree.ID {
		t.Fatalf("OAuth selected node %d outside OAuth scope", selected)
	}
	again, err := nodes.SelectOAuthEgressNode(ctx, account.ID)
	if err != nil {
		t.Fatal(err)
	}
	if again != selected {
		t.Fatalf("OAuth scope selection changed from %d to %d", selected, again)
	}

	// Temporary health/cooldown feedback must not move the persistent choice.
	degraded, err := nodes.GetEgressNode(ctx, selected)
	if err != nil {
		t.Fatal(err)
	}
	cooldown := time.Now().UTC().Add(time.Minute)
	degraded.Health, degraded.FailureCount, degraded.CooldownUntil, degraded.LastError = 0.2, 1, &cooldown, egress.LastErrorTransport
	if _, err := nodes.UpdateEgressNode(ctx, degraded); err != nil {
		t.Fatal(err)
	}
	afterFailure, err := nodes.SelectOAuthEgressNode(ctx, account.ID)
	if err != nil {
		t.Fatal(err)
	}
	if afterFailure != selected {
		t.Fatalf("transient failure rotated OAuth scope node from %d to %d", selected, afterFailure)
	}

	// Reclassifying/disabling the selected node is an explicit change to the
	// OAuth pool and therefore permits reassignment to another OAuth-scope node.
	degraded.Scope = egress.ScopeBuild
	degraded.Enabled = true
	if _, err := nodes.UpdateEgressNode(ctx, degraded); err != nil {
		t.Fatal(err)
	}
	afterReclassification, err := nodes.SelectOAuthEgressNode(ctx, account.ID)
	if err != nil {
		t.Fatal(err)
	}
	if afterReclassification != oauthOne.ID && afterReclassification != oauthTwo.ID && afterReclassification != oauthThree.ID || afterReclassification == selected {
		t.Fatalf("reclassified OAuth node was not replaced: old=%d new=%d ordinary=%d", selected, afterReclassification, ordinary.ID)
	}

	if err := nodes.DeleteEgressNode(ctx, afterReclassification); err != nil {
		t.Fatal(err)
	}
	last, err := nodes.SelectOAuthEgressNode(ctx, account.ID)
	if err != nil {
		t.Fatal(err)
	}
	if last == afterReclassification || last == ordinary.ID {
		t.Fatalf("deleted or ordinary Build node selected: %d", last)
	}
}

func TestOAuthScopeSelectionFailsWhenNoDedicatedNodeExists(t *testing.T) {
	ctx := context.Background()
	database := openTestDatabase(t)
	nodes := NewEgressRepository(database)
	cipher := egressOperationsCipher(t)
	ordinary := createHealthyEgressNode(t, ctx, nodes, cipher, "ordinary-only", 0)
	account := createEgressOperationsAccount(t, ctx, NewAccountRepository(database), "oauth-scope-empty")
	if _, err := nodes.SelectOAuthEgressNode(ctx, account.ID); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("selection error = %v, want ErrNotFound", err)
	}
	if _, err := nodes.GetEgressNode(ctx, ordinary.ID); err != nil {
		t.Fatal(err)
	}
}
