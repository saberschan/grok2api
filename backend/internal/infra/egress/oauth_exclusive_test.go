package egress

import (
	"context"
	"testing"
	"time"

	domain "github.com/chenyme/grok2api/backend/internal/domain/egress"
	"github.com/chenyme/grok2api/backend/internal/infra/security"
)

func TestOAuthScopeIsNotAnOrdinaryBuildCandidate(t *testing.T) {
	cipher, err := security.NewCipher("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	if err != nil {
		t.Fatal(err)
	}
	ordinaryProxy, err := cipher.Encrypt("http://ordinary.example:8080")
	if err != nil {
		t.Fatal(err)
	}
	oauthProxy, err := cipher.Encrypt("http://oauth-only.example:8080")
	if err != nil {
		t.Fatal(err)
	}
	ordinary := domain.Node{ID: 11, Name: "ordinary", Scope: domain.ScopeBuild, Enabled: true, Health: 1, EncryptedProxyURL: ordinaryProxy}
	oauthOnly := domain.Node{ID: 22, Name: "oauth-only", Scope: domain.ScopeBuildOAuth, Enabled: true, Health: 1, EncryptedProxyURL: oauthProxy}
	manager := NewManager(egressRepositoryTestStub{nodes: []domain.Node{ordinary, oauthOnly}}, cipher)
	manager.newBuildClient = func(string, time.Duration) (requestClient, error) { return &scriptedRequestClient{}, nil }

	lease, configured, err := manager.AcquireIfConfigured(context.Background(), domain.ScopeBuild, "ordinary-account")
	if err != nil {
		t.Fatal(err)
	}
	if !configured || lease == nil {
		t.Fatalf("ordinary Build egress lease = %#v configured=%v", lease, configured)
	}
	if lease.NodeID != ordinary.ID {
		lease.Release()
		t.Fatalf("ordinary Build selected OAuth-scope node %d, want node %d", lease.NodeID, ordinary.ID)
	}
	lease.Release()

	if _, _, err := manager.AcquireIfConfigured(WithEgressNode(context.Background(), oauthOnly.ID), domain.ScopeBuild, "bound-ordinary-account"); err == nil {
		t.Fatal("ordinary Build binding to OAuth-scope node was accepted")
	}
}
