package mcpoauth_test

// The organization MCP policy (RFC-062 §8) over a migrated database: it is
// applied at consent, at code redemption, at refresh and on every request.

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/mcpoauth"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
)

func TestPolicyDisabledStopsEverything(t *testing.T) {
	h := newHarness(t)
	user := h.member(h.tenant, "owner")
	tok, oerr := h.exchange(h.approve(user, h.tenant, authorizeQuery(nil)), verifier, nil)
	if oerr != nil {
		t.Fatal(oerr)
	}
	h.policies[h.tenant] = tenantdom.MCPSettings{Disabled: true}
	if _, err := h.principal(tok.AccessToken); err == nil {
		t.Fatal("token works while MCP is off for the organization")
	}
	if _, oerr := h.refresh(tok.RefreshToken, nil); oerr == nil {
		t.Fatal("refresh works while MCP is off")
	}
	ctx := context.Background()
	id, _ := h.svc.StartAuthorization(ctx, authorizeQuery(nil))
	view, err := h.svc.ConsentRequest(ctx, id, user, shared.MustIDFromString(h.tenant))
	if err != nil || view.Blocked != mcpoauth.BlockedMCPDisabled {
		t.Fatalf("consent view %+v %v, want blocked", view, err)
	}
	if _, err := h.svc.Approve(ctx, id, user, shared.MustIDFromString(h.tenant), mcpoauth.Actor{}); !errors.Is(err, mcpoauth.ErrPolicy) {
		t.Fatalf("approve while off: %v", err)
	}
}

func TestPolicyVerifiedClientsOnly(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	user := h.member(h.tenant, "owner")
	// Not on the platform list here: the harness lists assistant.example,
	// so build a service without it.
	strict := h.withTrustedHosts(nil)
	id, aerr := strict.StartAuthorization(ctx, authorizeQuery(nil))
	if aerr != nil {
		t.Fatal(aerr)
	}
	view, err := strict.ConsentRequest(ctx, id, user, shared.MustIDFromString(h.tenant))
	if err != nil || view.Verified || view.Blocked != mcpoauth.BlockedClientNotFound {
		t.Fatalf("unverified client view %+v %v", view, err)
	}
	if _, err := strict.Approve(ctx, id, user, shared.MustIDFromString(h.tenant), mcpoauth.Actor{}); !errors.Is(err, mcpoauth.ErrPolicy) {
		t.Fatalf("unverified client approved: %v", err)
	}
	// The organization lists the host: verified and allowed.
	h.policies[h.tenant] = tenantdom.MCPSettings{ClientHosts: []string{"assistant.example"}}
	id, _ = strict.StartAuthorization(ctx, authorizeQuery(nil))
	view, err = strict.ConsentRequest(ctx, id, user, shared.MustIDFromString(h.tenant))
	if err != nil || !view.Verified || view.Blocked != "" {
		t.Fatalf("listed host view %+v %v", view, err)
	}
	// Any client: allowed but still unverified.
	h.policies[h.tenant] = tenantdom.MCPSettings{AnyClient: true}
	id, _ = strict.StartAuthorization(ctx, authorizeQuery(nil))
	view, err = strict.ConsentRequest(ctx, id, user, shared.MustIDFromString(h.tenant))
	if err != nil || view.Verified || view.Blocked != "" {
		t.Fatalf("any-client view %+v %v", view, err)
	}
	if _, err := strict.Approve(ctx, id, user, shared.MustIDFromString(h.tenant), mcpoauth.Actor{}); err != nil {
		t.Fatalf("any-client approve: %v", err)
	}
}

func TestPolicyScopesCapGrantsAndTokens(t *testing.T) {
	h := newHarness(t)
	user := h.member(h.tenant, "owner")
	h.policies[h.tenant] = tenantdom.MCPSettings{Scopes: []string{"mcp:findings.read"}}
	tok, oerr := h.exchange(h.approve(user, h.tenant, authorizeQuery(nil)), verifier, nil)
	if oerr != nil {
		t.Fatal(oerr)
	}
	if tok.Scope != "mcp:findings.read" {
		t.Fatalf("granted %q beyond the policy", tok.Scope)
	}
	// A later, narrower policy narrows existing tokens at once.
	h.policies[h.tenant] = tenantdom.MCPSettings{Scopes: []string{"mcp:assets.read"}}
	p, err := h.principal(tok.AccessToken)
	if err != nil || len(p.Permissions) != 0 {
		t.Fatalf("permissions under the narrower policy: %v %v", p, err)
	}
}

func TestPolicyRefreshLifetime(t *testing.T) {
	h := newHarness(t)
	user := h.member(h.tenant, "owner")
	tok, oerr := h.exchange(h.approve(user, h.tenant, authorizeQuery(nil)), verifier, nil)
	if oerr != nil {
		t.Fatal(oerr)
	}
	h.policies[h.tenant] = tenantdom.MCPSettings{RefreshDays: 7}
	h.exec(`UPDATE mcp_oauth_grants SET created_at = now() - interval '8 days' WHERE tenant_id = $1`, h.tenant)
	if _, oerr := h.refresh(tok.RefreshToken, nil); oerr == nil {
		t.Fatal("refresh beyond the organization's connection lifetime")
	}
	if _, err := h.principal(tok.AccessToken); err == nil {
		t.Fatal("grant survived the lifetime check")
	}
}
