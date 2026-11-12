package mcpoauth_test

// Client registration (RFC-062 §5) over a migrated database: organization
// clients, dynamic registration and the purge.

import (
	"context"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/mcpoauth"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
)

func (h *harness) withDCR(on bool) *mcpoauth.Service {
	h.t.Helper()
	cfg := h.cfg
	cfg.DynamicRegistration = on
	svc, err := mcpoauth.NewService(cfg)
	if err != nil {
		h.t.Fatal(err)
	}
	return svc
}

func TestOrganizationClientIsOnlyItsOrganizations(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	owner := h.member(h.tenant, "owner")
	tenant := shared.MustIDFromString(h.tenant)
	c, err := h.svc.CreateOrganizationClient(ctx, tenant, owner, "Team Assistant", []string{"http://127.0.0.1:7000/cb"}, mcpoauth.Actor{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = h.db.Exec(`DELETE FROM mcp_oauth_clients WHERE id = $1`, c.ID.String()) })
	q := authorizeQuery(map[string]string{"client_id": c.ClientID, "redirect_uri": "http://127.0.0.1:41000/cb"})

	// Verified in its organization, under the default (verified-only) policy.
	id, aerr := h.svc.StartAuthorization(ctx, q)
	if aerr != nil {
		t.Fatal(aerr)
	}
	view, err := h.svc.ConsentRequest(ctx, id, owner, tenant)
	if err != nil || !view.Verified || view.Blocked != "" {
		t.Fatalf("own organization view %+v %v", view, err)
	}
	to, err := h.svc.Approve(ctx, id, owner, tenant, mcpoauth.Actor{})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(to)
	tok, oerr := h.svc.Token(ctx, url.Values{
		"grant_type": {"authorization_code"}, "code": {u.Query().Get("code")}, "code_verifier": {verifier},
		"client_id": {c.ClientID}, "redirect_uri": {"http://127.0.0.1:41000/cb"}, "resource": {resource},
	}, "", mcpoauth.Actor{})
	if oerr != nil {
		t.Fatal(oerr)
	}

	// Never usable in another organization, even with any client allowed.
	outsider := h.member(h.other, "owner")
	h.policies[h.other] = tenantdom.MCPSettings{AnyClient: true}
	id2, _ := h.svc.StartAuthorization(ctx, q)
	view, err = h.svc.ConsentRequest(ctx, id2, outsider, shared.MustIDFromString(h.other))
	if err != nil || view.Blocked != mcpoauth.BlockedClientNotFound {
		t.Fatalf("foreign organization view %+v %v", view, err)
	}

	// Listed for its organization only.
	if list, _ := h.svc.ListOrganizationClients(ctx, tenant); len(list) != 1 {
		t.Fatalf("organization clients: %d", len(list))
	}
	if list, _ := h.svc.ListOrganizationClients(ctx, shared.MustIDFromString(h.other)); len(list) != 0 {
		t.Fatalf("other organization lists %d clients", len(list))
	}
	// Deleting it from another organization does nothing; from its own ends
	// its connections.
	if err := h.svc.DeleteOrganizationClient(ctx, shared.MustIDFromString(h.other), outsider, c.ID, mcpoauth.Actor{}); err == nil {
		t.Fatal("deleted from another organization")
	}
	if err := h.svc.DeleteOrganizationClient(ctx, tenant, owner, c.ID, mcpoauth.Actor{}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.principal(tok.AccessToken); err == nil {
		t.Fatal("token of a deleted client works")
	}
}

func TestOrganizationClientValidation(t *testing.T) {
	h := newHarness(t)
	owner := h.member(h.tenant, "owner")
	for name, uris := range map[string][]string{
		"none":          nil,
		"custom scheme": {"myapp://cb"},
		"http remote":   {"http://app.example/cb"},
		"fragment":      {"https://app.example/cb#x"},
	} {
		_, err := h.svc.CreateOrganizationClient(context.Background(), shared.MustIDFromString(h.tenant), owner, "x", uris, mcpoauth.Actor{})
		if !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := h.svc.CreateOrganizationClient(context.Background(), shared.MustIDFromString(h.tenant), owner, "  ", []string{"https://a.example/cb"}, mcpoauth.Actor{}); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("blank name: %v", err)
	}
}

func TestDynamicRegistration(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if _, oerr := h.svc.RegisterDynamicClient(ctx, mcpoauth.DynamicRegistration{RedirectURIs: []string{"http://127.0.0.1/cb"}}); oerr == nil {
		t.Fatal("registered while dynamic registration is off")
	}
	dcr := h.withDCR(true)
	for name, bad := range map[string]mcpoauth.DynamicRegistration{
		"secret client": {RedirectURIs: []string{"https://a.example/cb"}, TokenEndpointAuthMethod: "client_secret_basic"},
		"client creds":  {RedirectURIs: []string{"https://a.example/cb"}, GrantTypes: []string{"client_credentials"}},
		"implicit":      {RedirectURIs: []string{"https://a.example/cb"}, ResponseTypes: []string{"token"}},
		"no redirect":   {},
		"remote http":   {RedirectURIs: []string{"http://evil.example/cb"}},
		"app type":      {RedirectURIs: []string{"https://a.example/cb"}, ApplicationType: "service"},
	} {
		if _, oerr := dcr.RegisterDynamicClient(ctx, bad); oerr == nil {
			t.Errorf("%s registered", name)
		}
	}
	reg, oerr := dcr.RegisterDynamicClient(ctx, mcpoauth.DynamicRegistration{
		RedirectURIs: []string{"http://127.0.0.1:5000/cb"}, ClientName: "CLI Agent", ApplicationType: "native",
	})
	if oerr != nil {
		t.Fatal(oerr)
	}
	t.Cleanup(func() { _, _ = h.db.Exec(`DELETE FROM mcp_oauth_clients WHERE client_id = $1`, reg.ClientID) })
	if reg.TokenEndpointAuthMethod != "none" || reg.ClientName != "CLI Agent" {
		t.Fatalf("registration %+v", reg)
	}
	owner := h.member(h.tenant, "owner")
	tenant := shared.MustIDFromString(h.tenant)
	q := authorizeQuery(map[string]string{"client_id": reg.ClientID, "redirect_uri": "http://127.0.0.1:5001/cb"})
	id, aerr := dcr.StartAuthorization(ctx, q)
	if aerr != nil {
		t.Fatal(aerr)
	}
	// Unverified: refused by the default policy, allowed (still unverified)
	// when the organization accepts any application.
	view, err := dcr.ConsentRequest(ctx, id, owner, tenant)
	if err != nil || view.Verified || view.Blocked != mcpoauth.BlockedClientNotFound {
		t.Fatalf("dynamic client view %+v %v", view, err)
	}
	h.policies[h.tenant] = tenantdom.MCPSettings{AnyClient: true}
	view, err = dcr.ConsentRequest(ctx, id, owner, tenant)
	if err != nil || view.Verified || view.Blocked != "" {
		t.Fatalf("dynamic client view with any client %+v %v", view, err)
	}
}

func TestPurgeRemovesEndedState(t *testing.T) {
	h := newHarness(t)
	user := h.member(h.tenant, "owner")
	tok, oerr := h.exchange(h.approve(user, h.tenant, authorizeQuery(nil)), verifier, nil)
	if oerr != nil {
		t.Fatal(oerr)
	}
	// Push everything of this tenant into the past.
	h.exec(`UPDATE mcp_oauth_grants SET revoked_at = now() - interval '40 days' WHERE tenant_id = $1`, h.tenant)
	h.exec(`UPDATE mcp_oauth_requests SET expires_at = now() - interval '2 days' WHERE tenant_id = $1`, h.tenant)
	repo := postgres.NewMCPOAuthRepository(&postgres.DB{DB: h.db})
	n, err := repo.PurgeForPlatform(context.Background(), time.Now())
	if err != nil || n == 0 {
		t.Fatalf("purge: %d %v", n, err)
	}
	var left int
	_ = h.db.QueryRow(`SELECT count(*) FROM mcp_oauth_grants WHERE tenant_id = $1`, h.tenant).Scan(&left)
	if left != 0 {
		t.Fatalf("%d grants left", left)
	}
	if _, err := h.principal(tok.AccessToken); err == nil {
		t.Fatal("token of a purged grant works")
	}
}
