package mcpoauth_test

// Access requests over a migrated database: a member blocked by the
// verified-applications policy asks for the publisher, administrators
// approve or decline, with tenant isolation and the request caps.

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"

	"github.com/google/uuid"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/mcpoauth"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	mcpoauthdom "github.com/openctemio/openctem/api/pkg/domain/mcpoauth"
	notificationdom "github.com/openctemio/openctem/api/pkg/domain/notification"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// fakePolicyWriter applies approvals to the harness policies.
type fakePolicyWriter struct{ policies fakePolicies }

func (f fakePolicyWriter) AllowMCPClientHost(_ context.Context, tenantID, host string, _ auditapp.AuditContext) error {
	p := f.policies[tenantID]
	if !slices.Contains(p.ClientHosts, host) {
		p.ClientHosts = append(p.ClientHosts, host)
	}
	f.policies[tenantID] = p
	return nil
}

// recordingNotifier keeps who was notified.
type recordingNotifier struct {
	mu   sync.Mutex
	sent []notificationdom.NotificationParams
}

func (n *recordingNotifier) Notify(_ context.Context, p notificationdom.NotificationParams) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.sent = append(n.sent, p)
	return nil
}

func (n *recordingNotifier) to(user shared.ID) int {
	n.mu.Lock()
	defer n.mu.Unlock()
	c := 0
	for _, p := range n.sent {
		if p.AudienceID != nil && *p.AudienceID == user && p.NotificationType == notificationdom.TypeMCPAccessRequest {
			c++
		}
	}
	return c
}

// withAccessRequests is the authorization server with access requests on
// and no platform-trusted hosts, so the test client is blocked by default.
func (h *harness) withAccessRequests(n *recordingNotifier) *mcpoauth.Service {
	h.t.Helper()
	cfg := h.cfg
	cfg.TrustedClientHosts = nil
	repo := cfg.Repository.(*postgres.MCPOAuthRepository)
	cfg.AccessRequests = repo
	cfg.PolicyWriter = fakePolicyWriter{policies: h.policies}
	cfg.Notifier = n
	svc, err := mcpoauth.NewService(cfg)
	if err != nil {
		h.t.Fatal(err)
	}
	for _, tenant := range []string{h.tenant, h.other} {
		tid := tenant
		h.t.Cleanup(func() {
			_, _ = h.db.ExecContext(context.Background(), `DELETE FROM mcp_access_requests WHERE tenant_id = $1`, tid)
		})
	}
	return svc
}

// consent starts an authorization and opens its consent page as user.
func consent(t *testing.T, svc *mcpoauth.Service, user shared.ID, tenant string) (shared.ID, *mcpoauth.ConsentView) {
	t.Helper()
	ctx := context.Background()
	id, aerr := svc.StartAuthorization(ctx, authorizeQuery(nil))
	if aerr != nil {
		t.Fatal(aerr)
	}
	view, err := svc.ConsentRequest(ctx, id, user, shared.MustIDFromString(tenant))
	if err != nil {
		t.Fatal(err)
	}
	return id, view
}

func TestAccessRequestApproveFlow(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	n := &recordingNotifier{}
	svc := h.withAccessRequests(n)
	tenant := shared.MustIDFromString(h.tenant)
	owner := h.member(h.tenant, "owner")
	alice := h.member(h.tenant, "member", "findings:read")
	bob := h.member(h.tenant, "member", "findings:read")

	id, view := consent(t, svc, alice, h.tenant)
	if view.Blocked != mcpoauth.BlockedClientNotFound || !view.Requestable || view.CanAllow || view.AccessRequested {
		t.Fatalf("member's blocked view %+v", view)
	}
	ar, err := svc.RequestAccess(ctx, id, alice, tenant, mcpoauth.Actor{})
	if err != nil {
		t.Fatal(err)
	}
	if ar.ClientHost != "assistant.example" || ar.ClientName != "Desk Assistant" {
		t.Fatalf("request not derived from the authorization request: %+v", ar)
	}
	if n.to(owner) != 1 || n.to(alice) != 0 {
		t.Fatalf("admin notified %d times, requester %d", n.to(owner), n.to(alice))
	}

	// A second member asking for the same publisher joins the request.
	id2, view2 := consent(t, svc, bob, h.tenant)
	if !view2.AccessRequested {
		t.Fatal("pending request not shown on the consent page")
	}
	ar2, err := svc.RequestAccess(ctx, id2, bob, tenant, mcpoauth.Actor{})
	if err != nil || ar2.ID != ar.ID {
		t.Fatalf("repeat request %v %v, want the same row", ar2, err)
	}
	if n.to(owner) != 1 {
		t.Fatal("administrators notified again for a repeat")
	}

	list, err := svc.ListAccessRequests(ctx, tenant)
	if err != nil || len(list) != 1 || list[0].RequestCount != 2 || list[0].RequesterName == "" {
		t.Fatalf("pending list %+v %v", list, err)
	}

	// Another organization sees nothing and cannot decide it.
	other := shared.MustIDFromString(h.other)
	if l, _ := svc.ListAccessRequests(ctx, other); len(l) != 0 {
		t.Fatalf("other tenant lists %d requests", len(l))
	}
	outsider := h.member(h.other, "owner")
	if err := svc.ApproveAccessRequest(ctx, other, ar.ID, outsider, mcpoauth.Actor{}); !errors.Is(err, mcpoauthdom.ErrNotFound) {
		t.Fatalf("cross-tenant approve: %v", err)
	}
	if err := svc.DenyAccessRequest(ctx, other, ar.ID, outsider, mcpoauth.Actor{}); !errors.Is(err, mcpoauthdom.ErrNotFound) {
		t.Fatalf("cross-tenant deny: %v", err)
	}
	if slices.Contains(h.policies[h.other].ClientHosts, "assistant.example") {
		t.Fatal("host added to the other tenant's policy")
	}

	if err := svc.ApproveAccessRequest(ctx, tenant, ar.ID, owner, mcpoauth.Actor{}); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(h.policies[h.tenant].ClientHosts, "assistant.example") {
		t.Fatal("approval did not add the publisher host")
	}
	if n.to(alice) != 1 {
		t.Fatal("requester not told")
	}
	if l, _ := svc.ListAccessRequests(ctx, tenant); len(l) != 0 {
		t.Fatalf("approved request still listed: %+v", l)
	}
	if err := svc.ApproveAccessRequest(ctx, tenant, ar.ID, owner, mcpoauth.Actor{}); !errors.Is(err, mcpoauthdom.ErrNotFound) {
		t.Fatalf("second approval: %v", err)
	}
	_, view3 := consent(t, svc, alice, h.tenant)
	if view3.Blocked != "" || !view3.Verified {
		t.Fatalf("after approval %+v", view3)
	}
}

func TestAccessRequestDeny(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	n := &recordingNotifier{}
	svc := h.withAccessRequests(n)
	tenant := shared.MustIDFromString(h.tenant)
	owner := h.member(h.tenant, "owner")
	alice := h.member(h.tenant, "member", "findings:read")
	id, _ := consent(t, svc, alice, h.tenant)
	ar, err := svc.RequestAccess(ctx, id, alice, tenant, mcpoauth.Actor{})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.DenyAccessRequest(ctx, tenant, ar.ID, owner, mcpoauth.Actor{}); err != nil {
		t.Fatal(err)
	}
	if len(h.policies[h.tenant].ClientHosts) != 0 {
		t.Fatal("decline changed the policy")
	}
	if n.to(alice) != 1 {
		t.Fatal("requester not told of the decline")
	}
	// After a decline the member may ask again (a new request).
	id, _ = consent(t, svc, alice, h.tenant)
	ar2, err := svc.RequestAccess(ctx, id, alice, tenant, mcpoauth.Actor{})
	if err != nil || ar2.ID == ar.ID {
		t.Fatalf("new request after decline: %v %v", ar2, err)
	}
}

func TestAccessRequestOnlyWhenAnApprovalHelps(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	svc := h.withAccessRequests(&recordingNotifier{})
	tenant := shared.MustIDFromString(h.tenant)
	alice := h.member(h.tenant, "member", "findings:read")
	mallory := h.member(h.tenant, "member", "findings:read")

	// Someone else's authorization request.
	id, _ := consent(t, svc, alice, h.tenant)
	if _, err := svc.RequestAccess(ctx, id, mallory, tenant, mcpoauth.Actor{}); !errors.Is(err, mcpoauth.ErrConsentUnavailable) {
		t.Fatalf("request on another member's consent: %v", err)
	}
	// A member of another organization.
	stranger := h.member(h.other, "member", "findings:read")
	sid, _ := consent(t, svc, stranger, h.tenant)
	if _, err := svc.RequestAccess(ctx, sid, stranger, tenant, mcpoauth.Actor{}); !errors.Is(err, mcpoauth.ErrConsentUnavailable) {
		t.Fatalf("request by a non-member: %v", err)
	}
	// MCP off: an approval would not help.
	h.policies[h.tenant] = tenantdom.MCPSettings{Disabled: true}
	id, view := consent(t, svc, alice, h.tenant)
	if view.Requestable {
		t.Fatal("requestable while MCP is off")
	}
	if _, err := svc.RequestAccess(ctx, id, alice, tenant, mcpoauth.Actor{}); !errors.Is(err, mcpoauth.ErrAccessRequestNotPossible) {
		t.Fatalf("request while off: %v", err)
	}
	// Already allowed.
	h.policies[h.tenant] = tenantdom.MCPSettings{AnyClient: true}
	id, _ = consent(t, svc, alice, h.tenant)
	if _, err := svc.RequestAccess(ctx, id, alice, tenant, mcpoauth.Actor{}); !errors.Is(err, mcpoauth.ErrAccessRequestNotPossible) {
		t.Fatalf("request for an allowed client: %v", err)
	}
}

func TestAccessRequestCaps(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	svc := h.withAccessRequests(&recordingNotifier{})
	tenant := shared.MustIDFromString(h.tenant)
	alice := h.member(h.tenant, "member", "findings:read")
	for i := 0; i < mcpoauth.MaxAccessRequestsPerMemberPerDay; i++ {
		h.exec(`INSERT INTO mcp_access_requests (tenant_id, client_host, client_name, client_id, requested_by, status)
			VALUES ($1, $2, 'x', 'https://x.example/c', $3, 'denied')`, h.tenant, uuid.NewString()[:8]+".example", alice.String())
	}
	id, _ := consent(t, svc, alice, h.tenant)
	if _, err := svc.RequestAccess(ctx, id, alice, tenant, mcpoauth.Actor{}); !errors.Is(err, mcpoauth.ErrAccessRequestLimit) {
		t.Fatalf("member cap: %v", err)
	}
	bob := h.member(h.tenant, "member", "findings:read")
	for i := 0; i < mcpoauth.MaxPendingAccessRequests; i++ {
		h.exec(`INSERT INTO mcp_access_requests (tenant_id, client_host, client_name, client_id, status)
			VALUES ($1, $2, 'x', 'https://x.example/c', 'pending')`, h.tenant, uuid.NewString()[:8]+".example")
	}
	id, _ = consent(t, svc, bob, h.tenant)
	if _, err := svc.RequestAccess(ctx, id, bob, tenant, mcpoauth.Actor{}); !errors.Is(err, mcpoauth.ErrAccessRequestLimit) {
		t.Fatalf("organization cap: %v", err)
	}
}

func TestAllowPublisherFromConsent(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	n := &recordingNotifier{}
	svc := h.withAccessRequests(n)
	tenant := shared.MustIDFromString(h.tenant)
	owner := h.member(h.tenant, "owner")
	alice := h.member(h.tenant, "member", "findings:read")
	settingsAdmin := h.member(h.tenant, "member", "findings:read", "settings:write")

	id, _ := consent(t, svc, alice, h.tenant)
	ar, err := svc.RequestAccess(ctx, id, alice, tenant, mcpoauth.Actor{})
	if err != nil {
		t.Fatal(err)
	}
	_, view := consent(t, svc, settingsAdmin, h.tenant)
	if !view.CanAllow {
		t.Fatal("settings:write holder not offered to allow")
	}
	id, view = consent(t, svc, owner, h.tenant)
	if !view.CanAllow || !view.AccessRequested {
		t.Fatalf("owner view %+v", view)
	}
	if err := svc.AllowPublisherFromConsent(ctx, id, owner, tenant, mcpoauth.Actor{}); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(h.policies[h.tenant].ClientHosts, "assistant.example") {
		t.Fatal("publisher not added")
	}
	if got, err := svc.ListAccessRequests(ctx, tenant); err != nil || len(got) != 0 {
		t.Fatalf("waiting request not closed: %+v %v", got, err)
	}
	var status string
	if err := h.db.QueryRowContext(ctx, `SELECT status FROM mcp_access_requests WHERE id = $1 AND tenant_id = $2`, ar.ID.String(), h.tenant).Scan(&status); err != nil || status != "approved" {
		t.Fatalf("request status %q %v", status, err)
	}
	if n.to(alice) != 1 {
		t.Fatal("requester not told")
	}
	// Now allowed: the owner can approve the consent itself.
	if _, err := svc.Approve(ctx, id, owner, tenant, mcpoauth.Actor{}); err != nil {
		t.Fatalf("approve after allowing the publisher: %v", err)
	}
}
