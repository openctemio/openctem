package mcpoauth_test

// Allowing a connection to read all organization data (RFC-062 MA25): the
// option is offered only to a full-data role, needs a fresh step-up, is
// audited, shortens the grant's lifetimes, is re-checked on every request,
// and can be ended or narrowed.
//
// DB-gated: DATABASE_URL must point at a migrated *_test database.

import (
	"context"
	"errors"
	"net/url"
	"testing"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/mcpoauth"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	mcpoauthdom "github.com/openctemio/openctem/api/pkg/domain/mcpoauth"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// fullRoles says who holds a full-data role (a custom role such as a global
// reader; owners and administrators are covered by HeldPermissions).
type fullRoles map[string]bool

func (f fullRoles) HasFullDataRole(_ context.Context, tenantID, userID shared.ID) (bool, error) {
	return f[tenantID.String()+"/"+userID.String()], nil
}

// set grants or removes the role of user in tenant.
func (f fullRoles) set(tenant string, user shared.ID, v bool) { f[tenant+"/"+user.String()] = v }

// stepGate is the step-up check: err is what a stale session gets.
type stepGate struct{ err error }

func (g *stepGate) RequireRecentAuth(context.Context, string) error { return g.err }

// auditRec records the audit events of the service.
type auditRec struct{ events []auditapp.AuditEvent }

func (a *auditRec) LogEvent(_ context.Context, _ auditapp.AuditContext, e auditapp.AuditEvent) error {
	a.events = append(a.events, e)
	return nil
}

func (a *auditRec) find(action auditdom.Action) *auditapp.AuditEvent {
	for i := range a.events {
		if a.events[i].Action == action {
			return &a.events[i]
		}
	}
	return nil
}

type fullDataEnv struct {
	*harness
	roles fullRoles
	gate  *stepGate
	audit *auditRec
}

func newFullDataEnv(t *testing.T) *fullDataEnv {
	t.Helper()
	h := newHarness(t)
	e := &fullDataEnv{harness: h, roles: fullRoles{}, gate: &stepGate{}, audit: &auditRec{}}
	cfg := h.cfg
	cfg.FullData, cfg.Audit = e.roles, e.audit
	svc, err := mcpoauth.NewService(cfg)
	if err != nil {
		t.Fatal(err)
	}
	svc.SetStepUpGate(e.gate)
	h.svc = svc
	return e
}

// approveFull runs authorize + consent with the full-data choice.
func (e *fullDataEnv) approveFull(user shared.ID, tenant string) (string, error) {
	e.t.Helper()
	id, aerr := e.svc.StartAuthorization(context.Background(), authorizeQuery(nil))
	if aerr != nil {
		e.t.Fatalf("authorize: %v", aerr)
	}
	to, err := e.svc.ApproveAccess(context.Background(), id, user, shared.MustIDFromString(tenant), true, mcpoauth.Actor{})
	if err != nil {
		return "", err
	}
	u, _ := url.Parse(to)
	return u.Query().Get("code"), nil
}

func TestConsentOffersFullDataOnlyToFullDataRoles(t *testing.T) {
	e := newFullDataEnv(t)
	tenant := shared.MustIDFromString(e.tenant)
	owner := e.member(e.tenant, "owner")
	reader := e.member(e.tenant, "member", "findings:read")
	e.roles.set(e.tenant, reader, true)
	plain := e.member(e.tenant, "member", "findings:read")

	for name, tc := range map[string]struct {
		user shared.ID
		want bool
	}{"owner": {owner, true}, "custom full-data role": {reader, true}, "member": {plain, false}} {
		id, aerr := e.svc.StartAuthorization(context.Background(), authorizeQuery(nil))
		if aerr != nil {
			t.Fatal(aerr)
		}
		view, err := e.svc.ConsentRequest(context.Background(), id, tc.user, tenant)
		if err != nil {
			t.Fatal(name, err)
		}
		if view.FullDataAvailable != tc.want {
			t.Errorf("%s: full data offered = %v, want %v", name, view.FullDataAvailable, tc.want)
		}
	}

	// A member who forces the option is refused and nothing is issued.
	id, _ := e.svc.StartAuthorization(context.Background(), authorizeQuery(nil))
	if _, err := e.svc.ApproveAccess(context.Background(), id, plain, tenant, true, mcpoauth.Actor{}); !errors.Is(err, mcpoauth.ErrFullDataNotAllowed) {
		t.Fatalf("a member without a full-data role approved full data: %v", err)
	}
	if e.audit.find(auditdom.ActionMCPFullDataAllowed) != nil {
		t.Fatal("a refused full-data approval was audited as allowed")
	}
	// The same pending request can still be approved the ordinary way.
	if _, err := e.svc.ApproveAccess(context.Background(), id, plain, tenant, false, mcpoauth.Actor{}); err != nil {
		t.Fatalf("scoped approval after the refusal: %v", err)
	}
}

func TestFullDataNeedsFreshStepUp(t *testing.T) {
	e := newFullDataEnv(t)
	owner := e.member(e.tenant, "owner")

	stale := errors.New("step-up required")
	e.gate.err = stale
	if _, err := e.approveFull(owner, e.tenant); !errors.Is(err, stale) {
		t.Fatalf("a stale session approved full data: %v", err)
	}
	if n := e.count(`SELECT count(*) FROM mcp_oauth_requests WHERE status = 'approved' AND user_id = $1`, owner.String()); n != 0 {
		t.Fatalf("%d requests approved after a refused step-up", n)
	}

	// A scoped approval needs no extra step-up here (the route still asks).
	if _, err := e.svc.ApproveAccess(context.Background(), mustStart(t, e.harness), owner, shared.MustIDFromString(e.tenant), false, mcpoauth.Actor{}); err != nil {
		t.Fatalf("scoped approval: %v", err)
	}

	// No gate wired: fail closed.
	e.svc.SetStepUpGate(nil)
	if _, err := e.approveFull(owner, e.tenant); !errors.Is(err, mcpoauth.ErrFullDataStepUp) {
		t.Fatalf("full data approved with no step-up check wired: %v", err)
	}

	e.svc.SetStepUpGate(&stepGate{})
	if _, err := e.approveFull(owner, e.tenant); err != nil {
		t.Fatalf("fresh step-up: %v", err)
	}
}

func mustStart(t *testing.T, h *harness) shared.ID {
	t.Helper()
	id, aerr := h.svc.StartAuthorization(context.Background(), authorizeQuery(nil))
	if aerr != nil {
		t.Fatal(aerr)
	}
	return id
}

func (e *fullDataEnv) count(q string, args ...any) int {
	e.t.Helper()
	var n int
	if err := e.db.QueryRow(q, args...).Scan(&n); err != nil {
		e.t.Fatal(err)
	}
	return n
}

func TestFullDataGrantLifecycle(t *testing.T) {
	e := newFullDataEnv(t)
	tenant := shared.MustIDFromString(e.tenant)
	reader := e.member(e.tenant, "member", "findings:read")
	e.roles.set(e.tenant, reader, true)

	code, err := e.approveFull(reader, e.tenant)
	if err != nil {
		t.Fatal(err)
	}
	// Audited at approval: the person, the client host and full_data.
	ev := e.audit.find(auditdom.ActionMCPFullDataAllowed)
	if ev == nil || ev.Metadata["client_host"] != "assistant.example" || ev.Metadata["full_data"] != true {
		t.Fatalf("full-data approval audit: %+v", ev)
	}
	if a := e.audit.find(auditdom.ActionMCPClientAuthorized); a == nil || a.Metadata["full_data"] != true {
		t.Fatalf("authorized event lacks full_data: %+v", a)
	}

	tok, oerr := e.exchange(code, verifier, nil)
	if oerr != nil {
		t.Fatal(oerr)
	}
	// Shorter windows than a scoped grant (10 min access token).
	if tok.ExpiresIn != int(mcpoauthdom.FullDataAccessTokenTTL.Seconds()) {
		t.Fatalf("access token life %ds", tok.ExpiresIn)
	}
	var grantExp, refreshExp time.Time
	var stored bool
	if err := e.db.QueryRow(`SELECT g.full_data, g.expires_at, (SELECT max(expires_at) FROM mcp_oauth_tokens WHERE grant_id = g.id AND kind = 'refresh')
		FROM mcp_oauth_grants g WHERE g.user_id = $1`, reader.String()).Scan(&stored, &grantExp, &refreshExp); err != nil || !stored {
		t.Fatalf("grant not stored as full data: %v %v", stored, err)
	}
	if d := time.Until(grantExp); d > mcpoauthdom.FullDataGrantMaxTTL || d < mcpoauthdom.FullDataGrantMaxTTL-time.Minute {
		t.Fatalf("grant ends in %s", d)
	}
	if d := time.Until(refreshExp); d > mcpoauthdom.FullDataRefreshIdleTTL || d < mcpoauthdom.FullDataRefreshIdleTTL-time.Minute {
		t.Fatalf("refresh token valid for %s", d)
	}
	if ti := e.audit.find(auditdom.ActionMCPTokenIssued); ti == nil || ti.Metadata["full_data"] != true {
		t.Fatalf("token issue audit lacks full_data: %+v", ti)
	}

	p, err := e.principal(tok.AccessToken)
	if err != nil || !p.FullData {
		t.Fatalf("principal %+v %v", p, err)
	}
	// Both lists show the badge to the right people.
	mine, _ := e.svc.ListConnections(context.Background(), tenant, &reader)
	if len(mine) != 1 || !mine[0].FullData {
		t.Fatalf("connection list %+v", mine)
	}

	// The role is removed: the very next request is scoped; the token works.
	e.roles.set(e.tenant, reader, false)
	p, err = e.principal(tok.AccessToken)
	if err != nil || p.FullData {
		t.Fatalf("after role loss: %+v %v", p, err)
	}
	// Getting the role back re-enables it (the grant itself did not change).
	e.roles.set(e.tenant, reader, true)
	if p, _ = e.principal(tok.AccessToken); !p.FullData {
		t.Fatal("regained role does not restore the grant")
	}

	// Losing the role then refreshing downgrades the grant for good.
	e.roles.set(e.tenant, reader, false)
	next, oerr := e.refresh(tok.RefreshToken, nil)
	if oerr != nil {
		t.Fatal(oerr)
	}
	if next.ExpiresIn != int(mcpoauthdom.AccessTokenTTL.Seconds()) {
		t.Fatalf("downgraded grant's token life %ds", next.ExpiresIn)
	}
	e.roles.set(e.tenant, reader, true)
	if p, _ = e.principal(next.AccessToken); p.FullData {
		t.Fatal("a grant downgraded at refresh became full data again")
	}
	if rm := e.audit.find(auditdom.ActionMCPFullDataRemoved); rm == nil || rm.Metadata["reason"] != "role_lost" {
		t.Fatalf("downgrade audit: %+v", rm)
	}
}

func TestFullDataGrantCanBeNarrowedAndRevoked(t *testing.T) {
	e := newFullDataEnv(t)
	ctx := context.Background()
	tenant := shared.MustIDFromString(e.tenant)
	owner := e.member(e.tenant, "owner")
	admin := e.member(e.tenant, "admin")
	other := e.member(e.tenant, "owner")

	code, _ := e.approveFull(owner, e.tenant)
	tok, oerr := e.exchange(code, verifier, nil)
	if oerr != nil {
		t.Fatal(oerr)
	}
	list, _ := e.svc.ListConnections(ctx, tenant, &owner)
	grant := shared.MustIDFromString(list[0].ID)

	// Someone else's grant, and another organization's, are not found.
	if err := e.svc.ScopeConnection(ctx, tenant, grant, other, false, mcpoauth.Actor{}); !errors.Is(err, mcpoauthdom.ErrNotFound) {
		t.Fatalf("another person narrowed the grant: %v", err)
	}
	if err := e.svc.ScopeConnection(ctx, shared.MustIDFromString(e.other), grant, admin, true, mcpoauth.Actor{}); !errors.Is(err, mcpoauthdom.ErrNotFound) {
		t.Fatalf("cross-organization narrowing: %v", err)
	}
	if p, _ := e.principal(tok.AccessToken); !p.FullData {
		t.Fatal("refused narrowing changed the grant")
	}

	// An organization administrator narrows it; the token keeps working.
	if err := e.svc.ScopeConnection(ctx, tenant, grant, admin, true, mcpoauth.Actor{}); err != nil {
		t.Fatal(err)
	}
	p, err := e.principal(tok.AccessToken)
	if err != nil || p.FullData {
		t.Fatalf("after narrowing: %+v %v", p, err)
	}
	if rm := e.audit.find(auditdom.ActionMCPFullDataRemoved); rm == nil || rm.Metadata["user_id"] != owner.String() {
		t.Fatalf("narrowing audit: %+v", rm)
	}
	list, _ = e.svc.ListConnections(ctx, tenant, &owner)
	if list[0].FullData {
		t.Fatal("the list still shows the badge")
	}

	// A second full-data grant is revoked outright.
	code, _ = e.approveFull(owner, e.tenant)
	tok2, _ := e.exchange(code, verifier, nil)
	p2, _ := e.principal(tok2.AccessToken)
	if err := e.svc.RevokeConnection(ctx, tenant, shared.MustIDFromString(p2.GrantID), owner, false, mcpoauth.Actor{}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.principal(tok2.AccessToken); err == nil {
		t.Fatal("revoked full-data grant still works")
	}
}

func TestFullDataIsPerOrganization(t *testing.T) {
	e := newFullDataEnv(t)
	ctx := context.Background()
	// Full-data role in the first organization only; a plain member in the other.
	user := e.member(e.tenant, "member", "findings:read")
	e.roles.set(e.tenant, user, true)
	e.join(e.other, user.String(), "member")

	code, err := e.approveFull(user, e.tenant)
	if err != nil {
		t.Fatal(err)
	}
	tok, _ := e.exchange(code, verifier, nil)
	if list, _ := e.svc.ListConnections(ctx, shared.MustIDFromString(e.other), nil); len(list) != 0 {
		t.Fatalf("the other organization lists %d connections", len(list))
	}
	p, err := e.principal(tok.AccessToken)
	if err != nil || p.TenantID != e.tenant || !p.FullData {
		t.Fatalf("principal %+v %v", p, err)
	}
	// In the other organization the same person is a plain member: they are
	// not offered the option and cannot force it.
	id := mustStart(t, e.harness)
	other := shared.MustIDFromString(e.other)
	view, err := e.svc.ConsentRequest(ctx, id, user, other)
	if err != nil || view.FullDataAvailable {
		t.Fatalf("full data offered in an organization where the role is not held: %+v %v", view, err)
	}
	if _, err := e.svc.ApproveAccess(ctx, id, user, other, true, mcpoauth.Actor{}); !errors.Is(err, mcpoauth.ErrFullDataNotAllowed) {
		t.Fatalf("full data approved across organizations: %v", err)
	}
}
