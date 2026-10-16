package integration

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app/audit"
	exposureapp "github.com/openctemio/openctem/api/internal/app/exposure"
	"github.com/openctemio/openctem/api/internal/app/integration"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/exposure"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// dispositionFixture: tenant A with an owner and two administrators (three
// eligible approvers), tenant B, tenant Solo whose owner is the only member,
// and tenant SoloAdmin whose only member is an administrator (not an owner).
type dispositionFixture struct {
	db                       *sql.DB
	pdb                      *postgres.DB
	a, b, solo, soloAdmin    shared.ID
	owner, u1, u2, soloOwner shared.ID
	lonelyAdmin              shared.ID
	svc                      *exposureapp.ExposureService
	creds                    *integration.CredentialImportService
}

func newDispositionFixture(t *testing.T) *dispositionFixture {
	t.Helper()
	db := setupTestDB(t)
	f := &dispositionFixture{
		db: db, pdb: &postgres.DB{DB: db},
		a:         createTestTenant(t, db, "disp-a"),
		b:         createTestTenant(t, db, "disp-b"),
		solo:      createTestTenant(t, db, "disp-solo"),
		soloAdmin: createTestTenant(t, db, "disp-solo-admin"),
		owner:     shared.NewID(), u1: shared.NewID(), u2: shared.NewID(), soloOwner: shared.NewID(),
		lonelyAdmin: shared.NewID(),
	}
	users := []shared.ID{f.owner, f.u1, f.u2, f.soloOwner, f.lonelyAdmin}
	t.Cleanup(func() {
		for _, id := range []shared.ID{f.a, f.b, f.solo, f.soloAdmin} {
			_, _ = db.Exec(`DELETE FROM tenants WHERE id = $1`, id.String())
		}
		for _, id := range users {
			_, _ = db.Exec(`DELETE FROM users WHERE id = $1`, id.String())
		}
		_ = db.Close()
	})
	for _, u := range users {
		f.exec(t, `INSERT INTO users (id, email, name) VALUES ($1, $2, 'disp')`, u.String(), u.String()+"@example.com")
	}
	f.member(t, f.a, f.owner, "owner")
	f.member(t, f.a, f.u1, "admin")
	f.member(t, f.a, f.u2, "admin")
	f.member(t, f.solo, f.soloOwner, "owner")
	f.member(t, f.soloAdmin, f.lonelyAdmin, "admin")

	log := logger.NewNop()
	gate := exposureapp.NewDispositionGate(postgres.NewExposureDispositionRepository(f.pdb),
		audit.NewAuditService(postgres.NewAuditRepository(f.pdb), log), log)
	gate.SetTOTP(fakeFreshTOTP{good: "246810"})
	expRepo := postgres.NewExposureRepository(f.pdb)
	histRepo := postgres.NewExposureStateHistoryRepository(f.pdb)
	f.svc = exposureapp.NewExposureService(expRepo, histRepo, log)
	f.svc.SetDispositionGate(gate)
	f.creds = integration.NewCredentialImportService(expRepo, histRepo, log)
	f.creds.SetDispositionGate(gate)
	return f
}

func (f *dispositionFixture) exec(t *testing.T, q string, args ...any) {
	t.Helper()
	if _, err := f.db.Exec(q, args...); err != nil {
		t.Fatalf("%v\n%s", err, q)
	}
}

func (f *dispositionFixture) member(t *testing.T, tenant, user shared.ID, role string) {
	f.exec(t, `INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, $3)`, user.String(), tenant.String(), role)
}

func (f *dispositionFixture) exposure(t *testing.T, tenant shared.ID, eventType, severity string) shared.ID {
	t.Helper()
	id := shared.NewID()
	f.exec(t, `INSERT INTO exposure_events (id, tenant_id, event_type, severity, state, title, fingerprint, source)
		VALUES ($1, $2, $3, $4, 'active', 'disp exposure', $5, 'test')`,
		id.String(), tenant.String(), eventType, severity, "disp-"+id.String())
	return id
}

func (f *dispositionFixture) state(t *testing.T, id shared.ID) string {
	t.Helper()
	var s string
	if err := f.db.QueryRow(`SELECT state FROM exposure_events WHERE id = $1`, id.String()).Scan(&s); err != nil {
		t.Fatalf("read state: %v", err)
	}
	return s
}

func (f *dispositionFixture) audits(t *testing.T, id shared.ID, action string) int {
	t.Helper()
	var n int
	if err := f.db.QueryRow(`SELECT COUNT(*) FROM audit_logs WHERE resource_id = $1 AND action = $2`, id.String(), action).Scan(&n); err != nil {
		t.Fatalf("count audit: %v", err)
	}
	return n
}

func (f *dispositionFixture) call(tenant, id, user shared.ID, state exposure.State) (*exposureapp.DispositionOutcome, error) {
	return f.svc.RequestDisposition(context.Background(), exposureapp.DispositionCall{
		TenantID: tenant.String(), ExposureID: id.String(), UserID: user.String(), State: state, Reason: "reviewed"})
}

// TestExposureDisposition_FourEyes: a medium exposure takes one approver; a
// high one takes two different people; the requester cannot confirm their
// own; another disposition cannot jump the queue; every step is audited.
func TestExposureDisposition_FourEyes(t *testing.T) {
	f := newDispositionFixture(t)

	medium := f.exposure(t, f.a, "port_open", "medium")
	if out, err := f.call(f.a, medium, f.u1, exposure.StateAccepted); err != nil || out.Pending {
		t.Fatalf("medium: %v pending=%v", err, out != nil && out.Pending)
	}
	if s := f.state(t, medium); s != "accepted" {
		t.Fatalf("medium state %s, want accepted at once", s)
	}

	high := f.exposure(t, f.a, "port_open", "high")
	out, err := f.call(f.a, high, f.u1, exposure.StateAccepted)
	if err != nil || !out.Pending || out.Request == nil {
		t.Fatalf("first approver: %v %+v", err, out)
	}
	if s := f.state(t, high); s != "active" {
		t.Fatalf("high state %s after one approver, want active", s)
	}
	// The requester cannot confirm their own request.
	if _, err := f.call(f.a, high, f.u1, exposure.StateAccepted); !errors.Is(err, exposure.ErrDispositionSelfApproval) {
		t.Fatalf("self confirm: %v, want ErrDispositionSelfApproval", err)
	}
	// A different disposition cannot replace the pending one.
	if _, err := f.call(f.a, high, f.u2, exposure.StateFalsePositive); !errors.Is(err, exposure.ErrDispositionConflict) {
		t.Fatalf("other disposition: %v, want ErrDispositionConflict", err)
	}
	// Another tenant cannot see or confirm it.
	if _, err := f.call(f.b, high, f.u2, exposure.StateAccepted); err == nil {
		t.Fatal("tenant B confirmed tenant A's disposition")
	}
	if _, err := f.svc.RejectDisposition(context.Background(), exposureapp.DispositionCall{
		TenantID: f.b.String(), ExposureID: high.String(), UserID: f.u2.String()}); err == nil {
		t.Fatal("tenant B rejected tenant A's disposition")
	}
	if s := f.state(t, high); s != "active" {
		t.Fatalf("state %s after refused calls, want active", s)
	}

	out, err = f.call(f.a, high, f.u2, exposure.StateAccepted)
	if err != nil || out.Pending || out.SelfApproved {
		t.Fatalf("second approver: %v %+v", err, out)
	}
	if s := f.state(t, high); s != "accepted" {
		t.Fatalf("high state %s after two approvers, want accepted", s)
	}
	if f.audits(t, high, "exposure.disposition_requested") != 1 || f.audits(t, high, "exposure.disposition_approved") != 1 {
		t.Fatal("request and approval are not both audited")
	}

	// The owner as requester, with other approvers present, cannot confirm.
	critical := f.exposure(t, f.a, "port_open", "critical")
	if out, err := f.call(f.a, critical, f.owner, exposure.StateFalsePositive); err != nil || !out.Pending {
		t.Fatalf("owner request: %v", err)
	}
	if _, err := f.call(f.a, critical, f.owner, exposure.StateFalsePositive); !errors.Is(err, exposure.ErrDispositionSelfApproval) {
		t.Fatalf("owner self confirm with other approvers: %v", err)
	}
	// Reject: a second approver drops it; the requester can ask again.
	if _, err := f.svc.RejectDisposition(context.Background(), exposureapp.DispositionCall{
		TenantID: f.a.String(), ExposureID: critical.String(), UserID: f.u1.String(), Reason: "not convinced"}); err != nil {
		t.Fatalf("reject: %v", err)
	}
	if f.audits(t, critical, "exposure.disposition_rejected") != 1 {
		t.Fatal("rejection not audited")
	}
	if out, err := f.call(f.a, critical, f.owner, exposure.StateFalsePositive); err != nil || !out.Pending {
		t.Fatalf("request after reject: %v", err)
	}

	// A request can never point at another tenant's exposure.
	repo := postgres.NewExposureDispositionRepository(f.pdb)
	other := f.exposure(t, f.b, "port_open", "high")
	req, _ := exposure.NewDispositionRequest(f.a, other, f.u1, exposure.StateAccepted, "x")
	if err := repo.Create(context.Background(), req); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant create: %v, want not found", err)
	}
}

// fakeFreshTOTP accepts one code, as the authenticator check would.
type fakeFreshTOTP struct{ good string }

func (f fakeFreshTOTP) VerifyFreshTOTP(_ context.Context, _, code string) error {
	if code != f.good {
		return exposure.ErrDispositionSelfApprovalBadCode
	}
	return nil
}

func (f *dispositionFixture) selfApprove(tenant, id, user shared.ID, state exposure.State, reason, code string) (*exposureapp.DispositionOutcome, error) {
	return f.svc.RequestDisposition(context.Background(), exposureapp.DispositionCall{
		TenantID: tenant.String(), ExposureID: id.String(), UserID: user.String(), State: state, Reason: reason,
		Self: exposureapp.SelfApproval{Requested: true, Code: code}})
}

func (f *dispositionFixture) auditSeverity(t *testing.T, id shared.ID, action string) []string {
	t.Helper()
	rows, err := f.db.Query(`SELECT severity FROM audit_logs WHERE resource_id = $1 AND action = $2 ORDER BY logged_at, id`, id.String(), action)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestExposureDisposition_OwnerAloneSelfApproves: a lone owner's request is
// never applied automatically; their own approval is a separate call with a
// reason and a fresh authenticator code, audited Critical; every refused
// attempt (no reason, no code, wrong code) is audited High and changes
// nothing; another tenant reaches nothing.
func TestExposureDisposition_OwnerAloneSelfApproves(t *testing.T) {
	f := newDispositionFixture(t)
	high := f.exposure(t, f.solo, "port_open", "high")
	out, err := f.call(f.solo, high, f.soloOwner, exposure.StateAccepted)
	if err != nil || !out.Pending || out.SelfApproved {
		t.Fatalf("solo owner request: %v %+v, want pending", err, out)
	}
	if s := f.state(t, high); s != "active" {
		t.Fatalf("state %s after the request, want active (never applied automatically)", s)
	}
	// Repeating the plain call is not an own approval.
	if _, err := f.call(f.solo, high, f.soloOwner, exposure.StateAccepted); !errors.Is(err, exposure.ErrDispositionSelfApproval) {
		t.Fatalf("plain repeat: %v, want ErrDispositionSelfApproval", err)
	}
	if _, err := f.selfApprove(f.solo, high, f.soloOwner, exposure.StateAccepted, "", "246810"); !errors.Is(err, exposure.ErrDispositionSelfApprovalNeedsReason) {
		t.Fatalf("no reason: %v", err)
	}
	if _, err := f.selfApprove(f.solo, high, f.soloOwner, exposure.StateAccepted, "only member", ""); !errors.Is(err, exposure.ErrDispositionSelfApprovalBadCode) {
		t.Fatalf("no code: %v", err)
	}
	if _, err := f.selfApprove(f.solo, high, f.soloOwner, exposure.StateAccepted, "only member", "111111"); !errors.Is(err, exposure.ErrDispositionSelfApprovalBadCode) {
		t.Fatalf("wrong code: %v", err)
	}
	// Another tenant cannot approve it, even with a good code.
	if _, err := f.selfApprove(f.b, high, f.soloOwner, exposure.StateAccepted, "x", "246810"); err == nil {
		t.Fatal("tenant B self-approved tenant Solo's exposure")
	}
	if s := f.state(t, high); s != "active" {
		t.Fatalf("state %s after refused attempts, want active", s)
	}
	if got := f.auditSeverity(t, high, "exposure.disposition_self_approval_refused"); len(got) != 3 || got[0] != "high" {
		t.Fatalf("refusals audited %v, want 3 at high", got)
	}

	out, err = f.selfApprove(f.solo, high, f.soloOwner, exposure.StateAccepted, "only member; reviewed the port", "246810")
	if err != nil || out.Pending || !out.SelfApproved {
		t.Fatalf("self-approve with fresh code: %v %+v", err, out)
	}
	if s := f.state(t, high); s != "accepted" {
		t.Fatalf("state %s, want accepted", s)
	}
	if got := f.auditSeverity(t, high, "exposure.disposition_self_approved"); len(got) != 1 || got[0] != "critical" {
		t.Fatalf("self-approval audit %v, want one critical", got)
	}
}

// TestExposureDisposition_SelfApprovalOnlyLoneOwner: an owner with other
// approvers, and a lone administrator who is not an owner, may never approve
// their own request, even with a good code.
func TestExposureDisposition_SelfApprovalOnlyLoneOwner(t *testing.T) {
	f := newDispositionFixture(t)
	crit := f.exposure(t, f.a, "port_open", "critical")
	if out, err := f.call(f.a, crit, f.owner, exposure.StateFalsePositive); err != nil || !out.Pending {
		t.Fatalf("owner request: %v", err)
	}
	if _, err := f.selfApprove(f.a, crit, f.owner, exposure.StateFalsePositive, "x", "246810"); !errors.Is(err, exposure.ErrDispositionSelfApprovalNotAllowed) {
		t.Fatalf("owner with other approvers: %v, want ErrDispositionSelfApprovalNotAllowed", err)
	}
	// Someone else's request is never "self"-approved.
	if _, err := f.selfApprove(f.a, crit, f.u1, exposure.StateFalsePositive, "x", "246810"); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("self-approve of another's request: %v", err)
	}
	lone := f.exposure(t, f.soloAdmin, "port_open", "high")
	if out, err := f.call(f.soloAdmin, lone, f.lonelyAdmin, exposure.StateAccepted); err != nil || !out.Pending {
		t.Fatalf("lone admin request: %v", err)
	}
	if _, err := f.selfApprove(f.soloAdmin, lone, f.lonelyAdmin, exposure.StateAccepted, "x", "246810"); !errors.Is(err, exposure.ErrDispositionSelfApprovalNotAllowed) {
		t.Fatalf("lone non-owner: %v, want ErrDispositionSelfApprovalNotAllowed", err)
	}
	if f.state(t, crit) != "active" || f.state(t, lone) != "active" {
		t.Fatal("a refused self-approval changed an exposure")
	}
	// Without a verifier wired the call fails closed.
	log := logger.NewNop()
	bare := exposureapp.NewDispositionGate(postgres.NewExposureDispositionRepository(f.pdb), nil, log)
	svc := exposureapp.NewExposureService(postgres.NewExposureRepository(f.pdb), postgres.NewExposureStateHistoryRepository(f.pdb), log)
	svc.SetDispositionGate(bare)
	solo := f.exposure(t, f.solo, "port_open", "high")
	if _, err := f.call(f.solo, solo, f.soloOwner, exposure.StateAccepted); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RequestDisposition(context.Background(), exposureapp.DispositionCall{TenantID: f.solo.String(),
		ExposureID: solo.String(), UserID: f.soloOwner.String(), State: exposure.StateAccepted, Reason: "x",
		Self: exposureapp.SelfApproval{Requested: true, Code: "246810"}}); !errors.Is(err, exposure.ErrDispositionSelfApprovalBadCode) {
		t.Fatalf("no verifier: %v, want ErrDispositionSelfApprovalBadCode", err)
	}
}

// TestExposureDisposition_Credentials: the credential routes follow the same
// rule.
func TestExposureDisposition_Credentials(t *testing.T) {
	f := newDispositionFixture(t)
	ctx := context.Background()
	leak := f.exposure(t, f.a, "credential_leaked", "critical")

	item, err := f.creds.MarkCredentialFalsePositive(ctx, f.a.String(), leak.String(), f.u1.String(), "test fixture")
	if err != nil || item.PendingDisposition == nil || item.State != "active" {
		t.Fatalf("first approver: %v %+v", err, item)
	}
	if _, err := f.creds.MarkCredentialFalsePositive(ctx, f.a.String(), leak.String(), f.u1.String(), ""); !errors.Is(err, exposure.ErrDispositionSelfApproval) {
		t.Fatalf("self confirm: %v", err)
	}
	if _, err := f.creds.MarkCredentialFalsePositive(ctx, f.b.String(), leak.String(), f.u2.String(), ""); err == nil {
		t.Fatal("tenant B confirmed tenant A's credential")
	}
	got, err := f.creds.GetByID(ctx, f.a.String(), leak.String())
	if err != nil || got.PendingDisposition == nil || got.PendingDisposition.RequestedState != "false_positive" {
		t.Fatalf("pending not shown on read: %v %+v", err, got)
	}
	item, err = f.creds.MarkCredentialFalsePositive(ctx, f.a.String(), leak.String(), f.u2.String(), "")
	if err != nil || item.PendingDisposition != nil || item.State != "false_positive" {
		t.Fatalf("second approver: %v %+v", err, item)
	}

	// A lone owner's leak: pending first, own approval only with a fresh code.
	soloLeak := f.exposure(t, f.solo, "credential_leaked", "critical")
	if item, err := f.creds.AcceptCredential(ctx, f.solo.String(), soloLeak.String(), f.soloOwner.String(), "rotated"); err != nil || item.PendingDisposition == nil || item.State != "active" {
		t.Fatalf("solo leak request: %v %+v", err, item)
	}
	if _, err := f.creds.ApplyCredentialDisposition(ctx, f.solo.String(), soloLeak.String(), f.soloOwner.String(), exposure.StateAccepted,
		"rotated", audit.AuditContext{}, exposureapp.SelfApproval{Requested: true, Code: "000000"}); !errors.Is(err, exposure.ErrDispositionSelfApprovalBadCode) {
		t.Fatalf("solo leak wrong code: %v", err)
	}
	if item, err := f.creds.ApplyCredentialDisposition(ctx, f.solo.String(), soloLeak.String(), f.soloOwner.String(), exposure.StateAccepted,
		"rotated", audit.AuditContext{}, exposureapp.SelfApproval{Requested: true, Code: "246810"}); err != nil || item.State != "accepted" {
		t.Fatalf("solo leak self-approve: %v %+v", err, item)
	}

	low := f.exposure(t, f.a, "credential_leaked", "low")
	if item, err := f.creds.AcceptCredential(ctx, f.a.String(), low.String(), f.u1.String(), ""); err != nil || item.State != "accepted" {
		t.Fatalf("low leak takes one approver: %v %+v", err, item)
	}
}

// TestExposureDisposition_SelfApprovalAfterMemberRemoval: a lone owner may
// not approve their own request within 7 days of a member being suspended
// or removed (removing the other approver must not open the path at once);
// after 7 days they may; another organization's change does not count.
func TestExposureDisposition_SelfApprovalAfterMemberRemoval(t *testing.T) {
	f := newDispositionFixture(t)
	gone, elsewhere := shared.NewID(), shared.NewID()
	t.Cleanup(func() {
		for _, id := range []shared.ID{gone, elsewhere} {
			_, _ = f.db.Exec(`DELETE FROM tenant_members WHERE user_id = $1`, id.String())
			_, _ = f.db.Exec(`DELETE FROM users WHERE id = $1`, id.String())
		}
	})
	for _, u := range []shared.ID{gone, elsewhere} {
		f.exec(t, `INSERT INTO users (id, email, name) VALUES ($1, $2, 'disp')`, u.String(), u.String()+"@example.com")
	}
	// Another organization suspended someone yesterday: does not count.
	f.exec(t, `INSERT INTO tenant_members (user_id, tenant_id, role, status, suspended_at) VALUES ($1, $2, 'admin', 'suspended', now() - interval '1 day')`,
		elsewhere.String(), f.b.String())
	high := f.exposure(t, f.solo, "port_open", "high")
	if out, err := f.call(f.solo, high, f.soloOwner, exposure.StateAccepted); err != nil || !out.Pending {
		t.Fatalf("request: %v", err)
	}
	// The solo organization suspended its admin 2 days ago.
	f.exec(t, `INSERT INTO tenant_members (user_id, tenant_id, role, status, suspended_at) VALUES ($1, $2, 'admin', 'suspended', now() - interval '2 days')`,
		gone.String(), f.solo.String())
	_, err := f.selfApprove(f.solo, high, f.soloOwner, exposure.StateAccepted, "only member", "246810")
	if !errors.Is(err, exposure.ErrDispositionSelfApprovalAfterRemoval) || !strings.Contains(err.Error(), "possible again from") {
		t.Fatalf("2 days after a suspension: %v, want ErrDispositionSelfApprovalAfterRemoval with the date", err)
	}
	if got := f.auditSeverity(t, high, "exposure.disposition_self_approval_refused"); len(got) != 1 {
		t.Fatalf("refusal audited %v, want once", got)
	}
	if s := f.state(t, high); s != "active" {
		t.Fatalf("state %s, want active", s)
	}
	f.exec(t, `UPDATE tenant_members SET suspended_at = now() - interval '8 days' WHERE user_id = $1`, gone.String())
	if out, err := f.selfApprove(f.solo, high, f.soloOwner, exposure.StateAccepted, "only member", "246810"); err != nil || !out.SelfApproved {
		t.Fatalf("8 days after: %v", err)
	}
}

// Demoting the other approver, or changing a role so it loses the approve
// permission, is a recent approver change: the owner left alone may not
// approve their own disposition for 7 days.
func TestExposureDisposition_SelfApprovalAfterRoleChange(t *testing.T) {
	f := newDispositionFixture(t)
	for i, action := range []string{"member.role_changed", "user.roles_updated", "role.updated", "role.deleted", "role.unassigned"} {
		high := f.exposure(t, f.solo, "port_open", "high")
		if out, err := f.call(f.solo, high, f.soloOwner, exposure.StateAccepted); err != nil || !out.Pending {
			t.Fatalf("request: %v", err)
		}
		f.exec(t, `DELETE FROM audit_logs WHERE tenant_id = $1 AND action = ANY($2)`, f.solo.String(),
			pq.Array([]string{"member.role_changed", "user.roles_updated", "role.updated", "role.deleted", "role.unassigned"}))
		f.exec(t, `INSERT INTO audit_logs (id, tenant_id, action, resource_type, resource_id, result, severity, message, logged_at)
			VALUES (gen_random_uuid(), $1, $2, 'role', 'x', 'success', 'medium', 'changed', now() - interval '1 hour')`, f.solo.String(), action)
		_, err := f.selfApprove(f.solo, high, f.soloOwner, exposure.StateAccepted, "only member", "246810")
		if !errors.Is(err, exposure.ErrDispositionSelfApprovalAfterRemoval) {
			t.Fatalf("%d: 1 hour after %s: %v, want ErrDispositionSelfApprovalAfterRemoval", i, action, err)
		}
		f.exec(t, `UPDATE audit_logs SET logged_at = now() - interval '8 days' WHERE tenant_id = $1 AND action = $2`, f.solo.String(), action)
		if out, err := f.selfApprove(f.solo, high, f.soloOwner, exposure.StateAccepted, "only member", "246810"); err != nil || !out.SelfApproved {
			t.Fatalf("%d: 8 days after %s: %v", i, action, err)
		}
	}
}
