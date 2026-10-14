package integration

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/audit"
	exposureapp "github.com/openctemio/openctem/api/internal/app/exposure"
	"github.com/openctemio/openctem/api/internal/app/integration"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/exposure"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// dispositionFixture: tenant A with an owner and two administrators (three
// eligible approvers), tenant B, and tenant Solo whose owner is the only
// member.
type dispositionFixture struct {
	db                       *sql.DB
	pdb                      *postgres.DB
	a, b, solo               shared.ID
	owner, u1, u2, soloOwner shared.ID
	svc                      *exposureapp.ExposureService
	creds                    *integration.CredentialImportService
}

func newDispositionFixture(t *testing.T) *dispositionFixture {
	t.Helper()
	db := setupTestDB(t)
	f := &dispositionFixture{
		db: db, pdb: &postgres.DB{DB: db},
		a:     createTestTenant(t, db, "disp-a"),
		b:     createTestTenant(t, db, "disp-b"),
		solo:  createTestTenant(t, db, "disp-solo"),
		owner: shared.NewID(), u1: shared.NewID(), u2: shared.NewID(), soloOwner: shared.NewID(),
	}
	users := []shared.ID{f.owner, f.u1, f.u2, f.soloOwner}
	t.Cleanup(func() {
		for _, id := range []shared.ID{f.a, f.b, f.solo} {
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

	log := logger.NewNop()
	gate := exposureapp.NewDispositionGate(postgres.NewExposureDispositionRepository(f.pdb),
		audit.NewAuditService(postgres.NewAuditRepository(f.pdb), log), log)
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

// TestExposureDisposition_OwnerAloneSelfApproves: the owner who is the only
// eligible approver applies at once; the step is audited Critical.
func TestExposureDisposition_OwnerAloneSelfApproves(t *testing.T) {
	f := newDispositionFixture(t)
	high := f.exposure(t, f.solo, "port_open", "high")
	out, err := f.call(f.solo, high, f.soloOwner, exposure.StateAccepted)
	if err != nil || out.Pending || !out.SelfApproved {
		t.Fatalf("solo owner: %v %+v", err, out)
	}
	if s := f.state(t, high); s != "accepted" {
		t.Fatalf("state %s, want accepted", s)
	}
	var sev string
	if err := f.db.QueryRow(`SELECT severity FROM audit_logs WHERE resource_id = $1 AND action = 'exposure.disposition_self_approved'`,
		high.String()).Scan(&sev); err != nil || sev != "critical" {
		t.Fatalf("self-approval audit: %v %q, want critical", err, sev)
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

	low := f.exposure(t, f.a, "credential_leaked", "low")
	if item, err := f.creds.AcceptCredential(ctx, f.a.String(), low.String(), f.u1.String(), ""); err != nil || item.State != "accepted" {
		t.Fatalf("low leak takes one approver: %v %+v", err, item)
	}
}
