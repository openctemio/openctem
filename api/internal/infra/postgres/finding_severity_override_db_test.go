package postgres

// Analyst severity override against a real database
// (docs/architecture/finding-severity-override.md): the change recomputes
// and persists priority, its reason and the SLA deadline; re-sightings and
// the ingest upsert keep the override and raise a review entry; a downgrade
// under the approval policy waits as a request and applies on approval;
// another tenant and a member without the asset in scope get not found;
// timeline and audit rows record old, new and reason. Skipped unless
// DATABASE_URL names a migrated test database.

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app/activity"
	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/datascope"
	"github.com/openctemio/openctem/api/internal/app/finding"
	"github.com/openctemio/openctem/api/internal/app/sla"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// sevSLA is an SLA policy by priority class: P0 2 days, P1 7, P2 30, P3 90.
type sevSLA struct{}

func (sevSLA) CalculateSLADeadlineForPriority(_ context.Context, _, _, pc string, _ vulnerability.Severity, at time.Time) (time.Time, error) {
	days := map[string]int{"P0": 2, "P1": 7, "P2": 30, "P3": 90}[pc]
	return at.Add(time.Duration(days) * 24 * time.Hour), nil
}

type sevFPLevel string

func (l sevFPLevel) GetFindingApprovalSettings(_ context.Context, _ string) (*tenantdom.FindingApprovalSettings, error) {
	return &tenantdom.FindingApprovalSettings{FPApproval: string(l)}, nil
}

type sevFixture struct {
	db      *sql.DB
	repo    *FindingRepository
	tenant  shared.ID
	asset   shared.ID
	analyst shared.ID
	other   shared.ID
	member  shared.ID
	svc     func(level string, caller string) *finding.VulnerabilityService
}

func newSevFixture(t *testing.T) *sevFixture {
	t.Helper()
	url := testdb.URL()
	if url == "" {
		t.Skip("DATABASE_URL not set; skipping DB execution check")
	}
	db, err := sql.Open("postgres", url)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}
	pdb := &DB{DB: db}
	fx := &sevFixture{db: db, repo: NewFindingRepository(pdb)}
	fx.tenant = seedTestTenant(ctx, t, db)
	fx.asset = seedPublicAsset(ctx, t, db, fx.tenant)
	fx.analyst, fx.other, fx.member = seedUser(ctx, t, pdb), seedUser(ctx, t, pdb), seedUser(ctx, t, pdb)
	log := logger.NewNop()
	assets := NewAssetRepository(pdb)
	fx.svc = func(level, caller string) *finding.VulnerabilityService {
		classifier := finding.NewPriorityClassificationService(fx.repo, assets,
			fakeEPSSRepo{}, fakeKEVRepo{}, fakeRuleRepo{}, fakeAuditRepo{}, log)
		svc := finding.NewVulnerabilityService(nil, fx.repo, log)
		svc.SetAssetRepository(assets)
		svc.SetDataScope(datascope.New(NewDataScopeRepository(pdb), func(context.Context) datascope.Caller {
			return datascope.Caller{UserID: caller}
		}, log))
		svc.SetPriorityClassifier(classifier)
		svc.SetSLAApplier(sla.NewApplier(sevSLA{}))
		svc.SetSeverityRequestRepository(NewSeverityRequestRepository(pdb))
		svc.SetActivityService(activity.NewFindingActivityService(NewFindingActivityRepository(pdb), fx.repo, log))
		svc.SetAuditService(auditapp.NewAuditService(NewAuditRepository(pdb), log))
		if level != "" {
			svc.SetSoloApproval(nil, nil, sevFPLevel(level))
		}
		return svc
	}
	return fx
}

// create makes a manual finding of sev on the public asset (classified and
// given an SLA deadline at creation).
func (fx *sevFixture) create(t *testing.T, sev string) *vulnerability.Finding {
	t.Helper()
	f, err := fx.svc("", "").CreateFinding(context.Background(), finding.CreateFindingInput{
		TenantID: fx.tenant.String(), AssetID: fx.asset.String(), Source: "manual", ToolName: "manual-entry",
		Message: "severity override probe", Severity: sev,
	})
	if err != nil {
		t.Fatalf("create finding: %v", err)
	}
	return f
}

func (fx *sevFixture) load(t *testing.T, id shared.ID) *vulnerability.Finding {
	t.Helper()
	f, err := fx.repo.GetByID(context.Background(), fx.tenant, id)
	if err != nil {
		t.Fatalf("load finding: %v", err)
	}
	return f
}

func (fx *sevFixture) count(t *testing.T, q string, args ...any) int {
	t.Helper()
	var n int
	if err := fx.db.QueryRowContext(context.Background(), q, args...).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}

func classOf(f *vulnerability.Finding) string {
	if pc := f.PriorityClass(); pc != nil {
		return string(*pc)
	}
	return ""
}

// TestSeverityChange_RecomputesPriorityAndSLA: low -> critical on a
// public-exposure asset moves P3 to P1 and the SLA deadline from 90 days to 7
// days from now, in the response and in the stored row, with the timeline and
// audit rows carrying old, new and reason.
func TestSeverityChange_RecomputesPriorityAndSLA(t *testing.T) {
	fx := newSevFixture(t)
	ctx := context.Background()
	f := fx.create(t, "low")
	before := fx.load(t, f.ID())
	if classOf(before) != "P3" || before.SLADeadline() == nil {
		t.Fatalf("setup: low finding class=%s sla=%v, want P3 with a deadline", classOf(before), before.SLADeadline())
	}

	res, err := fx.svc("", "").ChangeFindingSeverity(ctx, finding.ChangeSeverityInput{
		TenantID: fx.tenant.String(), FindingID: f.ID().String(), ActorID: fx.analyst.String(),
		Severity: "critical", Reason: "exploit published for our version",
	})
	if err != nil {
		t.Fatalf("change severity: %v", err)
	}
	stored := fx.load(t, f.ID())
	for name, got := range map[string]*vulnerability.Finding{"response": res.Finding, "stored": stored} {
		if got.Severity() != vulnerability.SeverityCritical || got.SourceSeverity() != vulnerability.SeverityLow {
			t.Errorf("%s: severity=%s source=%s, want critical over source low", name, got.Severity(), got.SourceSeverity())
		}
		if classOf(got) != "P1" {
			t.Errorf("%s: priority=%s, want P1 (critical, reachable)", name, classOf(got))
		}
		if got.PriorityClassReason() == before.PriorityClassReason() {
			t.Errorf("%s: the priority reason did not change: %q", name, got.PriorityClassReason())
		}
		d := got.SLADeadline()
		if d == nil || d.After(time.Now().Add(8*24*time.Hour)) || !d.Before(*before.SLADeadline()) {
			t.Errorf("%s: sla deadline %v, want about 7 days from now (was %v)", name, d, before.SLADeadline())
		}
	}
	if n := fx.count(t, `SELECT COUNT(*) FROM finding_activities WHERE tenant_id = $1 AND finding_id = $2
		AND activity_type = 'severity_changed' AND changes->>'old_severity' = 'low' AND changes->>'new_severity' = 'critical'
		AND changes->>'reason' = 'exploit published for our version'`, fx.tenant.String(), f.ID().String()); n != 1 {
		t.Errorf("severity_changed timeline rows = %d, want 1", n)
	}
	if n := fx.count(t, `SELECT COUNT(*) FROM audit_logs WHERE tenant_id = $1 AND resource_id = $2
		AND action = 'finding.severity_changed' AND actor_id = $3
		AND metadata->>'old_severity' = 'low' AND metadata->>'reason' = 'exploit published for our version'`,
		fx.tenant.String(), f.ID().String(), fx.analyst.String()); n != 1 {
		t.Errorf("audit rows = %d, want 1", n)
	}
}

// TestSeverityOverride_ResightingKeepsOverride: a re-sighting (enrich path)
// and a racing insert (upsert path) never revert the analyst's severity;
// they move the source severity, which raises a review entry.
func TestSeverityOverride_ResightingKeepsOverride(t *testing.T) {
	fx := newSevFixture(t)
	ctx := context.Background()
	f := fx.create(t, "high")
	// Level off + approver: the downgrade applies at once.
	if _, err := fx.svc(tenantdom.FPApprovalOff, "").ChangeFindingSeverity(ctx, finding.ChangeSeverityInput{
		TenantID: fx.tenant.String(), FindingID: f.ID().String(), ActorID: fx.analyst.String(),
		Severity: "low", Reason: "only reachable from the build network", CanApprove: true,
	}); err != nil {
		t.Fatalf("downgrade: %v", err)
	}
	stored := fx.load(t, f.ID())
	if stored.Severity() != vulnerability.SeverityLow || classOf(stored) != "P3" {
		t.Fatalf("after downgrade: severity=%s class=%s, want low/P3", stored.Severity(), classOf(stored))
	}
	// A downgrade one person may decide extends the deadline too (P3 window
	// from the first detection).
	if d, want := stored.SLADeadline(), stored.FirstDetectedAt().Add(90*24*time.Hour); d == nil || d.Sub(want).Abs() > time.Minute {
		t.Errorf("sla deadline after downgrade = %v, want %v", d, want)
	}

	resight, err := vulnerability.NewFinding(fx.tenant, fx.asset, vulnerability.FindingSourceSAST, "manual-entry", vulnerability.SeverityCritical, "severity override probe")
	if err != nil {
		t.Fatal(err)
	}
	resight.SetFingerprint(stored.Fingerprint())
	if _, err := fx.repo.EnrichBatchByFingerprints(ctx, fx.tenant, []*vulnerability.Finding{resight}, ""); err != nil {
		t.Fatalf("enrich: %v", err)
	}
	got := fx.load(t, f.ID())
	if got.Severity() != vulnerability.SeverityLow || !got.HasSeverityOverride() {
		t.Errorf("re-sighting reverted the override: severity=%s override=%v", got.Severity(), got.HasSeverityOverride())
	}
	if got.SourceSeverity() != vulnerability.SeverityCritical {
		t.Errorf("source severity = %s, want critical (the tool's new report)", got.SourceSeverity())
	}
	if n := fx.count(t, `SELECT COUNT(*) FROM finding_activities WHERE tenant_id = $1 AND finding_id = $2
		AND activity_type = 'severity_source_changed' AND changes->>'new_source_severity' = 'critical'`,
		fx.tenant.String(), f.ID().String()); n != 1 {
		t.Errorf("review entries = %d, want 1", n)
	}

	// The insert path (two ingests racing on the fingerprint) keeps it too.
	dup, _ := vulnerability.NewFinding(fx.tenant, fx.asset, vulnerability.FindingSourceSAST, "manual-entry", vulnerability.SeverityMedium, "severity override probe")
	dup.SetFingerprint(stored.Fingerprint())
	if _, err := fx.repo.CreateBatchWithResult(ctx, []*vulnerability.Finding{dup}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	got = fx.load(t, f.ID())
	if got.Severity() != vulnerability.SeverityLow || got.SourceSeverity() != vulnerability.SeverityMedium || classOf(got) != "P3" {
		t.Errorf("upsert: severity=%s source=%s class=%s, want low over source medium, P3", got.Severity(), got.SourceSeverity(), classOf(got))
	}

	// Restore (raises the severity: no approval) brings the tool's back.
	res, err := fx.svc(tenantdom.FPApprovalAll, "").ChangeFindingSeverity(ctx, finding.ChangeSeverityInput{
		TenantID: fx.tenant.String(), FindingID: f.ID().String(), ActorID: fx.analyst.String(),
		Restore: true, Reason: "the build network is now exposed",
	})
	if err != nil || !res.Applied {
		t.Fatalf("restore: applied=%v err=%v", res != nil && res.Applied, err)
	}
	got = fx.load(t, f.ID())
	if got.Severity() != vulnerability.SeverityMedium || got.HasSeverityOverride() || got.SeverityProvenance().Source != "" {
		t.Errorf("restored: severity=%s override=%v source=%q, want medium with no override", got.Severity(), got.HasSeverityOverride(), got.SeverityProvenance().Source)
	}
}

// TestSeverityOverride_DowngradeWaitsForApproval: under level all a
// downgrade is a pending request (stored, finding unchanged); another person's
// approval applies it, records the sign-off and recomputes the priority.
func TestSeverityOverride_DowngradeWaitsForApproval(t *testing.T) {
	fx := newSevFixture(t)
	ctx := context.Background()
	f := fx.create(t, "critical")
	svc := fx.svc(tenantdom.FPApprovalAll, "")
	start := fx.load(t, f.ID())
	if start.SLADeadline() == nil {
		t.Fatal("setup: no SLA deadline")
	}

	res, err := svc.ChangeFindingSeverity(ctx, finding.ChangeSeverityInput{
		TenantID: fx.tenant.String(), FindingID: f.ID().String(), ActorID: fx.analyst.String(),
		Severity: "low", Reason: "compensating WAF rule blocks the payload", CanApprove: true,
	})
	if err != nil {
		t.Fatalf("downgrade: %v", err)
	}
	if res.Applied || res.Request == nil {
		t.Fatalf("want a pending request, got applied=%v", res.Applied)
	}
	if got := fx.load(t, f.ID()); got.Severity() != vulnerability.SeverityCritical || classOf(got) != "P1" {
		t.Fatalf("finding changed before approval: severity=%s class=%s", got.Severity(), classOf(got))
	}
	if n := fx.count(t, `SELECT COUNT(*) FROM finding_severity_requests WHERE tenant_id = $1 AND finding_id = $2
		AND status = 'pending' AND requested_severity = 'low' AND previous_severity = 'critical' AND requested_by = $3`,
		fx.tenant.String(), f.ID().String(), fx.analyst.String()); n != 1 {
		t.Fatalf("pending request rows = %d, want 1", n)
	}
	pending, err := svc.PendingSeverityRequest(ctx, fx.tenant, f.ID())
	if err != nil || pending == nil || pending.ID != res.Request.ID {
		t.Fatalf("pending request read back: %v %v", pending, err)
	}

	in := finding.DecideSeverityRequestInput{TenantID: fx.tenant.String(), FindingID: f.ID().String(),
		RequestID: res.Request.ID.String(), ActorID: fx.analyst.String()}
	if _, err := svc.ApproveSeverityRequest(ctx, in); !errors.Is(err, vulnerability.ErrSelfApproval) {
		t.Fatalf("self approval: want ErrSelfApproval, got %v", err)
	}
	in.ActorID = fx.other.String()
	out, err := svc.ApproveSeverityRequest(ctx, in)
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	got := fx.load(t, f.ID())
	if !out.Applied || got.Severity() != vulnerability.SeverityLow || got.SourceSeverity() != vulnerability.SeverityCritical {
		t.Errorf("approved: severity=%s source=%s", got.Severity(), got.SourceSeverity())
	}
	if classOf(got) != "P3" {
		t.Errorf("priority after approved downgrade = %s, want P3", classOf(got))
	}
	// The approved downgrade is the explicit decision that extends the
	// deadline: the P3 window (90 days) from the first detection, not from now.
	wantDue := got.FirstDetectedAt().Add(90 * 24 * time.Hour)
	if d := got.SLADeadline(); d == nil || !d.After(*start.SLADeadline()) || d.Sub(wantDue).Abs() > time.Minute {
		t.Errorf("sla deadline after approved downgrade = %v, want %v (later than %v)", d, wantDue, start.SLADeadline())
	}
	if out.Finding.SLADeadline() == nil || !out.Finding.SLADeadline().Equal(*got.SLADeadline()) {
		t.Errorf("response deadline %v differs from stored %v", out.Finding.SLADeadline(), got.SLADeadline())
	}
	if o := got.SeverityOverride(); o == nil || o.By == nil || *o.By != fx.analyst {
		t.Errorf("override author = %+v, want the requester", o)
	}
	if n := fx.count(t, `SELECT COUNT(*) FROM approval_signoffs WHERE tenant_id = $1 AND subject_type = 'severity_request'
		AND subject_id = $2 AND user_id = $3`, fx.tenant.String(), res.Request.ID.String(), fx.other.String()); n != 1 {
		t.Errorf("sign-off rows = %d, want 1", n)
	}
	if n := fx.count(t, `SELECT COUNT(*) FROM finding_severity_requests WHERE id = $1 AND status = 'approved' AND decided_by = $2`,
		res.Request.ID.String(), fx.other.String()); n != 1 {
		t.Errorf("request not approved by the approver")
	}
	if n := fx.count(t, `SELECT COUNT(*) FROM audit_logs WHERE tenant_id = $1 AND resource_id = $2
		AND action IN ('finding.severity_requested', 'finding.severity_changed')`, fx.tenant.String(), f.ID().String()); n != 2 {
		t.Errorf("audit rows (requested + changed) = %d, want 2", n)
	}
}

// TestSeverityOverride_IsolationNegatives: another tenant and a member
// without the finding's asset in their data scope get not found; nothing
// changes.
func TestSeverityOverride_IsolationNegatives(t *testing.T) {
	fx := newSevFixture(t)
	ctx := context.Background()
	f := fx.create(t, "medium")

	other := seedTestTenant(ctx, t, fx.db)
	_, err := fx.svc("", "").ChangeFindingSeverity(ctx, finding.ChangeSeverityInput{
		TenantID: other.String(), FindingID: f.ID().String(), ActorID: fx.analyst.String(),
		Severity: "critical", Reason: "probe",
	})
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("cross-tenant: want not found, got %v", err)
	}

	// A member with no scope row sees nothing.
	_, err = fx.svc("", fx.member.String()).ChangeFindingSeverity(ctx, finding.ChangeSeverityInput{
		TenantID: fx.tenant.String(), FindingID: f.ID().String(), ActorID: fx.member.String(),
		Severity: "critical", Reason: "probe",
	})
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("out of data scope: want not found, got %v", err)
	}

	// Nor can such a member approve a request on it.
	res, err := fx.svc(tenantdom.FPApprovalAll, "").ChangeFindingSeverity(ctx, finding.ChangeSeverityInput{
		TenantID: fx.tenant.String(), FindingID: f.ID().String(), ActorID: fx.analyst.String(),
		Severity: "low", Reason: "test-only host",
	})
	if err != nil || res.Request == nil {
		t.Fatalf("downgrade request: %v", err)
	}
	_, err = fx.svc(tenantdom.FPApprovalAll, fx.member.String()).ApproveSeverityRequest(ctx, finding.DecideSeverityRequestInput{
		TenantID: fx.tenant.String(), FindingID: f.ID().String(), RequestID: res.Request.ID.String(), ActorID: fx.member.String(),
	})
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("approval out of data scope: want not found, got %v", err)
	}
	if got := fx.load(t, f.ID()); got.Severity() != vulnerability.SeverityMedium || got.HasSeverityOverride() {
		t.Errorf("finding changed by a refused caller: severity=%s", got.Severity())
	}
}
