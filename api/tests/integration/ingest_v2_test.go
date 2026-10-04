package integration

// RFC-026 WP-A6: the ingest semantics of protocol v2 results on a migrated
// database. The accept side (HTTP, edge) is exercised separately; here the
// segments are stored the way the accept side stores them and the worker-side
// processor runs them.

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/lib/pq"
	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/ingestjob"
	"github.com/openctemio/openctem/api/pkg/domain/ingestreport"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

type v2Rig struct {
	t       *testing.T
	svc     *ingest.Service
	db      *sql.DB
	reports *postgres.IngestReportRepository
	jobs    *postgres.IngestJobRepository
	proc    *ingest.V2JobProcessor
}

type v2Tenant struct {
	tenant, sensor shared.ID
	repo           string
}

func newV2Rig(t *testing.T, guard ingest.BlindingGuard) *v2Rig {
	t.Helper()
	return newV2RigWith(t, guard, nil)
}

// newV2RigWith is newV2Rig with a hook that wires more of the service (the
// result quarantine, the command reader).
func newV2RigWith(t *testing.T, guard ingest.BlindingGuard, configure func(*ingest.Service, *postgres.DB)) *v2Rig {
	t.Helper()
	sqldb := setupTestDB(t)
	t.Cleanup(func() { _ = sqldb.Close() })
	db := &postgres.DB{DB: sqldb}
	log := logger.NewNop()
	svc := ingest.NewService(
		postgres.NewAssetRepository(db), postgres.NewFindingRepository(db),
		postgres.NewVulnerabilityRepository(db), postgres.NewComponentRepository(db),
		postgres.NewSensorRepository(db), postgres.NewBranchRepository(db), postgres.NewTenantRepository(db),
		postgres.NewAuditRepository(db), log)
	if configure != nil {
		configure(svc, db)
	}
	r := &v2Rig{t: t, svc: svc, db: sqldb, reports: postgres.NewIngestReportRepository(db), jobs: postgres.NewIngestJobRepository(db)}
	r.proc = ingest.NewV2JobProcessor(svc, r.reports, r.jobs, protov2.DefaultLimits(), guard, log)
	return r
}

func (r *v2Rig) newTenant(tools ...string) v2Tenant {
	r.t.Helper()
	ctx := context.Background()
	tn := v2Tenant{tenant: shared.NewID(), sensor: shared.NewID()}
	tn.repo = "github.com/acme/app-" + tn.tenant.String()[:8]
	if _, err := r.db.ExecContext(ctx, `INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`,
		tn.tenant.String(), "v2-"+tn.tenant.String()); err != nil {
		r.t.Fatalf("seed tenant: %v", err)
	}
	r.t.Cleanup(func() {
		// Reports first (their jobs cascade), so no queue row outlives the
		// test even if the tenant delete fails.
		_, _ = r.db.ExecContext(context.Background(), `DELETE FROM ingest_reports WHERE tenant_id = $1`, tn.tenant.String())
		_, _ = r.db.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, tn.tenant.String())
	})
	if _, err := r.db.ExecContext(ctx, `INSERT INTO sensors (id, tenant_id, name, api_key_hash, api_key_prefix, status, type, tools)
		VALUES ($1, $2, 'v2-sensor', $3, 'rda_test', 'active', 'worker', $4)`,
		tn.sensor.String(), tn.tenant.String(), "h-"+tn.sensor.String(), pq.Array(tools)); err != nil {
		r.t.Fatalf("seed sensor: %v", err)
	}
	return tn
}

type v2Finding struct {
	rule, assetRef, cve string
}

// segment builds one complete v2 segment: the repository asset, the tool and
// the metadata of a full default-branch scan, and the given findings.
func (tn v2Tenant) segment(tool string, withAsset bool, findings ...v2Finding) *ctis.Report {
	r := &ctis.Report{
		Version: "1.0",
		Metadata: ctis.ReportMetadata{
			Timestamp:    time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC),
			CoverageType: "full",
			Branch:       &ctis.BranchInfo{Name: "main", IsDefaultBranch: true, RepositoryURL: "https://" + tn.repo},
		},
		Tool: &ctis.Tool{Name: tool},
	}
	if withAsset {
		r.Assets = []ctis.Asset{{ID: "repo", Type: ctis.AssetTypeRepository, Value: tn.repo}}
	}
	for _, f := range findings {
		cf := ctis.Finding{Type: ctis.FindingTypeVulnerability, Title: "finding " + f.rule, Severity: ctis.SeverityHigh,
			RuleID: f.rule, AssetRef: f.assetRef, Description: "sensor-supplied description " + f.rule,
			Location: &ctis.FindingLocation{Path: "src/" + f.rule + ".go", StartLine: 10}}
		if f.cve != "" {
			cf.Vulnerability = &ctis.VulnerabilityDetails{CVEID: f.cve, CVSSScore: 9.9}
		}
		r.Findings = append(r.Findings, cf)
	}
	return r
}

func (r *v2Rig) open(tn v2Tenant, reportID string, header *ctis.Report) *ingestreport.Report {
	r.t.Helper()
	canonical, digest, err := ingest.V2HeaderOf(header)
	if err != nil {
		r.t.Fatal(err)
	}
	now := time.Now()
	rep := &ingestreport.Report{ID: shared.NewID(), TenantID: tn.tenant, SensorID: tn.sensor, ReportID: reportID,
		State: protov2.StateReceiving, MediaType: protov2.MediaTypeCTIS, SensorType: "worker",
		HeaderDigest: digest, Header: canonical, ToolName: header.Tool.Name,
		ExpiresAt: now.Add(time.Hour), ReceivedAt: now}
	if err := r.reports.Create(context.Background(), rep); err != nil {
		r.t.Fatalf("create report: %v", err)
	}
	return rep
}

func (r *v2Rig) put(tn v2Tenant, rep *ingestreport.Report, seq int, seg *ctis.Report) {
	r.t.Helper()
	payload, err := json.Marshal(seg)
	if err != nil {
		r.t.Fatal(err)
	}
	s := seq
	job := ingestjob.NewV2Job(tn.tenant, &tn.sensor, rep.ReportID, ingestjob.V2Segment{
		ReportRef: rep.ID, Seq: &s, ContentDigest: fmt.Sprintf("sha-256=:%d:", seq), MediaType: protov2.MediaTypeCTIS}, payload)
	// Never claimable: a parallel package's ClaimBatch must not see it; the
	// test runs the processor on it directly.
	job.DelayUntil(time.Now().Add(24 * time.Hour))
	if _, _, err := r.jobs.EnqueueV2(context.Background(), job); err != nil {
		r.t.Fatalf("enqueue: %v", err)
	}
	if ok, err := r.reports.ReserveSegment(context.Background(), rep.ID, len(seg.Assets), len(seg.Findings),
		protov2.DefaultMaxAssetsPerReport, protov2.DefaultMaxFindingsPerReport, time.Now().Add(time.Hour)); err != nil || !ok {
		r.t.Fatalf("reserve: %v %v", ok, err)
	}
}

func (r *v2Rig) process(rep *ingestreport.Report, seq int) {
	r.t.Helper()
	job, err := r.jobs.GetV2Segment(context.Background(), rep.ID, seq)
	if err != nil {
		r.t.Fatalf("get segment job: %v", err)
	}
	if _, err := r.proc.Process(context.Background(), job); err != nil {
		r.t.Fatalf("process segment %d: %v", seq, err)
	}
}

func (r *v2Rig) commit(tn v2Tenant, rep *ingestreport.Report, n int) bool {
	r.t.Helper()
	ctx := context.Background()
	ok, err := r.reports.Commit(ctx, rep.ID, n, false, time.Now())
	if err != nil {
		r.t.Fatal(err)
	}
	if !ok {
		return false
	}
	commitJob := ingestjob.NewV2Job(tn.tenant, &tn.sensor, rep.ReportID, ingestjob.V2Segment{ReportRef: rep.ID}, nil)
	commitJob.DelayUntil(time.Now().Add(24 * time.Hour))
	job, _, err := r.jobs.EnqueueV2(ctx, commitJob)
	if err != nil {
		r.t.Fatal(err)
	}
	if _, err := r.proc.Process(ctx, job); err != nil {
		r.t.Fatalf("process commit: %v", err)
	}
	return true
}

func (r *v2Rig) status(rep *ingestreport.Report) protov2.Status {
	r.t.Helper()
	got, err := r.reports.GetByID(context.Background(), rep.ID)
	if err != nil {
		r.t.Fatal(err)
	}
	return got.Status(time.Now())
}

func (r *v2Rig) countFindings(tn v2Tenant, status string) int {
	r.t.Helper()
	var n int
	q := `SELECT COUNT(*) FROM findings WHERE tenant_id = $1`
	args := []any{tn.tenant.String()}
	if status != "" {
		q += ` AND status = $2`
		args = append(args, status)
	}
	if err := r.db.QueryRowContext(context.Background(), q, args...).Scan(&n); err != nil {
		r.t.Fatal(err)
	}
	return n
}

func (r *v2Rig) countAssets(tn v2Tenant) int {
	r.t.Helper()
	var n int
	if err := r.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM assets WHERE tenant_id = $1`, tn.tenant.String()).Scan(&n); err != nil {
		r.t.Fatal(err)
	}
	return n
}

// A 3-segment report of a bound, cleanly completed run arrives out of order;
// findings are stored as segments are processed, but nothing is auto-resolved
// until the commit, and the commit resolves exactly the findings the report no
// longer contains.
func TestIngestV2_SegmentsOutOfOrderAutoResolveOnlyOnCommit(t *testing.T) {
	r, _ := newBindingV2Rig(t)
	tn := r.newTenant("semgrep")
	baseCmd := r.runCommand(tn, "semgrep", "", "completed", 0)
	nextCmd := r.runCommand(tn, "semgrep", "", "completed", 0)

	// Baseline report: rules a, b, gone.
	base := r.openAs(tn, "0192a3b4-0000-7000-8000-000000000001", "worker", &baseCmd, tn.segment("semgrep", true))
	r.put(tn, base, 0, tn.segment("semgrep", true, v2Finding{rule: "a", assetRef: "repo"}, v2Finding{rule: "b", assetRef: "repo"}, v2Finding{rule: "gone", assetRef: "repo"}))
	r.process(base, 0)
	if !r.commit(tn, base, 1) {
		t.Fatal("commit baseline")
	}
	if st := r.status(base); st.State != protov2.StateCompleted || st.Accepted.Findings != 3 {
		t.Fatalf("baseline status %+v", st)
	}
	open := r.countFindings(tn, "new")
	if open != 3 {
		t.Fatalf("open after baseline: %d", open)
	}

	// Next scan in 3 segments without "gone": a, b, c.
	rep := r.openAs(tn, "0192a3b4-0000-7000-8000-000000000002", "worker", &nextCmd, tn.segment("semgrep", true))
	r.put(tn, rep, 2, tn.segment("semgrep", true, v2Finding{rule: "c", assetRef: "repo"}))
	r.put(tn, rep, 0, tn.segment("semgrep", true, v2Finding{rule: "a", assetRef: "repo"}))
	r.put(tn, rep, 1, tn.segment("semgrep", true, v2Finding{rule: "b"})) // no asset_ref: the single asset
	for _, seq := range []int{2, 0, 1} {
		r.process(rep, seq)
	}
	if got := r.countFindings(tn, "resolved"); got != 0 {
		t.Fatalf("resolved before commit: %d", got)
	}
	st := r.status(rep)
	if st.State != protov2.StateReceiving || st.Accepted.Findings != 3 || st.Segments.Received != 3 {
		t.Fatalf("pre-commit status %+v", st)
	}

	if !r.commit(tn, rep, 3) {
		t.Fatal("commit")
	}
	st = r.status(rep)
	if st.State != protov2.StateCompleted || st.AutoResolve != protov2.AutoResolveApplied || st.AutoResolved != 1 {
		t.Fatalf("committed status %+v", st)
	}
	if got := r.countFindings(tn, "resolved"); got != 1 {
		t.Fatalf("resolved after commit: %d", got)
	}
	// Segment payloads are dropped once the report finished.
	var bytesLeft int
	_ = r.db.QueryRow(`SELECT COALESCE(SUM(octet_length(payload)),0) FROM ingest_jobs WHERE ingest_report_id = $1`, rep.ID.String()).Scan(&bytesLeft)
	if bytesLeft != 0 {
		t.Fatalf("payload bytes left: %d", bytesLeft)
	}
}

// An uncommitted report expires and never resolves anything.
func TestIngestV2_ExpiredReportNeverResolves(t *testing.T) {
	r := newV2Rig(t, ingest.DefaultBlindingGuard())
	tn := r.newTenant("semgrep")
	base := r.open(tn, "0192a3b4-0000-7000-8000-000000000011", tn.segment("semgrep", true))
	r.put(tn, base, 0, tn.segment("semgrep", true, v2Finding{rule: "a", assetRef: "repo"}, v2Finding{rule: "b", assetRef: "repo"}))
	r.process(base, 0)
	r.commit(tn, base, 1)

	rep := r.open(tn, "0192a3b4-0000-7000-8000-000000000012", tn.segment("semgrep", true))
	r.put(tn, rep, 0, tn.segment("semgrep", true, v2Finding{rule: "a", assetRef: "repo"}))
	r.process(rep, 0)
	if _, err := r.reports.ExpireStale(context.Background(), time.Now().Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if r.commit(tn, rep, 1) {
		t.Fatal("an expired report was committed")
	}
	if st := r.status(rep); st.State != protov2.StateExpired {
		t.Fatalf("state %s", st.State)
	}
	if got := r.countFindings(tn, "resolved"); got != 0 {
		t.Fatalf("an expired report resolved %d findings", got)
	}
}

// A finding with no resolvable asset is rejected, and no fallback asset is
// created for it.
func TestIngestV2_AssetlessFindingRejectedNoFallbackAsset(t *testing.T) {
	r := newV2Rig(t, ingest.DefaultBlindingGuard())
	tn := r.newTenant("semgrep")
	rep := r.open(tn, "0192a3b4-0000-7000-8000-000000000021", tn.segment("semgrep", false))
	// Segment 0: findings, no asset at all (v1 would invent one from the
	// branch metadata). Segment 1: one finding names an asset that is not in
	// its segment, one resolves.
	r.put(tn, rep, 0, tn.segment("semgrep", false, v2Finding{rule: "x"}, v2Finding{rule: "y"}))
	r.put(tn, rep, 1, tn.segment("semgrep", true, v2Finding{rule: "z", assetRef: "elsewhere"}, v2Finding{rule: "ok", assetRef: "repo"}))
	r.process(rep, 0)
	r.process(rep, 1)
	r.commit(tn, rep, 2)

	st := r.status(rep)
	if st.Accepted.Findings != 1 || st.Rejected.Findings != 3 || st.Accepted.Assets != 1 {
		t.Fatalf("status %+v", st)
	}
	if len(st.Errors) != 3 {
		t.Fatalf("errors %+v", st.Errors)
	}
	for _, e := range st.Errors {
		if e.Code != protov2.CodeAssetUnresolved || e.Segment == nil {
			t.Fatalf("error %+v", e)
		}
	}
	if got := r.countAssets(tn); got != 1 {
		t.Fatalf("assets: %d (a fallback asset was created)", got)
	}
	if got := r.countFindings(tn, ""); got != 1 {
		t.Fatalf("findings: %d", got)
	}
}

// A tool the sensor did not declare never auto-resolves on commit, even when
// the stored header names it (the accept side refuses it first; this is the
// defense in depth for a sensor whose tools changed in between).
func TestIngestV2_UndeclaredToolDoesNotAutoResolve(t *testing.T) {
	r, _ := newBindingV2Rig(t)
	tn := r.newTenant("trivy")
	baseCmd := r.runCommand(tn, "semgrep", "", "completed", 0)
	nextCmd := r.runCommand(tn, "semgrep", "", "completed", 0)
	base := r.openAs(tn, "0192a3b4-0000-7000-8000-000000000031", "worker", &baseCmd, tn.segment("semgrep", true))
	r.put(tn, base, 0, tn.segment("semgrep", true, v2Finding{rule: "a", assetRef: "repo"}, v2Finding{rule: "b", assetRef: "repo"}))
	r.process(base, 0)
	r.commit(tn, base, 1)
	rep := r.openAs(tn, "0192a3b4-0000-7000-8000-000000000032", "worker", &nextCmd, tn.segment("semgrep", true))
	r.put(tn, rep, 0, tn.segment("semgrep", true, v2Finding{rule: "a", assetRef: "repo"}))
	r.process(rep, 0)
	r.commit(tn, rep, 1)
	if st := r.status(rep); st.AutoResolve != protov2.AutoResolveSkipped {
		t.Fatalf("auto_resolve %q", st.AutoResolve)
	}
	if got := r.countFindings(tn, "resolved"); got != 0 {
		t.Fatalf("resolved %d", got)
	}
}

// The blinding guard holds a commit that would resolve too much at once.
func TestIngestV2_BlindingGuardHolds(t *testing.T) {
	r, _ := newBindingV2RigGuard(t, ingest.BlindingGuard{Ratio: 0.5, MinFindings: 1})
	tn := r.newTenant("semgrep")
	baseCmd := r.runCommand(tn, "semgrep", "", "completed", 0)
	nextCmd := r.runCommand(tn, "semgrep", "", "completed", 0)
	base := r.openAs(tn, "0192a3b4-0000-7000-8000-000000000041", "worker", &baseCmd, tn.segment("semgrep", true))
	r.put(tn, base, 0, tn.segment("semgrep", true, v2Finding{rule: "a", assetRef: "repo"}, v2Finding{rule: "b", assetRef: "repo"}, v2Finding{rule: "c", assetRef: "repo"}))
	r.process(base, 0)
	r.commit(tn, base, 1)
	// The next report sees only "a": resolving b and c is 2 of 3 open.
	rep := r.openAs(tn, "0192a3b4-0000-7000-8000-000000000042", "worker", &nextCmd, tn.segment("semgrep", true))
	r.put(tn, rep, 0, tn.segment("semgrep", true, v2Finding{rule: "a", assetRef: "repo"}))
	r.process(rep, 0)
	r.commit(tn, rep, 1)
	if st := r.status(rep); st.AutoResolve != protov2.AutoResolveHeld || st.AutoResolved != 0 {
		t.Fatalf("status %+v", st)
	}
	if got := r.countFindings(tn, "resolved"); got != 0 {
		t.Fatalf("held, yet resolved %d", got)
	}
}

// Sensor CVE text never reaches the global catalog; an existing catalog entry
// is linked but not changed.
func TestIngestV2_NoGlobalCatalogWrites(t *testing.T) {
	r := newV2Rig(t, ingest.DefaultBlindingGuard())
	tn := r.newTenant("semgrep")
	ctx := context.Background()
	unknownCVE := fmt.Sprintf("CVE-2099-%d", 10000+time.Now().UnixNano()%80000)
	knownCVE := fmt.Sprintf("CVE-2098-%d", 10000+time.Now().UnixNano()%80000)
	knownID := shared.NewID()
	if _, err := r.db.ExecContext(ctx, `INSERT INTO vulnerabilities (id, cve_id, title, description, severity)
		VALUES ($1, $2, 'catalog title', 'catalog description', 'low')`, knownID.String(), knownCVE); err != nil {
		t.Fatalf("seed catalog: %v", err)
	}
	t.Cleanup(func() {
		_, _ = r.db.ExecContext(context.Background(), `DELETE FROM findings WHERE tenant_id = $1`, tn.tenant.String())
		_, _ = r.db.ExecContext(context.Background(), `DELETE FROM vulnerabilities WHERE cve_id IN ($1, $2)`, knownCVE, unknownCVE)
	})

	rep := r.open(tn, "0192a3b4-0000-7000-8000-000000000051", tn.segment("semgrep", true))
	r.put(tn, rep, 0, tn.segment("semgrep", true,
		v2Finding{rule: "u", assetRef: "repo", cve: unknownCVE}, v2Finding{rule: "k", assetRef: "repo", cve: knownCVE}))
	r.process(rep, 0)
	r.commit(tn, rep, 1)

	var n int
	_ = r.db.QueryRow(`SELECT COUNT(*) FROM vulnerabilities WHERE cve_id = $1`, unknownCVE).Scan(&n)
	if n != 0 {
		t.Fatal("a sensor wrote a new CVE into the global catalog")
	}
	var desc, sev string
	_ = r.db.QueryRow(`SELECT description, severity FROM vulnerabilities WHERE id = $1`, knownID.String()).Scan(&desc, &sev)
	if desc != "catalog description" || sev != "low" {
		t.Fatalf("the catalog entry was changed: %q %q", desc, sev)
	}
	var linked int
	_ = r.db.QueryRow(`SELECT COUNT(*) FROM findings WHERE tenant_id = $1 AND vulnerability_id = $2`, tn.tenant.String(), knownID.String()).Scan(&linked)
	if linked != 1 {
		t.Fatalf("finding not linked to the existing catalog entry: %d", linked)
	}
	var reported int
	_ = r.db.QueryRow(`SELECT COUNT(*) FROM findings WHERE tenant_id = $1 AND description LIKE 'sensor-supplied description%'`, tn.tenant.String()).Scan(&reported)
	if reported != 2 {
		t.Fatalf("reported text not kept on the tenant's findings: %d", reported)
	}
}

// Two tenants can use the same report id; their reports and findings stay
// apart.
func TestIngestV2_SameReportIDTwoTenantsIsolated(t *testing.T) {
	r := newV2Rig(t, ingest.DefaultBlindingGuard())
	a, b := r.newTenant("semgrep"), r.newTenant("semgrep")
	id := "0192a3b4-0000-7000-8000-000000000061"
	ra := r.open(a, id, a.segment("semgrep", true))
	rb := r.open(b, id, b.segment("semgrep", true))
	r.put(a, ra, 0, a.segment("semgrep", true, v2Finding{rule: "a1", assetRef: "repo"}, v2Finding{rule: "a2", assetRef: "repo"}))
	r.put(b, rb, 0, b.segment("semgrep", true, v2Finding{rule: "b1", assetRef: "repo"}))
	r.process(ra, 0)
	r.process(rb, 0)
	r.commit(a, ra, 1)
	r.commit(b, rb, 1)
	if r.countFindings(a, "") != 2 || r.countFindings(b, "") != 1 {
		t.Fatalf("findings a=%d b=%d", r.countFindings(a, ""), r.countFindings(b, ""))
	}
	if _, err := r.reports.Get(context.Background(), a.tenant, b.sensor, id); err == nil {
		t.Fatal("tenant a read tenant b's report")
	}
}

// A segment the worker processes twice (a retry after a crash) is counted
// once.
func TestIngestV2_RetriedSegmentCountedOnce(t *testing.T) {
	r := newV2Rig(t, ingest.DefaultBlindingGuard())
	tn := r.newTenant("semgrep")
	rep := r.open(tn, "0192a3b4-0000-7000-8000-000000000071", tn.segment("semgrep", true))
	r.put(tn, rep, 0, tn.segment("semgrep", true, v2Finding{rule: "a", assetRef: "repo"}))
	r.process(rep, 0)
	r.process(rep, 0)
	r.commit(tn, rep, 1)
	if st := r.status(rep); st.Accepted.Findings != 1 || st.Accepted.Assets != 1 {
		t.Fatalf("status %+v", st)
	}
}
