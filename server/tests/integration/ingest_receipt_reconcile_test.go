package integration

// Every receipt reconciles on every ingest path (research 436;
// docs/architecture/ingest-receipts.md, "Outcomes"): what the source sent
// equals new + seen again + reopened + suppressed + failed + skipped + the
// other outcomes (split adds to the received side). The paths: an upload
// (with records the parser skipped), a connector sync (a second sync sees
// the same findings again), a store that fails, and a fingerprint check
// that fails (counted as failed, never dropped without a trace).

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/ctis/v2"

	"github.com/openctemio/openctem/server/internal/app/ingest"
	"github.com/openctemio/openctem/server/internal/app/scope"
	"github.com/openctemio/openctem/server/internal/infra/postgres"
	"github.com/openctemio/openctem/server/pkg/domain/ingestreceipt"
	"github.com/openctemio/openctem/server/pkg/domain/sensor"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// failingFindings fails one step of the finding store.
type failingFindings struct {
	*postgres.FindingRepository
	failCreate, failCheck bool
}

func (f *failingFindings) CreateBatchWithResult(ctx context.Context, fs []*vulnerability.Finding) (*vulnerability.BatchCreateResult, error) {
	if f.failCreate {
		return nil, errors.New("store down")
	}
	return f.FindingRepository.CreateBatchWithResult(ctx, fs)
}

func (f *failingFindings) CheckFingerprintsExist(ctx context.Context, tenantID shared.ID, fps []string) (map[string]bool, error) {
	if f.failCheck {
		return nil, errors.New("store down")
	}
	return f.FindingRepository.CheckFingerprintsExist(ctx, tenantID, fps)
}

// reconExcluded is the host every reconciliation tenant excludes.
const reconExcluded = "excluded.recon-host.example.org"

type reconRig struct {
	t        *testing.T
	db       *sql.DB
	findings *failingFindings
	ing      *ingest.Service
	receipts *postgres.IngestReceiptRepository
}

func newReconRig(t *testing.T) *reconRig {
	t.Helper()
	db := openLifecycleDB(t)
	pg := &postgres.DB{DB: db}
	ff := &failingFindings{FindingRepository: postgres.NewFindingRepository(pg)}
	ing := ingest.NewService(
		postgres.NewAssetRepository(pg), ff,
		postgres.NewVulnerabilityRepository(pg), postgres.NewComponentRepository(pg),
		postgres.NewSensorRepository(pg), postgres.NewBranchRepository(pg), postgres.NewTenantRepository(pg),
		postgres.NewAuditRepository(pg), logger.NewNop())
	rr := postgres.NewIngestReceiptRepository(pg)
	ing.SetReceiptRecorder(rr)
	ing.SetExclusionSource(scope.NewService(postgres.NewScopeTargetRepository(pg), postgres.NewScopeExclusionRepository(pg),
		postgres.NewAssetRepository(pg), logger.NewNop()))
	return &reconRig{t: t, db: db, findings: ff, ing: ing, receipts: rr}
}

// reconReport is one host with the given rules; a rule named twice is a
// repeat in the same report, and rule "gone" is on a host the tenant
// excluded from scope (skipped, with its receipt item).
func reconReport(rules ...string) *ctis.Report {
	rep := &ctis.Report{Version: ctis.SchemaVersion, Tool: &ctis.Tool{Name: "nuclei"},
		Assets: []ctis.Asset{{ID: "h", Type: ctis.AssetTypeDomainName, Value: "recon-host.example.org"},
			{ID: "gone", Type: ctis.AssetTypeDomainName, Value: reconExcluded}},
		Metadata: ctis.ReportMetadata{ID: ctis.NewReportID(), GeneratedAt: time.Now().UTC(), CoverageType: "partial"}}
	for _, r := range rules {
		ref := "h"
		if r == "gone" {
			ref = "gone"
		}
		rep.Findings = append(rep.Findings, ctis.Finding{Type: ctis.FindingTypeVulnerability, Title: "check " + r,
			RuleID: "rule-" + r, Severity: ctis.SeverityHigh, AssetRef: ref})
	}
	return rep
}

// tenant seeds a tenant that excludes reconExcluded.
func (r *reconRig) tenant() shared.ID {
	r.t.Helper()
	tid := seedLifecycleTenant(context.Background(), r.t, r.db)
	if _, err := r.db.ExecContext(context.Background(), `INSERT INTO scope_exclusions (tenant_id, exclusion_type, pattern,
		reason, status, approved_at, approved_by, created_by) VALUES ($1, 'domain', $2, 'test', 'active', now(), 'approver', 'test')`,
		tid.String(), reconExcluded); err != nil {
		r.t.Fatal(err)
	}
	return tid
}

func (r *reconRig) ingest(tenant shared.ID, rep *ctis.Report, opts ingest.Options) *ingest.Output {
	r.t.Helper()
	tid := tenant
	out, err := r.ing.Ingest(context.Background(), &sensor.Sensor{TenantID: &tid, Status: sensor.SensorStatusActive},
		ingest.Input{Report: rep, CoverageType: ingest.CoverageTypePartial, Options: opts})
	if err != nil {
		r.t.Fatalf("ingest: %v", err)
	}
	return out
}

// receipt reads a receipt's counts and asserts it reconciles.
func (r *reconRig) reconciled(tenant shared.ID, id string) (int, ingestreceipt.Counts, map[string]int) {
	r.t.Helper()
	var (
		received int
		c        ingestreceipt.Counts
		raw      []byte
	)
	if err := r.db.QueryRowContext(context.Background(), `
		SELECT findings_received, findings_created, findings_updated, findings_reopened, findings_suppressed,
			findings_failed, skipped, outcomes
		FROM ingest_receipts WHERE tenant_id = $1 AND id = $2`, tenant.String(), id).
		Scan(&received, &c.Created, &c.StillDetected, &c.Reopened, &c.Suppressed, &c.Failed, &c.Skipped, &raw); err != nil {
		r.t.Fatalf("receipt: %v", err)
	}
	outcomes := map[string]int{}
	if err := json.Unmarshal(raw, &outcomes); err != nil {
		r.t.Fatal(err)
	}
	if n := ingestreceipt.Unaccounted(received, c, outcomes); n != 0 {
		r.t.Fatalf("receipt does not reconcile (%d unaccounted): received %d, counts %+v, outcomes %v", n, received, c, outcomes)
	}
	// The tool rows sum to the receipt.
	var toolReceived int
	if err := r.db.QueryRowContext(context.Background(), `SELECT COALESCE(SUM(received), 0) FROM ingest_receipt_tools
		WHERE tenant_id = $1 AND receipt_id = $2`, tenant.String(), id).Scan(&toolReceived); err != nil {
		r.t.Fatal(err)
	}
	if toolReceived != received {
		r.t.Fatalf("tool rows received %d, receipt %d", toolReceived, received)
	}
	return received, c, outcomes
}

func TestReceiptReconcile_Upload(t *testing.T) {
	r := newReconRig(t)
	ctx := context.Background()
	tenant := r.tenant()
	ref := shared.NewID()
	opts := ingest.Options{SourceKind: "import", SourceName: "import:nuclei",
		Receipt: &ingestreceipt.Source{Kind: ingestreceipt.SourceUpload, Ref: ref.String()}}
	if err := r.receipts.CreateUpload(ctx, &ingestreceipt.Upload{ID: ref, TenantID: tenant, Format: "ctis"}); err != nil {
		t.Fatal(err)
	}

	// Two files of one upload: a repeat inside the first, the second repeats
	// the first, and one finding names no asset.
	out := r.ingest(tenant, reconReport("a", "a", "b", "gone"), opts)
	r.ingest(tenant, reconReport("a", "b"), opts)
	// Two records the parser skipped (below the minimum severity).
	if err := r.receipts.FinishUpload(ctx, tenant, ref, &ingestreceipt.UploadResult{Status: ingestreceipt.StatusCompleted, Skipped: 2}); err != nil {
		t.Fatal(err)
	}
	if out.ReceiptID != ref.String() {
		t.Fatalf("receipt %s, want the upload's %s", out.ReceiptID, ref)
	}
	received, c, outcomes := r.reconciled(tenant, ref.String())
	if received != 8 || c.Created != 2 || outcomes[ingestreceipt.OutcomeMerged] != 3 || c.Skipped != 3 {
		t.Fatalf("received %d, counts %+v, outcomes %v", received, c, outcomes)
	}
}

func TestReceiptReconcile_ConnectorSeenAgain(t *testing.T) {
	r := newReconRig(t)
	ctx := context.Background()
	tenant := r.tenant()
	sync := func(run string, rules ...string) string {
		tid := tenant
		out, err := r.ing.Ingest(ctx, &sensor.Sensor{TenantID: &tid, Status: sensor.SensorStatusActive}, ingest.Input{
			Report: reconReport(rules...), CoverageType: ingest.CoverageTypePartial,
			Options: ingest.Options{Binding: ingest.TrustedBinding(), SourceKind: "integration", SourceName: "feed", SourceRun: run},
		})
		if err != nil {
			t.Fatal(err)
		}
		return out.ReceiptID
	}
	first := sync("sync-1", "a", "b")
	second := sync("sync-2", "a", "a", "b", "c")
	if _, c, _ := r.reconciled(tenant, first); c.Created != 2 {
		t.Fatalf("first sync %+v", c)
	}
	// The second sync: c is new, a and b are seen again unchanged, the
	// second a is a repeat in the same report.
	received, c, outcomes := r.reconciled(tenant, second)
	if received != 4 || c.Created != 1 || c.StillDetected != 2 || outcomes[ingestreceipt.OutcomeMerged] != 1 {
		t.Fatalf("second sync: received %d, counts %+v, outcomes %v", received, c, outcomes)
	}
	// Another tenant's receipts are untouched.
	other := seedLifecycleTenant(ctx, t, r.db)
	var n int
	if err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM ingest_receipts WHERE tenant_id = $1`, other.String()).Scan(&n); err != nil || n != 0 {
		t.Fatalf("another tenant has %d receipts (%v)", n, err)
	}
}

// A store failure is counted as failed (with its error), and the findings
// skipped beside it stay skipped: before, the failures were subtracted from
// a skipped count that never held them.
func TestReceiptReconcile_StoreFailure(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		failCreate, failCheck bool
		still, failed         int
	}{{"create", true, false, 1, 1}, {"fingerprint check", false, true, 0, 2}} {
		t.Run(tc.name, func(t *testing.T) {
			r := newReconRig(t)
			tenant := r.tenant()
			opts := func(run string) ingest.Options {
				return ingest.Options{Binding: ingest.TrustedBinding(), SourceKind: "integration", SourceName: "feed", SourceRun: run}
			}
			// a exists before the failing sync.
			r.ingest(tenant, reconReport("a"), opts("sync-0"))
			r.findings.failCreate, r.findings.failCheck = tc.failCreate, tc.failCheck
			out := r.ingest(tenant, reconReport("a", "b", "gone"), opts("sync-1"))
			received, c, _ := r.reconciled(tenant, out.ReceiptID)
			if received != 3 || c.StillDetected != tc.still || c.Failed != tc.failed || c.Skipped != 1 {
				t.Fatalf("received %d, counts %+v", received, c)
			}
		})
	}
}
