package integration

// Per-item dispositions on the receipt, the policy and version that decided
// each item, the versioned policy snapshot, and the durable side-effect
// outbox (docs/rfcs/RFC-122-ingest-receipts.md, "Dispositions").

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/ingestjob"
	"github.com/openctemio/openctem/api/pkg/domain/ingestreceipt"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/suppression"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// countingChecker counts the suppression rule loads (the snapshot cache).
type countingChecker struct {
	ingest.SuppressionChecker
	mu    sync.Mutex
	loads int
	fail  bool
}

func (c *countingChecker) ListActiveRules(ctx context.Context, tenantID shared.ID) ([]*suppression.Rule, error) {
	c.mu.Lock()
	c.loads++
	fail := c.fail
	c.mu.Unlock()
	if fail {
		return nil, errors.New("rules store down")
	}
	return c.SuppressionChecker.ListActiveRules(ctx, tenantID)
}

// noAssets is an uploader scope that holds no asset.
type noAssets struct{}

func (noAssets) AssetsInScope(context.Context, []shared.ID) ([]shared.ID, error) { return nil, nil }

func dispReport(repo string, findings ...ctis.Finding) *ctis.Report {
	return &ctis.Report{Version: "1.0", Tool: &ctis.Tool{Name: "semgrep"},
		Metadata: ctis.ReportMetadata{ID: shared.NewID().String(), Timestamp: time.Now().UTC()},
		Assets: []ctis.Asset{{ID: "a", Type: ctis.AssetTypeRepository, Value: repo},
			{ID: "b", Type: ctis.AssetTypeRepository, Value: repo + "-second"}},
		Findings: findings}
}

func dispFinding(rule, ref string, line int) ctis.Finding {
	return ctis.Finding{AssetRef: ref, Type: ctis.FindingTypeVulnerability, Title: rule, RuleID: rule, Severity: "high",
		Location: &ctis.FindingLocation{Path: "app/run.py", StartLine: line, Snippet: rule + "()"}}
}

func TestIngest_DispositionsAndPolicyVersions(t *testing.T) {
	checker := &countingChecker{}
	r := newV2RigWith(t, ingest.DefaultBlindingGuard(), func(svc *ingest.Service, db *postgres.DB) {
		checker.SuppressionChecker = suppression.NewService(postgres.NewSuppressionRepository(db), logger.NewNop())
		svc.SetSuppressionChecker(checker)
		svc.SetPolicyVersions(postgres.NewIngestPolicyVersions(db))
	})
	ctx := context.Background()
	tn := r.newTenant()
	ruleID := shared.NewID()
	if _, err := r.db.ExecContext(ctx, `INSERT INTO suppression_rules (id, tenant_id, name, rule_id, suppression_type, status, approved_at)
		VALUES ($1, $2, 'fp', 'py.md5', 'false_positive', 'approved', NOW())`, ruleID.String(), tn.tenant.String()); err != nil {
		t.Fatal(err)
	}
	version := func() int64 {
		v, err := postgres.NewIngestPolicyVersions(&postgres.DB{DB: r.db}).PolicyVersion(ctx, tn.tenant)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	v1 := version()
	if v1 == 0 {
		t.Fatal("a suppression rule write did not bump the policy version")
	}
	tid := tn.tenant
	agt := &sensor.Sensor{ID: tn.sensor, TenantID: &tid, Type: sensor.SensorTypeWorker, Status: sensor.SensorStatusActive}
	rep := dispReport(tn.repo, dispFinding("py.md5", "a", 3), dispFinding("py.cmdi", "a", 9), dispFinding("py.lost", "nope", 1))
	out, err := r.svc.Ingest(ctx, agt, ingest.Input{Report: rep})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	receipt, _ := shared.IDFromString(out.ReceiptID)
	repo := postgres.NewIngestReceiptRepository(&postgres.DB{DB: r.db})

	// The suppressed finding is recorded as suppressed with its rule and
	// the version it was decided under; the other as created.
	rows, _, err := repo.ListActions(ctx, tn.tenant, receipt, "", nil, pagination.New(1, 100))
	if err != nil {
		t.Fatal(err)
	}
	actions := map[string]ingestreceipt.ActionRow{}
	for _, row := range rows {
		actions[row.Title] = row
	}
	sup := actions["py.md5"]
	if sup.Action != ingestreceipt.ActionSuppressed || sup.Policy != ingestreceipt.PolicySuppressionRule ||
		sup.PolicyID == nil || *sup.PolicyID != ruleID || sup.PolicyVersion == nil || *sup.PolicyVersion != v1 {
		t.Fatalf("suppressed row = %+v", sup)
	}
	if actions["py.cmdi"].Action != ingestreceipt.ActionCreated || actions["py.cmdi"].Policy != "" {
		t.Fatalf("created row = %+v", actions["py.cmdi"])
	}
	// The finding without a target asset is a rejected item, decided by
	// validation, with no evidence.
	items, total, err := repo.ListItems(ctx, tn.tenant, receipt, "", nil, pagination.New(1, 100))
	if err != nil || total != 1 {
		t.Fatalf("items %d %v", total, err)
	}
	if it := items[0]; it.Disposition != ingestreceipt.DispositionRejected || it.ReasonCode != ingestreceipt.ReasonNoTargetAsset ||
		it.Policy != ingestreceipt.PolicyValidation || it.PolicyVersion != v1 || it.Title != "py.lost" || it.Tool != "semgrep" {
		t.Fatalf("item = %+v", it)
	}
	// A restricted reader does not see an item without an asset.
	scoped := &shared.DataScope{TenantID: tn.tenant, UserID: shared.NewID()}
	if _, n, _ := repo.ListItems(ctx, tn.tenant, receipt, "", scoped, pagination.New(1, 100)); n != 0 {
		t.Fatalf("a restricted reader saw %d items without an asset", n)
	}
	if counts, _ := repo.ItemCounts(ctx, tn.tenant, receipt, nil); counts["rejected"] != 1 {
		t.Fatalf("counts %v", counts)
	}
	// Another tenant reads nothing of the receipt.
	if _, n, _ := repo.ListItems(ctx, shared.NewID(), receipt, "", nil, pagination.New(1, 100)); n != 0 {
		t.Fatal("another tenant read the receipt's items")
	}

	// An uploader whose scope holds none of the assets: out of scope items,
	// decided by the uploader's scope.
	rep2 := dispReport(tn.repo, dispFinding("py.other", "a", 5))
	out2, err := r.svc.Ingest(ctx, agt, ingest.Input{Report: rep2, Options: ingest.Options{Actor: noAssets{}}})
	if err != nil {
		t.Fatal(err)
	}
	r2, _ := shared.IDFromString(out2.ReceiptID)
	items, _, _ = repo.ListItems(ctx, tn.tenant, r2, ingestreceipt.DispositionOutOfScope, nil, pagination.New(1, 100))
	if len(items) != 1 || items[0].Policy != ingestreceipt.PolicyUploaderScope || items[0].ReasonCode != ingestreceipt.ReasonOutsideScope {
		t.Fatalf("out of scope items = %+v", items)
	}

	// The snapshot is reused while the version holds, reloaded when a
	// policy changes, and the new rule applies at once.
	loads := checker.loads
	if _, err := r.svc.Ingest(ctx, agt, ingest.Input{Report: dispReport(tn.repo, dispFinding("py.cmdi", "a", 9))}); err != nil {
		t.Fatal(err)
	}
	if checker.loads != loads {
		t.Fatalf("rules reloaded at an unchanged version (%d -> %d)", loads, checker.loads)
	}
	if _, err := r.db.ExecContext(ctx, `INSERT INTO suppression_rules (id, tenant_id, name, rule_id, suppression_type, status, approved_at)
		VALUES ($1, $2, 'fp2', 'py.new', 'accepted_risk', 'approved', NOW())`, shared.NewID().String(), tn.tenant.String()); err != nil {
		t.Fatal(err)
	}
	if version() <= v1 {
		t.Fatal("a new rule did not bump the version")
	}
	if _, err := r.svc.Ingest(ctx, agt, ingest.Input{Report: dispReport(tn.repo, dispFinding("py.new", "a", 11))}); err != nil {
		t.Fatal(err)
	}
	if checker.loads != loads+1 {
		t.Fatalf("rules loads %d, want %d after a policy change", checker.loads, loads+1)
	}
	var st string
	_ = r.db.QueryRowContext(ctx, `SELECT status FROM findings WHERE tenant_id = $1 AND rule_id = 'py.new'`, tn.tenant.String()).Scan(&st)
	if st == "new" || st == "" {
		t.Fatalf("the new rule did not apply: %q", st)
	}

	// A snapshot that cannot load fails the ingest before anything is
	// written (it used to turn suppression off for the batch).
	if _, err := r.db.ExecContext(ctx, `UPDATE ingest_policy_versions SET version = version + 1 WHERE tenant_id = $1`, tn.tenant.String()); err != nil {
		t.Fatal(err)
	}
	checker.mu.Lock()
	checker.fail = true
	checker.mu.Unlock()
	before := 0
	_ = r.db.QueryRowContext(ctx, `SELECT count(*) FROM findings WHERE tenant_id = $1`, tn.tenant.String()).Scan(&before)
	if _, err := r.svc.Ingest(ctx, agt, ingest.Input{Report: dispReport(tn.repo, dispFinding("py.md5", "a", 77))}); err == nil {
		t.Fatal("ingest proceeded without its policies")
	}
	after := 0
	_ = r.db.QueryRowContext(ctx, `SELECT count(*) FROM findings WHERE tenant_id = $1`, tn.tenant.String()).Scan(&after)
	if after != before {
		t.Fatalf("an ingest without policies wrote %d findings", after-before)
	}
}

// The automations of new findings are stored as one side-effect job after
// the batch, not started in a goroutine; the worker runs them from the job,
// reading only the job's tenant's findings.
func TestIngest_SideEffectsAreDurable(t *testing.T) {
	var direct int
	var jobs *postgres.IngestJobRepository
	r := newV2RigWith(t, ingest.DefaultBlindingGuard(), func(svc *ingest.Service, db *postgres.DB) {
		jobs = postgres.NewIngestJobRepository(db)
		svc.SetFindingCreatedCallback(func(context.Context, shared.ID, []*vulnerability.Finding) { direct++ })
		svc.SetSideEffectQueue(jobs)
	})
	ctx := context.Background()
	tn, other := r.newTenant(), r.newTenant()
	tid := tn.tenant
	agt := &sensor.Sensor{ID: tn.sensor, TenantID: &tid, Type: sensor.SensorTypeWorker, Status: sensor.SensorStatusActive}
	if _, err := r.svc.Ingest(ctx, agt, ingest.Input{Report: dispReport(tn.repo, dispFinding("py.a", "a", 1), dispFinding("py.b", "a", 2))}); err != nil {
		t.Fatal(err)
	}
	if direct != 0 {
		t.Fatal("side effects ran in the ingest instead of the queue")
	}
	var id string
	if err := r.db.QueryRowContext(ctx, `SELECT id::text FROM ingest_jobs WHERE tenant_id = $1 AND kind = 'side_effects'`, tn.tenant.String()).Scan(&id); err != nil {
		t.Fatalf("no side-effect job: %v", err)
	}
	jid, _ := shared.IDFromString(id)
	job, err := jobs.GetByID(ctx, tn.tenant, jid)
	if err != nil || job.Kind() != ingestjob.KindSideEffects {
		t.Fatalf("job %v %v", job, err)
	}
	var ran []string
	proc := ingest.NewSideEffectProcessor(postgres.NewFindingRepository(&postgres.DB{DB: r.db}),
		func(_ context.Context, tenant shared.ID, fs []*vulnerability.Finding) error {
			for _, f := range fs {
				if f.TenantID() != tenant {
					t.Errorf("a finding of another tenant reached the runner")
				}
				ran = append(ran, f.RuleID())
			}
			return nil
		})
	if _, err := proc.Process(ctx, job); err != nil {
		t.Fatal(err)
	}
	if len(ran) != 2 {
		t.Fatalf("ran %v, want both new findings", ran)
	}
	// The same job filed under another tenant reads none of these findings.
	foreign := ingestjob.FromRow(shared.NewID(), other.tenant, nil, "fx", "side_effects", job.Payload(), make([]byte, 32),
		ingestjob.StatusProcessing, 1, 5, 0, nil, "", "", nil, time.Now(), time.Now(), time.Now())
	ran = nil
	if _, err := proc.Process(ctx, foreign); err != nil {
		t.Fatal(err)
	}
	if len(ran) != 0 {
		t.Fatalf("another tenant's job ran %v", ran)
	}
	// A runner failure fails the job (retried).
	failing := ingest.NewSideEffectProcessor(postgres.NewFindingRepository(&postgres.DB{DB: r.db}),
		func(context.Context, shared.ID, []*vulnerability.Finding) error {
			return errors.New("automations down")
		})
	if _, err := failing.Process(ctx, job); err == nil {
		t.Fatal("a failed run completed the job")
	}
}
