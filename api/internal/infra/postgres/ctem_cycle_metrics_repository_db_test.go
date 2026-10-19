package postgres

import (
	"context"
	"database/sql"
	"math"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/ctemcycle"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// TestCTEMCycleMetricsRepository exercises Compute (over a seeded active
// window), the Upsert→Get roundtrip, and the batch-loaded trend list —
// all against the real app_test schema. Skipped unless DATABASE_URL is
// set.
func TestCTEMCycleMetricsRepository(t *testing.T) {
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB-backed metrics test")
	}
	raw, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer raw.Close()

	ctx := context.Background()
	if err := raw.PingContext(ctx); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}

	tenantID := seedTestTenant(ctx, t, raw)
	assetID := seedTestAsset(ctx, t, raw, tenantID)

	// Active window = [base-10d, base].
	base := time.Now().UTC().Truncate(time.Second)
	activatedAt := base.Add(-10 * 24 * time.Hour)

	var cycleID string
	if err := raw.QueryRowContext(ctx,
		`INSERT INTO ctem_cycles (tenant_id, name, status, created_by, activated_at, closed_at)
		 VALUES ($1, 'metrics cycle', 'closed', $2, $3, $4)
		 RETURNING id`,
		tenantID.String(), shared.NewID().String(), activatedAt, base,
	).Scan(&cycleID); err != nil {
		t.Fatalf("seed cycle: %v", err)
	}

	// Findings. MTTR is mean(resolved_at-created_at) over findings
	// resolved within the window.
	//   A: created -9d, resolved -8d  → 24h,  has evidence
	//   B: created -7d, resolved -5d  → 48h,  no evidence
	//   C: created -6d, unresolved    → opened only
	//   E: created -20d, resolved -4d → 384h, created BEFORE window
	fp := func(s string) string { return "fp-" + cycleID[:8] + "-" + s }
	insertFinding := func(tag, status string, createdOff, resolvedOff time.Duration, resolved bool) string {
		var id string
		var resolvedAt any
		if resolved {
			resolvedAt = base.Add(resolvedOff)
		}
		if err := raw.QueryRowContext(ctx,
			`INSERT INTO findings
			   (tenant_id, asset_id, source, tool_name, message, severity, status, fingerprint, created_at, resolved_at)
			 VALUES ($1,$2,'sast','tool','msg','high',$3,$4,$5,$6)
			 RETURNING id`,
			tenantID.String(), assetID.String(), status, fp(tag),
			base.Add(createdOff), resolvedAt,
		).Scan(&id); err != nil {
			t.Fatalf("seed finding %s: %v", tag, err)
		}
		return id
	}
	findingA := insertFinding("A", "resolved", -9*24*time.Hour, -8*24*time.Hour, true)
	_ = insertFinding("B", "resolved", -7*24*time.Hour, -5*24*time.Hour, true)
	_ = insertFinding("C", "new", -6*24*time.Hour, 0, false)
	_ = insertFinding("E", "resolved", -20*24*time.Hour, -4*24*time.Hour, true)

	// Validation evidence for A only → coverage denominator is the 3
	// findings resolved in window (A,B,E); numerator is 1 → 33.33%.
	if _, err := raw.ExecContext(ctx,
		`INSERT INTO validation_evidence (tenant_id, finding_id, executor_kind, outcome, created_at)
		 VALUES ($1,$2,'test','detected',$3)`,
		tenantID.String(), findingA, base.Add(-8*24*time.Hour),
	); err != nil {
		t.Fatalf("seed evidence: %v", err)
	}

	// Priority-class transitions: 2 inside window, 1 outside.
	insertChurn := func(off time.Duration) {
		if _, err := raw.ExecContext(ctx,
			`INSERT INTO priority_class_audit_log
			   (tenant_id, finding_id, new_class, reason, source, created_at)
			 VALUES ($1,$2,'P1','seed','rule',$3)`,
			tenantID.String(), findingA, base.Add(off),
		); err != nil {
			t.Fatalf("seed churn: %v", err)
		}
	}
	insertChurn(-6 * 24 * time.Hour)
	insertChurn(-3 * 24 * time.Hour)
	insertChurn(-20 * 24 * time.Hour) // outside window

	repo := NewCTEMCycleMetricsRepository(&DB{DB: raw})
	tcid, err := shared.IDFromString(cycleID)
	if err != nil {
		t.Fatalf("parse cycle id: %v", err)
	}

	// --- Compute ---
	set, err := repo.Compute(ctx, tenantID, tcid)
	if err != nil {
		t.Fatalf("compute: %v", err)
	}
	assertMetric(t, set, ctemcycle.MetricFindingsOpened, 3)   // A,B,C created in window
	assertMetric(t, set, ctemcycle.MetricFindingsResolved, 3) // A,B,E resolved in window
	assertMetric(t, set, ctemcycle.MetricMTTRHours, (24+48+384)/3.0)
	assertMetric(t, set, ctemcycle.MetricPClassChurn, 2)
	assertMetric(t, set, ctemcycle.MetricValidationCoverage, 100.0/3.0)
	assertMetric(t, set, ctemcycle.MetricScopeDriftSize, 0)

	// --- Upsert → Get roundtrip ---
	if err := repo.UpsertBatch(ctx, tenantID, tcid, set); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	stored, err := repo.Get(ctx, tenantID, tcid)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(stored) != 8 {
		t.Fatalf("want 8 stored metrics, got %d", len(stored))
	}
	// Upsert is delete-then-insert: a second upsert must not duplicate.
	if err := repo.UpsertBatch(ctx, tenantID, tcid, set); err != nil {
		t.Fatalf("re-upsert: %v", err)
	}
	stored, _ = repo.Get(ctx, tenantID, tcid)
	if len(stored) != 8 {
		t.Fatalf("after re-upsert want 8, got %d (upsert not idempotent)", len(stored))
	}

	// --- Tenant isolation: a foreign tenant sees nothing ---
	other := seedTestTenant(ctx, t, raw)
	foreign, err := repo.Get(ctx, other, tcid)
	if err != nil {
		t.Fatalf("foreign get: %v", err)
	}
	if len(foreign) != 0 {
		t.Fatalf("cross-tenant leak: foreign tenant read %d metrics", len(foreign))
	}
	if err := repo.UpsertBatch(ctx, other, tcid, set); !shared.IsNotFound(err) {
		t.Fatalf("foreign upsert should be ErrNotFound, got %v", err)
	}

	// --- Trend list ---
	cycles, err := repo.ListClosedForTenant(ctx, tenantID)
	if err != nil {
		t.Fatalf("list closed: %v", err)
	}
	if len(cycles) != 1 {
		t.Fatalf("want 1 closed cycle, got %d", len(cycles))
	}
	assertMetric(t, cycles[0].Metrics, ctemcycle.MetricFindingsOpened, 3)
	assertMetric(t, cycles[0].Metrics, ctemcycle.MetricValidationCoverage, 100.0/3.0)
}

func assertMetric(t *testing.T, set map[string]float64, key string, want float64) {
	t.Helper()
	got, ok := set[key]
	if !ok {
		t.Errorf("metric %s missing", key)
		return
	}
	if math.Abs(got-want) > 0.01 {
		t.Errorf("metric %s = %.4f, want %.4f", key, got, want)
	}
}

// TestCTEMCycleMetrics_DispositionsAreNotFixes: a cycle whose only closures
// are a false positive and an accepted risk remediated nothing. MTTR and
// validation coverage have no sample (left out, so a charter criterion on
// MTTR reads not_measurable instead of passing with 0 h), and nothing counts
// as resolved. Cross-tenant: another tenant's real fix in the same window
// is not counted.
func TestCTEMCycleMetrics_DispositionsAreNotFixes(t *testing.T) {
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB-backed metrics test")
	}
	raw, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer raw.Close()
	ctx := context.Background()
	if err := raw.PingContext(ctx); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}

	tenantID := seedTestTenant(ctx, t, raw)
	assetID := seedTestAsset(ctx, t, raw, tenantID)
	otherTenant := seedTestTenant(ctx, t, raw)
	otherAsset := seedTestAsset(ctx, t, raw, otherTenant)

	base := time.Now().UTC().Truncate(time.Second)
	var cycleID string
	if err := raw.QueryRowContext(ctx,
		`INSERT INTO ctem_cycles (tenant_id, name, status, created_by, activated_at, closed_at)
		 VALUES ($1, 'dispositions only', 'closed', $2, $3, $4) RETURNING id`,
		tenantID.String(), shared.NewID().String(), base.Add(-10*24*time.Hour), base,
	).Scan(&cycleID); err != nil {
		t.Fatalf("seed cycle: %v", err)
	}
	insert := func(tenant, asset shared.ID, tag, status string) {
		if _, err := raw.ExecContext(ctx,
			`INSERT INTO findings
			   (tenant_id, asset_id, source, tool_name, message, severity, status, fingerprint, created_at, resolved_at)
			 VALUES ($1,$2,'sast','tool','msg','high',$3,$4,$5,$6)`,
			tenant.String(), asset.String(), status, "fp-disp-"+cycleID[:8]+"-"+tag,
			base.Add(-9*24*time.Hour), base.Add(-8*24*time.Hour),
		); err != nil {
			t.Fatalf("seed finding %s: %v", tag, err)
		}
	}
	insert(tenantID, assetID, "fp", "false_positive")
	insert(tenantID, assetID, "acc", "accepted")
	insert(otherTenant, otherAsset, "other-fixed", "resolved")

	cid, err := shared.IDFromString(cycleID)
	if err != nil {
		t.Fatal(err)
	}
	set, err := NewCTEMCycleMetricsRepository(&DB{DB: raw}).Compute(ctx, tenantID, cid)
	if err != nil {
		t.Fatalf("compute: %v", err)
	}
	if v, ok := set[ctemcycle.MetricMTTRHours]; ok {
		t.Fatalf("mttr_hours = %v, want no value (nothing remediated)", v)
	}
	if v, ok := set[ctemcycle.MetricValidationCoverage]; ok {
		t.Fatalf("validation_coverage = %v, want no value (nothing remediated)", v)
	}
	assertMetric(t, set, ctemcycle.MetricFindingsResolved, 0)
	assertMetric(t, set, ctemcycle.MetricFindingsOpened, 2)

	ev := ctemcycle.EvaluateCriterion(ctemcycle.CharterSuccessCriterion{Name: "fix fast", Metric: "MTTR", Target: "< 72h"}, set)
	if ev.Outcome != ctemcycle.CriterionNotMeasurable {
		t.Fatalf("MTTR criterion outcome = %s, want not_measurable", ev.Outcome)
	}
}
