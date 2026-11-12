package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/ctemcycle"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func openCharterEvalDB(t *testing.T) *sql.DB {
	t.Helper()
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB-backed charter evaluation test")
	}
	raw, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	if err := raw.PingContext(context.Background()); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}
	return raw
}

// TestCTEMCycleMetrics_CharterMetrics covers the metrics added so charter
// criteria have something real to be checked against: P0/P1 resolved in the
// window, and the risk-snapshot metrics (risk before/after/reduction, open
// P0/P1 at close).
func TestCTEMCycleMetrics_CharterMetrics(t *testing.T) {
	raw := openCharterEvalDB(t)
	ctx := context.Background()

	tenantID := seedTestTenant(ctx, t, raw)
	assetID := seedTestAsset(ctx, t, raw, tenantID)

	base := time.Now().UTC().Truncate(time.Second)
	activatedAt := base.Add(-10 * 24 * time.Hour)

	var cycleID string
	if err := raw.QueryRowContext(ctx,
		`INSERT INTO ctem_cycles (tenant_id, name, status, created_by, activated_at, closed_at)
		 VALUES ($1, 'charter metrics cycle', 'closed', $2, $3, $4) RETURNING id`,
		tenantID.String(), shared.NewID().String(), activatedAt, base,
	).Scan(&cycleID); err != nil {
		t.Fatalf("seed cycle: %v", err)
	}

	insert := func(tag, class string, resolvedOff time.Duration) {
		if _, err := raw.ExecContext(ctx,
			`INSERT INTO findings
			   (tenant_id, asset_id, source, tool_name, message, severity, status,
			    fingerprint, created_at, resolved_at, priority_class)
			 VALUES ($1,$2,'sast','tool','msg','high','resolved',$3,$4,$5,$6)`,
			tenantID.String(), assetID.String(), "fp-"+cycleID[:8]+"-"+tag,
			base.Add(-9*24*time.Hour), base.Add(resolvedOff), class,
		); err != nil {
			t.Fatalf("seed finding %s: %v", tag, err)
		}
	}
	insert("p0a", "P0", -5*24*time.Hour)
	insert("p0b", "P0", -2*24*time.Hour)
	insert("p1a", "P1", -3*24*time.Hour)
	insert("p2a", "P2", -3*24*time.Hour)
	insert("p0-outside", "P0", -20*24*time.Hour) // resolved before the window

	snapshot := func(day time.Time, risk float64, p0, p1 int) {
		if _, err := raw.ExecContext(ctx,
			`INSERT INTO risk_snapshots (tenant_id, snapshot_date, risk_score_avg, p0_open, p1_open)
			 VALUES ($1, $2::date, $3, $4, $5)`,
			tenantID.String(), day.Format("2006-01-02"), risk, p0, p1,
		); err != nil {
			t.Fatalf("seed risk snapshot: %v", err)
		}
	}
	snapshot(activatedAt.Add(-3*24*time.Hour), 90, 9, 9) // older: must not be picked
	snapshot(activatedAt.Add(-24*time.Hour), 80, 3, 4)   // latest on/before start
	snapshot(base.Add(-24*time.Hour), 60, 0, 2)          // latest on/before close

	repo := NewCTEMCycleMetricsRepository(&DB{DB: raw})
	cid, _ := shared.IDFromString(cycleID)

	set, err := repo.Compute(ctx, tenantID, cid)
	if err != nil {
		t.Fatalf("compute: %v", err)
	}
	assertMetric(t, set, ctemcycle.MetricP0Resolved, 2)
	assertMetric(t, set, ctemcycle.MetricP1Resolved, 1)
	assertMetric(t, set, ctemcycle.MetricRiskBefore, 80)
	assertMetric(t, set, ctemcycle.MetricRiskAfter, 60)
	assertMetric(t, set, ctemcycle.MetricRiskReductionPct, 25)
	assertMetric(t, set, ctemcycle.MetricP0OpenAtClose, 0)
	assertMetric(t, set, ctemcycle.MetricP1OpenAtClose, 2)

	// Another tenant's snapshots must never feed this tenant's cycle.
	other := seedTestTenant(ctx, t, raw)
	if _, err := raw.ExecContext(ctx,
		`INSERT INTO risk_snapshots (tenant_id, snapshot_date, risk_score_avg, p0_open, p1_open)
		 VALUES ($1, $2::date, 1, 99, 99)`,
		other.String(), base.Format("2006-01-02"),
	); err != nil {
		t.Fatalf("seed foreign snapshot: %v", err)
	}
	set, err = repo.Compute(ctx, tenantID, cid)
	if err != nil {
		t.Fatalf("recompute: %v", err)
	}
	assertMetric(t, set, ctemcycle.MetricP0OpenAtClose, 0)
	assertMetric(t, set, ctemcycle.MetricRiskAfter, 60)
}

// Without a snapshot on/before the window start, risk before/after/reduction
// are absent (so a risk criterion is "not measurable"), never a fake 0.
func TestCTEMCycleMetrics_NoBaselineSnapshot(t *testing.T) {
	raw := openCharterEvalDB(t)
	ctx := context.Background()
	tenantID := seedTestTenant(ctx, t, raw)

	base := time.Now().UTC().Truncate(time.Second)
	var cycleID string
	if err := raw.QueryRowContext(ctx,
		`INSERT INTO ctem_cycles (tenant_id, name, status, created_by, activated_at, closed_at)
		 VALUES ($1, 'no baseline', 'closed', $2, $3, $4) RETURNING id`,
		tenantID.String(), shared.NewID().String(), base.Add(-10*24*time.Hour), base,
	).Scan(&cycleID); err != nil {
		t.Fatalf("seed cycle: %v", err)
	}
	// Only a snapshot inside the window.
	if _, err := raw.ExecContext(ctx,
		`INSERT INTO risk_snapshots (tenant_id, snapshot_date, risk_score_avg, p0_open, p1_open)
		 VALUES ($1, $2::date, 50, 1, 0)`,
		tenantID.String(), base.Add(-2*24*time.Hour).Format("2006-01-02"),
	); err != nil {
		t.Fatalf("seed snapshot: %v", err)
	}

	repo := NewCTEMCycleMetricsRepository(&DB{DB: raw})
	cid, _ := shared.IDFromString(cycleID)
	set, err := repo.Compute(ctx, tenantID, cid)
	if err != nil {
		t.Fatalf("compute: %v", err)
	}
	for _, k := range []string{ctemcycle.MetricRiskBefore, ctemcycle.MetricRiskAfter, ctemcycle.MetricRiskReductionPct} {
		if _, ok := set[k]; ok {
			t.Errorf("%s must be absent without a baseline snapshot, got %v", k, set[k])
		}
	}
	assertMetric(t, set, ctemcycle.MetricP0OpenAtClose, 1)
}

// TestCTEMCycleCharterEvaluation_TenantIsolation proves the criteria read and
// the evaluation write are scoped by tenant_id.
func TestCTEMCycleCharterEvaluation_TenantIsolation(t *testing.T) {
	raw := openCharterEvalDB(t)
	ctx := context.Background()
	tenantID := seedTestTenant(ctx, t, raw)
	other := seedTestTenant(ctx, t, raw)

	charter := `{"success_criteria":[
		{"name":"P0","metric":"P0 resolved","target":">= 1"},
		{"name":"KEV","metric":"open KEV findings","target":"0"}]}`
	var cycleID string
	if err := raw.QueryRowContext(ctx,
		`INSERT INTO ctem_cycles (tenant_id, name, status, created_by, charter)
		 VALUES ($1, 'iso cycle', 'closed', $2, $3::jsonb) RETURNING id`,
		tenantID.String(), shared.NewID().String(), charter,
	).Scan(&cycleID); err != nil {
		t.Fatalf("seed cycle: %v", err)
	}
	repo := NewCTEMCycleMetricsRepository(&DB{DB: raw})
	cid, _ := shared.IDFromString(cycleID)

	crit, err := repo.GetSuccessCriteria(ctx, tenantID, cid)
	if err != nil {
		t.Fatalf("get criteria: %v", err)
	}
	if len(crit) != 2 || crit[0].Metric != "P0 resolved" {
		t.Fatalf("criteria = %+v", crit)
	}
	if _, err := repo.GetSuccessCriteria(ctx, other, cid); !shared.IsNotFound(err) {
		t.Fatalf("foreign tenant read criteria: err=%v, want ErrNotFound", err)
	}

	ev := ctemcycle.EvaluateCharter(crit, ctemcycle.CycleMetricSet{ctemcycle.MetricP0Resolved: 3}, time.Now())

	// Foreign write: rejected and nothing stored.
	if err := repo.SaveCharterEvaluation(ctx, other, cid, ev); !shared.IsNotFound(err) {
		t.Fatalf("foreign save: err=%v, want ErrNotFound", err)
	}
	var stored sql.NullString
	if err := raw.QueryRowContext(ctx,
		`SELECT charter_evaluation::text FROM ctem_cycles WHERE id = $1`, cycleID,
	).Scan(&stored); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if stored.Valid {
		t.Fatalf("foreign tenant wrote an evaluation: %s", stored.String)
	}

	// Owner write roundtrips.
	if err := repo.SaveCharterEvaluation(ctx, tenantID, cid, ev); err != nil {
		t.Fatalf("save: %v", err)
	}
	if err := raw.QueryRowContext(ctx,
		`SELECT charter_evaluation::text FROM ctem_cycles WHERE id = $1 AND tenant_id = $2`,
		cycleID, tenantID.String(),
	).Scan(&stored); err != nil {
		t.Fatalf("read back: %v", err)
	}
	var got ctemcycle.CharterEvaluation
	if err := json.Unmarshal([]byte(stored.String), &got); err != nil {
		t.Fatalf("decode stored evaluation: %v", err)
	}
	if got.Met != 1 || got.NotMeasurable != 1 || got.CompletionRate == nil || *got.CompletionRate != 100 {
		t.Fatalf("stored evaluation = %+v", got)
	}
	if got.Criteria[0].Outcome != ctemcycle.CriterionMet || got.Criteria[0].Actual == nil || *got.Criteria[0].Actual != 3 {
		t.Fatalf("criterion 0 = %+v", got.Criteria[0])
	}
}
