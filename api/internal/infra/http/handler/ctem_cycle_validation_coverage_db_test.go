package handler

import (
	"context"
	"database/sql"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// TestComputeValidationCoverage_CountsValidationEvidence guards the query
// behind the cycle-close coverage SLO gate. It used to join
// pentest_findings.finding_id, a column that does not exist, so it failed on
// every call and the gate always let the cycle close.
func TestComputeValidationCoverage_CountsValidationEvidence(t *testing.T) {
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB-backed handler test")
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

	tenantID := seedHandlerTenant(ctx, t, raw)
	otherTenant := seedHandlerTenant(ctx, t, raw)

	seedFinding := func(tenant, class, status string, withEvidence bool) {
		t.Helper()
		assetID := shared.NewID().String()
		if _, err := raw.ExecContext(ctx,
			`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1,$2,$3,'host')`,
			assetID, tenant, "a-"+assetID); err != nil {
			t.Fatalf("seed asset: %v", err)
		}
		var findingID string
		if err := raw.QueryRowContext(ctx,
			`INSERT INTO findings (tenant_id, asset_id, source, tool_name, message, severity, status, fingerprint, priority_class, resolved_at)
			 VALUES ($1,$2,'sast','tool','msg','high',$3,$4,$5,NOW()) RETURNING id`,
			tenant, assetID, status, "fp-"+assetID, class).Scan(&findingID); err != nil {
			t.Fatalf("seed finding: %v", err)
		}
		if withEvidence {
			if _, err := raw.ExecContext(ctx,
				`INSERT INTO validation_evidence (tenant_id, finding_id, executor_kind, outcome) VALUES ($1,$2,'manual','detected')`,
				tenant, findingID); err != nil {
				t.Fatalf("seed evidence: %v", err)
			}
		}
	}

	seedFinding(tenantID, "P0", "resolved", true)
	seedFinding(tenantID, "P0", "resolved", false)
	seedFinding(tenantID, "P1", "resolved", true)
	seedFinding(tenantID, "P1", "new", true) // not terminal: not counted
	seedFinding(otherTenant, "P0", "resolved", true)

	repo := postgres.NewCTEMCycleMetricsRepository(&postgres.DB{DB: raw})
	h := NewCTEMCycleHandler(raw, repo, logger.NewNop())

	cov, err := h.computeValidationCoverage(ctx, tenantID, "", "")
	if err != nil {
		t.Fatalf("computeValidationCoverage: %v", err)
	}
	if cov.P0Total != 2 || cov.P0WithEvidence != 1 {
		t.Errorf("P0 = %d/%d, want 1/2", cov.P0WithEvidence, cov.P0Total)
	}
	if cov.P1Total != 1 || cov.P1WithEvidence != 1 {
		t.Errorf("P1 = %d/%d, want 1/1 (open findings must not count)", cov.P1WithEvidence, cov.P1Total)
	}
}
