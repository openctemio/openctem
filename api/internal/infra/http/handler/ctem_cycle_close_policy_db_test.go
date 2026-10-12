package handler

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// stubCyclePolicy answers per tenant; a tenant not in the map gets the
// default (advisory) policy.
type stubCyclePolicy struct {
	enforce map[string]bool
	err     error
	asked   []string
}

func (s *stubCyclePolicy) GetCycleSettings(_ context.Context, tenantID string) (*tenant.CycleSettings, error) {
	s.asked = append(s.asked, tenantID)
	if s.err != nil {
		return nil, s.err
	}
	return &tenant.CycleSettings{EnforceCoverageSLO: s.enforce[tenantID]}, nil
}

// seedReviewCycleBelowSLO seeds a cycle in review with one resolved P0
// finding that has no validation evidence: P0 coverage 0%, below the SLO.
func seedReviewCycleBelowSLO(ctx context.Context, t *testing.T, db *sql.DB, tenantID string) string {
	t.Helper()
	assetID := shared.NewID().String()
	if _, err := db.ExecContext(ctx,
		`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1,$2,'a','host')`,
		assetID, tenantID); err != nil {
		t.Fatalf("seed asset: %v", err)
	}
	base := time.Now().UTC().Truncate(time.Second)
	var cycleID string
	if err := db.QueryRowContext(ctx,
		`INSERT INTO ctem_cycles (tenant_id, name, status, created_by, activated_at, charter)
		 VALUES ($1,'slo cycle','review',$2,$3,'{}'::jsonb) RETURNING id`,
		tenantID, shared.NewID().String(), base.Add(-10*24*time.Hour),
	).Scan(&cycleID); err != nil {
		t.Fatalf("seed cycle: %v", err)
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO findings
		   (tenant_id, asset_id, source, tool_name, message, severity, status,
		    fingerprint, created_at, resolved_at, priority_class)
		 VALUES ($1,$2,'sast','tool','msg','critical','resolved',$3,$4,$5,'P0')`,
		tenantID, assetID, "fp-slo-"+cycleID,
		base.Add(-6*24*time.Hour), base.Add(-3*24*time.Hour)); err != nil {
		t.Fatalf("seed finding: %v", err)
	}
	return cycleID
}

// The coverage SLO gate on closing a cycle is the organization's own policy:
// an organization that requires it cannot close a cycle below the SLO, while
// another organization's choice never applies to it, and a policy that cannot
// be read does not let the cycle close.
func TestCTEMCycleHandler_ClosePolicyIsPerOrganization(t *testing.T) {
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
	repo := postgres.NewCTEMCycleMetricsRepository(&postgres.DB{DB: raw})

	strict := seedHandlerTenant(ctx, t, raw)
	lenient := seedHandlerTenant(ctx, t, raw)
	strictCycle := seedReviewCycleBelowSLO(ctx, t, raw, strict)
	lenientCycle := seedReviewCycleBelowSLO(ctx, t, raw, lenient)

	policy := &stubCyclePolicy{enforce: map[string]bool{strict: true}}
	h := NewCTEMCycleHandler(raw, repo, logger.NewNop()).WithCyclePolicy(policy)

	close := func(tenantID, cycleID string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.Close(w, cycleRequest(http.MethodPost, "/api/v1/ctem-cycles/"+cycleID+"/close", tenantID, cycleID))
		return w
	}

	if w := close(strict, strictCycle); w.Code != http.StatusBadRequest {
		t.Fatalf("enforcing organization below the SLO: status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	var status string
	if err := raw.QueryRowContext(ctx, `SELECT status FROM ctem_cycles WHERE id=$1`, strictCycle).Scan(&status); err != nil || status != "review" {
		t.Fatalf("refused cycle status = %q (%v), want still review", status, err)
	}

	// The strict organization's policy does not leak to another organization.
	if w := close(lenient, lenientCycle); w.Code != http.StatusOK {
		t.Fatalf("advisory organization below the SLO: status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	for _, asked := range policy.asked {
		if asked != strict && asked != lenient {
			t.Fatalf("policy read for an unexpected tenant %q", asked)
		}
	}
	if len(policy.asked) != 2 || policy.asked[0] != strict || policy.asked[1] != lenient {
		t.Fatalf("policy reads = %v, want each organization's own", policy.asked)
	}

	// An unreadable policy fails closed.
	h.WithCyclePolicy(&stubCyclePolicy{err: errors.New("db down")})
	if w := close(strict, strictCycle); w.Code != http.StatusInternalServerError {
		t.Fatalf("unreadable policy: status = %d, want 500", w.Code)
	}
}
