package postgres

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/pagination"
)

// The findings list gained a server-side sla_status filter so the SLA breach
// board can ask for sla_status IN ('overdue','exceeded') directly instead of
// scoring one capped page in the client. buildWhereClause is pure, so the SQL
// shape is asserted here without a DB.
func TestBuildWhereClause_SLAStatusFilter(t *testing.T) {
	r := &FindingRepository{}

	f := vulnerability.NewFindingFilter().
		WithSLAStatuses(vulnerability.SLAStatusOverdue, vulnerability.SLAStatusExceeded)

	where, args := r.buildWhereClause(f)

	if !strings.Contains(where, "sla_status = ANY($1)") {
		t.Errorf("WHERE missing sla_status = ANY clause\nfull: %s", where)
	}
	// The whole set is bound as a single array arg.
	if len(args) != 1 {
		t.Fatalf("expected 1 bound arg (the status array), got %d: %#v", len(args), args)
	}
}

// An unset SLA filter must not emit a sla_status predicate (no accidental
// always-on clause that would silently drop rows).
func TestBuildWhereClause_NoSLAStatusWhenUnset(t *testing.T) {
	r := &FindingRepository{}
	where, _ := r.buildWhereClause(vulnerability.NewFindingFilter())
	if strings.Contains(where, "sla_status") {
		t.Errorf("unset SLA filter leaked clause: %s", where)
	}
}

// TestList_SLAStatusFilter proves the filter actually selects rows against the
// real schema: a finding with sla_status='overdue' is returned for the breach
// board's ?sla_status=overdue,exceeded query, and an 'on_track' finding is not.
// Skipped unless DATABASE_URL is set (runs in CI, which provisions Postgres).
func TestList_SLAStatusFilter(t *testing.T) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB execution check")
	}

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer func() { _ = db.Close() }()

	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}

	tenantID := seedTestTenant(ctx, t, db)
	assetID := seedTestAsset(ctx, t, db, tenantID)

	overdueID := seedSLATestFinding(ctx, t, db, tenantID, assetID, "overdue")
	exceededID := seedSLATestFinding(ctx, t, db, tenantID, assetID, "exceeded")
	onTrackID := seedSLATestFinding(ctx, t, db, tenantID, assetID, "on_track")

	repo := NewFindingRepository(&DB{DB: db})

	filter := vulnerability.NewFindingFilter().
		WithTenantID(tenantID).
		WithSLAStatuses(vulnerability.SLAStatusOverdue, vulnerability.SLAStatusExceeded)

	res, err := repo.List(ctx, filter, vulnerability.NewFindingListOptions(), pagination.New(1, 100))
	if err != nil {
		t.Fatalf("List: %v", err)
	}

	got := make(map[string]bool, len(res.Data))
	for _, f := range res.Data {
		got[f.ID().String()] = true
	}

	if !got[overdueID.String()] {
		t.Errorf("overdue finding %s missing from breach-board results", overdueID)
	}
	if !got[exceededID.String()] {
		t.Errorf("exceeded finding %s missing from breach-board results", exceededID)
	}
	if got[onTrackID.String()] {
		t.Errorf("on_track finding %s must be excluded by ?sla_status=overdue,exceeded", onTrackID)
	}
}

func seedSLATestFinding(ctx context.Context, t *testing.T, db *sql.DB, tenantID, assetID shared.ID, slaStatus string) shared.ID {
	t.Helper()
	id := shared.NewID()
	_, err := db.ExecContext(ctx,
		`INSERT INTO findings
		   (id, tenant_id, asset_id, source, tool_name, message, severity, status, fingerprint, sla_status)
		 VALUES ($1, $2, $3, 'sca', 'sla-test', 'sla filter probe', 'high', 'new', $4, $5)`,
		id.String(), tenantID.String(), assetID.String(), "sla-fp-"+id.String(), slaStatus)
	if err != nil {
		t.Fatalf("seed finding: %v", err)
	}
	// Cleaned up via the tenant cascade.
	return id
}
