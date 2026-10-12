package postgres

import (
	"context"
	"database/sql"
	"testing"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// TestEscalateKEVFindings_FlagsAndEscalates proves the KEV reconciliation pass
// against the real schema:
//
//   - a non-critical KEV finding is escalated to critical AND flagged is_in_kev.
//   - an ALREADY-critical KEV finding with is_in_kev=false is STILL flagged
//     (proves the flag is not severity-gated — the historical bug).
//   - a terminal-status (accepted) KEV finding is left untouched.
//   - the tenant appears in the returned touched-tenant set.
//
// Skipped unless DATABASE_URL is set.
func TestEscalateKEVFindings_FlagsAndEscalates(t *testing.T) {
	dbURL := testdb.URL()
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

	// Unique CVE seeded into the KEV catalog for this test. kev_catalog is
	// global (not tenant-scoped), so clean it up explicitly.
	kevCVE := "CVE-2099-" + shortSuffix(tenantID)
	seedKEVCatalog(ctx, t, db, kevCVE)

	nonCritical := seedKEVTestFinding(ctx, t, db, tenantID, assetID, "high", "new", kevCVE, false)
	alreadyCritical := seedKEVTestFinding(ctx, t, db, tenantID, assetID, "critical", "confirmed", kevCVE, false)
	terminal := seedKEVTestFinding(ctx, t, db, tenantID, assetID, "high", "accepted", kevCVE, false)

	esc := NewKEVEscalator(&DB{DB: db})
	res, err := esc.EscalateKEVFindings(ctx)
	if err != nil {
		t.Fatalf("EscalateKEVFindings: %v", err)
	}

	// Non-critical KEV finding: escalated + flagged.
	if sev, kev := readFinding(ctx, t, db, nonCritical); sev != "critical" || !kev {
		t.Errorf("non-critical KEV finding: got severity=%q is_in_kev=%v, want critical/true", sev, kev)
	}

	// Already-critical KEV finding: flag set even though escalation skips it.
	if sev, kev := readFinding(ctx, t, db, alreadyCritical); sev != "critical" || !kev {
		t.Errorf("already-critical KEV finding: got severity=%q is_in_kev=%v, want critical/true (flag must not be severity-gated)", sev, kev)
	}

	// Terminal-status KEV finding: untouched.
	if sev, kev := readFinding(ctx, t, db, terminal); sev != "high" || kev {
		t.Errorf("terminal KEV finding: got severity=%q is_in_kev=%v, want high/false (must not be touched)", sev, kev)
	}

	// The tenant must appear in the touched set (cross-tenant call, so other
	// tenants may also be present — assert membership, not exact count).
	if !containsTenant(res.Tenants, tenantID) {
		t.Errorf("touched tenants %v does not include %s", res.Tenants, tenantID)
	}
}

func seedKEVCatalog(ctx context.Context, t *testing.T, db *sql.DB, cve string) {
	t.Helper()
	_, err := db.ExecContext(ctx,
		`INSERT INTO kev_catalog (cve_id, vulnerability_name, date_added)
		 VALUES ($1, $2, NOW()) ON CONFLICT (cve_id) DO NOTHING`,
		cve, "kev-escalation-test")
	if err != nil {
		t.Fatalf("seed kev_catalog: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM kev_catalog WHERE cve_id = $1`, cve)
	})
}

func seedKEVTestFinding(ctx context.Context, t *testing.T, db *sql.DB, tenantID, assetID shared.ID, severity, status, cve string, isInKEV bool) shared.ID {
	t.Helper()
	id := shared.NewID()
	_, err := db.ExecContext(ctx,
		`INSERT INTO findings
		   (id, tenant_id, asset_id, source, tool_name, message, severity, status, fingerprint, cve_id, is_in_kev)
		 VALUES ($1, $2, $3, 'sca', 'kev-test', 'kev escalation probe', $4, $5, $6, $7, $8)`,
		id.String(), tenantID.String(), assetID.String(), severity, status,
		"kev-fp-"+id.String(), cve, isInKEV)
	if err != nil {
		t.Fatalf("seed finding: %v", err)
	}
	// Cleaned up via the tenant cascade.
	return id
}

func readFinding(ctx context.Context, t *testing.T, db *sql.DB, id shared.ID) (severity string, isInKEV bool) {
	t.Helper()
	err := db.QueryRowContext(ctx,
		`SELECT severity, is_in_kev FROM findings WHERE id = $1`, id.String()).
		Scan(&severity, &isInKEV)
	if err != nil {
		t.Fatalf("read finding %s: %v", id, err)
	}
	return severity, isInKEV
}

func containsTenant(tenants []shared.ID, want shared.ID) bool {
	for _, tid := range tenants {
		if tid.Equals(want) {
			return true
		}
	}
	return false
}

// shortSuffix derives a short digits-only suffix from an ID so the synthetic CVE
// fits findings.cve_id (VARCHAR(20)) and stays unique per test run.
func shortSuffix(id shared.ID) string {
	s := id.String()
	out := make([]rune, 0, 6)
	for _, r := range s {
		if r >= '0' && r <= '9' {
			out = append(out, r)
			if len(out) == 6 {
				break
			}
		}
	}
	if len(out) == 0 {
		return "000000"
	}
	return string(out)
}

// TestEscalateKEVFindings_UnflagsCVEThatLeftKEV: a CVE CISA removed from KEV
// (the sync prunes it from kev_catalog) must stop being flagged on findings.
// Before the fix the flag was only ever set false→true, so a removed CVE kept
// is_in_kev=true and its KEV due date forever, on every status.
func TestEscalateKEVFindings_UnflagsCVEThatLeftKEV(t *testing.T) {
	dbURL := testdb.URL()
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

	stillKEV := "CVE-2098-" + shortSuffix(tenantID)
	seedKEVCatalog(ctx, t, db, stillKEV)
	leftKEV := "CVE-2097-" + shortSuffix(tenantID) // never in kev_catalog

	keep := seedKEVTestFinding(ctx, t, db, tenantID, assetID, "critical", "new", stillKEV, true)
	openGone := seedKEVTestFinding(ctx, t, db, tenantID, assetID, "critical", "new", leftKEV, true)
	resolvedGone := seedKEVTestFinding(ctx, t, db, tenantID, assetID, "critical", "resolved", leftKEV, true)
	if _, err := db.ExecContext(ctx, `UPDATE findings SET kev_due_date = CURRENT_DATE WHERE id = ANY($1)`,
		pq.Array([]string{keep.String(), openGone.String(), resolvedGone.String()})); err != nil {
		t.Fatalf("set due dates: %v", err)
	}

	res, err := NewKEVEscalator(&DB{DB: db}).EscalateKEVFindings(ctx)
	if err != nil {
		t.Fatalf("EscalateKEVFindings: %v", err)
	}

	hasDue := func(id shared.ID) bool {
		var due sql.NullTime
		if err := db.QueryRowContext(ctx, `SELECT kev_due_date FROM findings WHERE id = $1`, id.String()).Scan(&due); err != nil {
			t.Fatalf("read due: %v", err)
		}
		return due.Valid
	}
	if _, kev := readFinding(ctx, t, db, keep); !kev || !hasDue(keep) {
		t.Errorf("finding still in KEV: is_in_kev=%v due=%v, want true/true", kev, hasDue(keep))
	}
	for name, id := range map[string]shared.ID{"open": openGone, "resolved": resolvedGone} {
		sev, kev := readFinding(ctx, t, db, id)
		if kev || hasDue(id) {
			t.Errorf("%s finding whose CVE left KEV: is_in_kev=%v due=%v, want false/false", name, kev, hasDue(id))
		}
		if sev != "critical" {
			t.Errorf("%s finding: severity=%q, want critical (never lowered)", name, sev)
		}
	}
	if res.Unflagged < 2 {
		t.Errorf("Unflagged=%d, want >= 2", res.Unflagged)
	}
	if !containsTenant(res.Tenants, tenantID) {
		t.Errorf("touched tenants %v does not include %s", res.Tenants, tenantID)
	}
}
