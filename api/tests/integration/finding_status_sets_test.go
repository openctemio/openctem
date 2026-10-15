package integration

import (
	"context"
	"database/sql"
	"testing"

	"github.com/openctemio/openctem/api/internal/infra/controller"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// The SQL definition of an open finding (is_open_finding_status) is the Go one,
// status for status.
func TestFindingStatusSets_SQLMatchesGo(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	for _, st := range vulnerability.AllFindingStatuses() {
		var open bool
		if err := db.QueryRow(`SELECT is_open_finding_status($1)`, string(st)).Scan(&open); err != nil {
			t.Fatalf("is_open_finding_status(%s): %v", st, err)
		}
		if open != vulnerability.IsOpenStatus(st) {
			t.Errorf("status %s: SQL open=%v, Go open=%v", st, open, vulnerability.IsOpenStatus(st))
		}
	}
}

// One fixture, one answer: a tenant with one finding in every status. Every
// consumer that asks "open?" or "fixed?" counts the same findings, a
// disposition is never closed today as a fix nor part of MTTR, and another
// tenant's findings never leak into the counts.
func TestFindingStatusSets_ConsumersAgree(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()
	tenant := createTestTenant(t, db, "status-sets")
	other := createTestTenant(t, db, "status-sets-other")
	t.Cleanup(func() {
		for _, id := range []shared.ID{tenant, other} {
			_, _ = db.Exec(`DELETE FROM tenants WHERE id = $1`, id.String())
		}
		_ = db.Close()
	})
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("%v\n%s", err, q)
		}
	}
	newAsset := func(tid shared.ID) shared.ID {
		id := shared.NewID()
		exec(`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, $3, 'host')`,
			id.String(), tid.String(), "ss-"+id.String())
		return id
	}
	assetID := newAsset(tenant)
	otherAsset := newAsset(other)
	// The canonical finding the duplicate names: resolved long ago, so it is
	// in none of the counts below.
	canonical := shared.NewID()
	exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status)
		VALUES ($1, $2, $3, 'sast', 'ss-tool', 'm', 'high', $4, 'resolved')`,
		canonical.String(), tenant.String(), assetID.String(), "ss-canonical-"+canonical.String())
	// Every status on the tenant's asset; the closed ones closed today.
	for _, st := range vulnerability.AllFindingStatuses() {
		source := "sast"
		if st == vulnerability.FindingStatusDraft || st == vulnerability.FindingStatusInReview {
			source = "pentest"
		}
		closedToday := !vulnerability.IsOpenStatus(st) && st != vulnerability.FindingStatusDraft && st != vulnerability.FindingStatusInReview
		var dupOf any
		if st == vulnerability.FindingStatusDuplicate {
			dupOf = canonical.String()
		}
		id := shared.NewID()
		exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status,
				priority_class, first_detected_at, resolved_at, duplicate_of)
			VALUES ($1, $2, $3, $4, 'ss-tool', 'm', 'high', $5, $6, 'P1', NOW() - INTERVAL '10 hours',
				CASE WHEN $7 THEN NOW() END, $8)`,
			id.String(), tenant.String(), assetID.String(), source, "ss-"+id.String(), string(st), closedToday, dupOf)
	}
	// Another tenant's open finding never counts for this one.
	exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status)
		VALUES ($1, $2, $3, 'sast', 'ss-tool', 'm', 'high', $4, 'new')`,
		shared.NewID().String(), other.String(), otherAsset.String(), "ss-other-"+otherAsset.String())

	wantOpen := len(vulnerability.OpenStatuses()) // 6: draft and in_review are not published

	// Risk snapshot: open and P1 open are the open set; closed today and MTTR
	// count only the fix (resolved), never the three dispositions.
	if _, err := controller.NewRiskSnapshotController(db, logger.NewNop()).Reconcile(ctx); err != nil {
		t.Fatalf("risk snapshot: %v", err)
	}
	var open, p1, closedToday int
	var mttrHigh sql.NullFloat64
	if err := db.QueryRow(`SELECT findings_open, p1_open, findings_closed_today, mttr_high_hours
		FROM risk_snapshots WHERE tenant_id = $1 AND snapshot_date = CURRENT_DATE`, tenant.String()).
		Scan(&open, &p1, &closedToday, &mttrHigh); err != nil {
		t.Fatalf("read snapshot: %v", err)
	}
	if open != wantOpen || p1 != wantOpen {
		t.Errorf("snapshot open=%d p1=%d, want %d (the open set)", open, p1, wantOpen)
	}
	if closedToday != 1 {
		t.Errorf("snapshot closed_today = %d, want 1 (only the fix; dispositions are not remediated)", closedToday)
	}
	if !mttrHigh.Valid || mttrHigh.Float64 < 9.9 || mttrHigh.Float64 > 10.1 {
		t.Errorf("snapshot mttr_high = %v, want about 10h from the one fix", mttrHigh)
	}

	// Asset finding count and the has-findings filter: the open set.
	a, err := postgres.NewAssetRepository(&postgres.DB{DB: db}).GetByID(ctx, tenant, assetID)
	if err != nil {
		t.Fatalf("asset: %v", err)
	}
	if a.FindingCount() != wantOpen {
		t.Errorf("asset finding_count = %d, want %d (FP, accepted, duplicate and drafts are not open)", a.FindingCount(), wantOpen)
	}
	otherA, err := postgres.NewAssetRepository(&postgres.DB{DB: db}).GetByID(ctx, other, otherAsset)
	if err != nil {
		t.Fatalf("other asset: %v", err)
	}
	if otherA.FindingCount() != 1 {
		t.Errorf("other tenant's asset finding_count = %d, want 1", otherA.FindingCount())
	}

	// Open findings of the asset (used by the asset detail and risk inputs).
	n, err := postgres.NewFindingRepository(&postgres.DB{DB: db}).CountOpenByAssetID(ctx, tenant, assetID)
	if err != nil {
		t.Fatalf("count open by asset: %v", err)
	}
	if int(n) != wantOpen {
		t.Errorf("CountOpenByAssetID = %d, want %d", n, wantOpen)
	}
}
