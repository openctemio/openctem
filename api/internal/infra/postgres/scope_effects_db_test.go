package postgres

import (
	"context"
	"database/sql"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Scope effects (research/320) on the real schema: a permanent not_ours or
// retired exclusion in effect, or a "not ours" decision, closes the open
// findings of the assets it matches as resolved / out_of_scope with a
// timeline entry; do_not_scan, temporary, pending exclusions and other
// tenants' exclusions close nothing; taking the exclusion out of effect (or
// changing its kind) reopens exactly those findings to their old status,
// never as a regression. Requires DATABASE_URL.
func TestScopeEffects(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	pg := &DB{DB: db}
	repo := NewScopeEffectsRepository(pg)
	attr := NewAttributionRepository(pg)
	tenant := seedTestTenant(ctx, t, db)
	other := seedTestTenant(ctx, t, db)

	asset := func(tid shared.ID, name, typ string) string {
		t.Helper()
		id := shared.NewID().String()
		mustExec(t, db, `INSERT INTO assets (id, tenant_id, name, asset_type, status) VALUES ($1, $2, $3, $4, 'active')`,
			id, tid.String(), name, typ)
		return id
	}
	finding := func(tid shared.ID, assetID, status string) string {
		t.Helper()
		id := shared.NewID().String()
		mustExec(t, db, `INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, status, fingerprint)
			VALUES ($1, $2, $3, 'dast', 'tool', 'msg', 'high', $4, $5)`,
			id, tid.String(), assetID, status, "fp-scope-effects-"+id)
		return id
	}
	exclusion := func(tid shared.ID, typ, pattern, kind, extra string) string {
		t.Helper()
		var id string
		q := `INSERT INTO scope_exclusions (tenant_id, exclusion_type, pattern, reason, status, approved_by, approved_at, created_by, kind)
			VALUES ($1, $2, $3, 'test', 'active', 'a', now(), 'r', $4) RETURNING id::text`
		if err := db.QueryRowContext(ctx, q, tid.String(), typ, pattern, kind).Scan(&id); err != nil {
			t.Fatal(err)
		}
		if extra != "" {
			mustExec(t, db, `UPDATE scope_exclusions SET `+extra+` WHERE id = $1`, id)
		}
		return id
	}
	status := func(id string) (st string, reason sql.NullString, regression bool) {
		t.Helper()
		if err := db.QueryRowContext(ctx, `SELECT status, closure_reason, COALESCE(is_regression, false) FROM findings WHERE id = $1`, id).
			Scan(&st, &reason, &regression); err != nil {
			t.Fatal(err)
		}
		return st, reason, regression
	}
	wantStatus := func(id, want string) {
		t.Helper()
		if st, _, _ := status(id); st != want {
			t.Fatalf("finding %s: status %s, want %s", id, st, want)
		}
	}

	notOurs := asset(tenant, "x.sold.example.com", "subdomain")
	apex := asset(tenant, "sold.example.com", "domain")
	retired := asset(tenant, "203.0.113.7", "ip_address")
	dns := asset(tenant, "fragile.example.com", "subdomain")
	temp := asset(tenant, "maint.example.com", "subdomain")
	pending := asset(tenant, "pending.example.com", "subdomain")
	rejected := asset(tenant, "typo.example.net", "domain")
	keep := asset(tenant, "app.example.com", "subdomain")
	theirs := asset(other, "x.sold.example.com", "subdomain")

	exclusion(tenant, "domain", "*.sold.example.com", "not_ours", "")
	retiredEx := exclusion(tenant, "cidr", "203.0.113.0/28", "retired", "")
	exclusion(tenant, "domain", "fragile.example.com", "do_not_scan", "")
	exclusion(tenant, "domain", "maint.example.com", "not_ours", "expires_at = now() + interval '3 days'")
	exclusion(tenant, "domain", "pending.example.com", "not_ours", "status = 'pending', approved_by = NULL, approved_at = NULL")
	if _, err := attr.SaveDecision(ctx, tenant, rejected, attribution.StateRejected, ""); err != nil {
		t.Fatal(err)
	}
	// The other tenant has no exclusion; this tenant's must not reach it.

	fNotOurs := finding(tenant, notOurs, "confirmed")
	fApex := finding(tenant, apex, "new")
	fFixApplied := finding(tenant, retired, "fix_applied")
	fAccepted := finding(tenant, retired, "accepted")
	fDraft := finding(tenant, notOurs, "draft")
	fDNS := finding(tenant, dns, "confirmed")
	fTemp := finding(tenant, temp, "confirmed")
	fPending := finding(tenant, pending, "confirmed")
	fRejected := finding(tenant, rejected, "in_progress")
	fKeep := finding(tenant, keep, "new")
	fTheirs := finding(other, theirs, "confirmed")

	closed, err := repo.CloseOutOfScope(ctx, tenant, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(closed) != 4 {
		t.Fatalf("closed %d findings, want 4 (not ours, apex under the wildcard, retired range, rejected)", len(closed))
	}
	for _, id := range []string{fNotOurs, fApex, fFixApplied, fRejected} {
		st, reason, _ := status(id)
		if st != "resolved" || reason.String != "out_of_scope" {
			t.Fatalf("finding %s: %s/%s, want resolved/out_of_scope", id, st, reason.String)
		}
	}
	wantStatus(fAccepted, "accepted") // already closed: left alone
	wantStatus(fDraft, "draft")       // a pentester's draft is not touched
	wantStatus(fDNS, "confirmed")     // do_not_scan: findings stay open
	wantStatus(fTemp, "confirmed")    // temporary: findings stay open
	wantStatus(fPending, "confirmed") // not in effect yet
	wantStatus(fKeep, "new")
	wantStatus(fTheirs, "confirmed") // another tenant's finding on the same name

	var entries int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM finding_activities WHERE tenant_id = $1 AND finding_id = $2
		AND source = 'scope_effects' AND changes->>'new_status' = 'resolved' AND changes->>'old_status' = 'confirmed'`,
		tenant.String(), fNotOurs).Scan(&entries); err != nil {
		t.Fatal(err)
	}
	if entries != 1 {
		t.Fatalf("timeline entries for the close: %d, want 1", entries)
	}

	if again, err := repo.CloseOutOfScope(ctx, tenant, 100); err != nil || len(again) != 0 {
		t.Fatalf("second pass closed %d (err %v), want 0", len(again), err)
	}
	if n, err := repo.ReopenBackInScope(ctx, tenant, 100); err != nil || len(n) != 0 {
		t.Fatalf("reopen with everything still out of scope moved %d (err %v), want 0", len(n), err)
	}
	if n, err := repo.CloseOutOfScope(ctx, other, 100); err != nil || len(n) != 0 {
		t.Fatalf("the other tenant: closed %d (err %v), want 0", len(n), err)
	}

	tenants, err := repo.TenantsWithScopeEffects(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, id := range tenants {
		if id == tenant {
			found = true
		}
		if id == other {
			t.Fatal("the other tenant has nothing to reconcile")
		}
	}
	if !found {
		t.Fatal("the tenant with a closing exclusion is not listed")
	}

	// Re-include: the retired range becomes do_not_scan, the decision is
	// undone. Their findings reopen to the status they had, not as a
	// regression; the not-ours wildcard still holds its two.
	mustExec(t, db, `UPDATE scope_exclusions SET kind = 'do_not_scan' WHERE id = $1`, retiredEx)
	if _, err := attr.SaveDecision(ctx, tenant, rejected, attribution.StateConfirmed, ""); err != nil {
		t.Fatal(err)
	}
	reopened, err := repo.ReopenBackInScope(ctx, tenant, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(reopened) != 2 {
		t.Fatalf("reopened %d, want 2", len(reopened))
	}
	for id, want := range map[string]string{fFixApplied: "fix_applied", fRejected: "in_progress"} {
		st, reason, regression := status(id)
		if st != want || reason.Valid || regression {
			t.Fatalf("finding %s: %s (reason %v, regression %v), want %s, no reason, no regression", id, st, reason, regression, want)
		}
	}
	wantStatus(fNotOurs, "resolved")
	wantStatus(fApex, "resolved")

	// Removing the wildcard reopens the rest.
	mustExec(t, db, `DELETE FROM scope_exclusions WHERE tenant_id = $1 AND pattern = '*.sold.example.com'`, tenant.String())
	if reopened, err = repo.ReopenBackInScope(ctx, tenant, 100); err != nil || len(reopened) != 2 {
		t.Fatalf("reopened %d (err %v), want 2", len(reopened), err)
	}
	wantStatus(fNotOurs, "confirmed")
	wantStatus(fApex, "new")
}
