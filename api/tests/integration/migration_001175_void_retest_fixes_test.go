package integration

// Migration 001175: a "fixed" retest that re-ran the template with the
// finding's matched-at URL as its input (the path requested twice, a certain
// miss) is voided, and the finding it resolved returns to its prior status.
// Retests against an origin or a bare host, later-superseded retests and
// findings a person changed since are untouched. Runs in a rolled-back
// transaction.

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestMigration001175VoidsPathTargetRetestFixes(t *testing.T) {
	db := openLifecycleDB(t)
	ctx := context.Background()
	tenant := seedLifecycleTenant(ctx, t, db)

	up, err := os.ReadFile("../../migrations/001175_void_path_target_retest_fixes.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(string(up)), "insert into") {
		t.Fatal("the migration must not insert rows (no SQL audit or activity rows)")
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := tx.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%v\n%s", err, q)
		}
	}

	assetID := shared.NewID().String()
	exec(`INSERT INTO assets (id, tenant_id, name, asset_type, status) VALUES ($1, $2, 'shop.example.com', 'domain', 'active')`,
		assetID, tenant.String())

	// finding inserts a nuclei finding a retest resolved (method) or a person resolved.
	finding := func(method string) string {
		t.Helper()
		id := shared.NewID().String()
		exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, rule_id, file_path, message, severity,
				fingerprint, status, resolved_at, resolution, resolution_method)
			VALUES ($1::uuid, $2, $3, 'dast', 'nuclei', 'wordpress-click2shell', 'https://shop.example.com/wp-admin/js/theme.js',
				'hit', 'high', $1::text, 'resolved', NOW(), 'retest: not detected (wordpress-click2shell)', $4)`,
			id, tenant.String(), assetID, method)
		return id
	}
	retest := func(findingID, target, outcome, age string) string {
		t.Helper()
		id := shared.NewID().String()
		exec(`INSERT INTO finding_retests (id, tenant_id, finding_id, asset_id, trigger, status, outcome, reason,
				prior_status, result_status, template_id, target, deadline_at, created_at, completed_at)
			VALUES ($1, $2, $3, $4, 'manual', 'completed', $5, 'template did not match and the target answered',
				'confirmed', 'resolved', 'wordpress-click2shell', $6, NOW(), NOW() - $7::interval, NOW() - $7::interval)`,
			id, tenant.String(), findingID, assetID, outcome, target, age)
		return id
	}

	fPath := finding("retest_verified")
	rPath := retest(fPath, "https://shop.example.com/wp-admin/js/theme.js", "fixed", "1 hour")
	fQuery := finding("retest_verified")
	rQuery := retest(fQuery, "https://shop.example.com/?p=1", "fixed", "1 hour")
	fOrigin := finding("retest_verified")
	rOrigin := retest(fOrigin, "https://shop.example.com", "fixed", "1 hour")
	fSlash := finding("retest_verified")
	retest(fSlash, "https://shop.example.com/", "fixed", "1 hour")
	fHost := finding("retest_verified")
	retest(fHost, "shop.example.com", "fixed", "1 hour")
	fPerson := finding("manual") // a person resolved it after the retest
	retest(fPerson, "https://shop.example.com/wp-admin/js/theme.js", "fixed", "1 hour")
	fLater := finding("retest_verified") // a later retest superseded the bad one
	retest(fLater, "https://shop.example.com/wp-admin/js/theme.js", "fixed", "2 hours")
	retest(fLater, "https://shop.example.com", "fixed", "1 hour")

	exec(string(up))

	status := func(id string) string {
		t.Helper()
		var s string
		if err := tx.QueryRowContext(ctx, `SELECT status FROM findings WHERE tenant_id = $1 AND id = $2`, tenant.String(), id).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	outcome := func(id string) (string, string) {
		t.Helper()
		var o, reason string
		if err := tx.QueryRowContext(ctx, `SELECT outcome, reason FROM finding_retests WHERE tenant_id = $1 AND id = $2`, tenant.String(), id).Scan(&o, &reason); err != nil {
			t.Fatal(err)
		}
		return o, reason
	}

	for name, f := range map[string]string{"path": fPath, "query": fQuery} {
		if got := status(f); got != "confirmed" {
			t.Errorf("%s target: finding status = %q, want confirmed (back to its prior status)", name, got)
		}
	}
	for name, r := range map[string]string{"path": rPath, "query": rQuery} {
		if o, reason := outcome(r); o != "unknown" || !strings.HasPrefix(reason, "voided:") {
			t.Errorf("%s target: retest = %q %q, want unknown with a voided reason", name, o, reason)
		}
	}
	var resolvedAt *string
	if err := tx.QueryRowContext(ctx, `SELECT resolved_at::text FROM findings WHERE id = $1`, fPath).Scan(&resolvedAt); err != nil {
		t.Fatal(err)
	}
	if resolvedAt != nil {
		t.Errorf("voided finding keeps resolved_at %v", *resolvedAt)
	}
	for name, f := range map[string]string{"origin": fOrigin, "trailing slash": fSlash, "bare host": fHost, "person": fPerson, "superseded": fLater} {
		if got := status(f); got != "resolved" {
			t.Errorf("%s: finding status = %q, want resolved (untouched)", name, got)
		}
	}
	if o, _ := outcome(rOrigin); o != "fixed" {
		t.Errorf("origin retest outcome = %q, want fixed (untouched)", o)
	}
}
