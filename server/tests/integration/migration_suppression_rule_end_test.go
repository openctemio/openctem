package integration

// Migrations suppression_rule_review_flag .. suppression_rule_end_required_validate:
// every suppression rule has an end. Rules without one get 90 days from now
// and, while pending or approved, the review flag; a rule that already had an
// end is untouched; a row without an end is then refused; the downs give the
// old rows back their "no end" and drop the constraint.

import (
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/testdb"
)

func TestMigrationSuppressionRuleEnd(t *testing.T) {
	const dir = "../../migrations"
	db := testdb.PrivateDatabase(t, "migsupend", dir)
	first := testdb.MigrationVersion(t, dir, "suppression_rule_review_flag")
	last := testdb.MigrationVersion(t, dir, "suppression_rule_end_required_validate")
	testdb.Migrate(t, db, dir, first, last, true)

	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	const (
		tenant   = "a1111111-1111-4111-8111-111111111112"
		approved = "e5555555-5555-4555-8555-555555555561"
		pending  = "e5555555-5555-4555-8555-555555555562"
		rejected = "e5555555-5555-4555-8555-555555555563"
		ended    = "e5555555-5555-4555-8555-555555555564"
	)
	exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'a', 'mig-supend-a')`, tenant)
	exec(`INSERT INTO suppression_rules (id, tenant_id, name, rule_id, suppression_type, status, expires_at) VALUES
		($1, $5, 'approved', 'r1', 'false_positive', 'approved', NULL),
		($2, $5, 'pending', 'r2', 'wont_fix', 'pending', NULL),
		($3, $5, 'rejected', 'r3', 'false_positive', 'rejected', NULL),
		($4, $5, 'ended', 'r4', 'false_positive', 'approved', '2030-01-01T00:00:00Z')`, approved, pending, rejected, ended, tenant)

	testdb.Migrate(t, db, dir, first, last, false)

	check := func(id string, wantFlag bool, wantReason string, wantEnd *time.Time) {
		t.Helper()
		var end time.Time
		var flagged bool
		var reason string
		if err := db.QueryRow(`SELECT expires_at, review_flagged_at IS NOT NULL, review_reason FROM suppression_rules WHERE id = $1`, id).
			Scan(&end, &flagged, &reason); err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		if flagged != wantFlag || reason != wantReason {
			t.Fatalf("%s: flagged=%v reason=%q, want %v %q", id, flagged, reason, wantFlag, wantReason)
		}
		if wantEnd != nil {
			if !end.Equal(*wantEnd) {
				t.Fatalf("%s: end %v, want %v", id, end, *wantEnd)
			}
			return
		}
		if d := time.Until(end); d < 89*24*time.Hour || d > 91*24*time.Hour {
			t.Fatalf("%s: end %v is not about 90 days ahead", id, end)
		}
	}
	keep := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	check(approved, true, "no_end_date", nil)
	check(pending, true, "no_end_date", nil)
	check(rejected, false, "no_end_date", nil)
	check(ended, false, "", &keep)

	// A rule without an end is refused; a writer that names none gets the default.
	if _, err := db.Exec(`INSERT INTO suppression_rules (tenant_id, name, rule_id, expires_at) VALUES ($1, 'x', 'r5', NULL)`, tenant); err == nil {
		t.Fatal("a rule without an end was stored")
	}
	exec(`INSERT INTO suppression_rules (tenant_id, name, rule_id) VALUES ($1, 'y', 'r6')`, tenant)
	var defaulted bool
	if err := db.QueryRow(`SELECT expires_at > now() + interval '89 days' FROM suppression_rules WHERE tenant_id = $1 AND rule_id = 'r6'`, tenant).Scan(&defaulted); err != nil || !defaulted {
		t.Fatalf("default end: %v %v", defaulted, err)
	}
	exec(`DELETE FROM suppression_rules WHERE rule_id = 'r6'`)

	// Down, then up again.
	testdb.Migrate(t, db, dir, first, last, true)
	var noEnd int
	if err := db.QueryRow(`SELECT count(*) FROM suppression_rules WHERE expires_at IS NULL`).Scan(&noEnd); err != nil || noEnd != 3 {
		t.Fatalf("down restored %d rules without an end, want 3 (%v)", noEnd, err)
	}
	testdb.Migrate(t, db, dir, first, last, false)
	check(approved, true, "no_end_date", nil)
}
