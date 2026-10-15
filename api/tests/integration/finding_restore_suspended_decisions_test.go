package integration

import (
	"testing"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The one-time repair restores each decision the old taint-source code
// reversed (confirmed with resolution decision_suspended) to its latest
// suspended decision, with a timeline entry and one open review flag, in the
// finding's own tenant. A confirmed finding a person reopened is untouched;
// running it again changes nothing.
func TestRestoreSuspendedDecisions(t *testing.T) {
	const dir = "../../migrations"
	db := testdb.PrivateDatabase(t, "migrestoredecision", dir)
	v := testdb.MigrationVersion(t, dir, "finding_restore_suspended_decisions")
	testdb.Migrate(t, db, dir, v, v, true)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("%v\n%s", err, q)
		}
	}
	type fx struct{ tenant, finding shared.ID }
	seed := func(name, resolution, prior string) fx {
		tn := createTestTenant(t, db, name)
		asset, id := shared.NewID(), shared.NewID()
		exec(`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, $3, 'repository')`, asset.String(), tn.String(), name)
		exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status, resolution)
			VALUES ($1, $2, $3, 'sast', 'semgrep', 'm', 'high', $4, 'confirmed', $5)`, id.String(), tn.String(), asset.String(), "rs-"+id.String(), resolution)
		exec(`INSERT INTO finding_decision_suspensions (tenant_id, finding_id, prior_status, prior_resolution, reason, old_source_hash, new_source_hash)
			VALUES ($1, $2, $3, 'reviewed by a person', 'taint_source_changed', 'a1', 'b2')`, tn.String(), id.String(), prior)
		return fx{tn, id}
	}
	fp := seed("rs-fp", "decision_suspended", "false_positive")
	acc := seed("rs-acc", "decision_suspended", "accepted")
	reopened := seed("rs-reopened", "a person reopened it", "false_positive")

	testdb.Migrate(t, db, dir, v, v, false)
	testdb.Migrate(t, db, dir, v, v, true)
	testdb.Migrate(t, db, dir, v, v, false)

	check := func(x fx, wantStatus string, wantFlags, wantEntries int) {
		t.Helper()
		var status string
		var flags, entries int
		if err := db.QueryRow(`SELECT status,
				(SELECT COUNT(*) FROM finding_decision_reviews r WHERE r.tenant_id = $2 AND r.finding_id = f.id AND r.cleared_at IS NULL),
				(SELECT COUNT(*) FROM finding_activities a WHERE a.tenant_id = $2 AND a.finding_id = f.id AND a.changes->>'reason' = 'decision_restored')
			FROM findings f WHERE f.id = $1`, x.finding.String(), x.tenant.String()).Scan(&status, &flags, &entries); err != nil {
			t.Fatal(err)
		}
		if status != wantStatus || flags != wantFlags || entries != wantEntries {
			t.Errorf("finding %s: status=%s flags=%d entries=%d, want %s %d %d", x.finding, status, flags, entries, wantStatus, wantFlags, wantEntries)
		}
	}
	check(fp, "false_positive", 1, 1)
	check(acc, "accepted", 1, 1)
	check(reopened, "confirmed", 0, 0)
	var end *string
	_ = db.QueryRow(`SELECT acceptance_expires_at::text FROM findings WHERE id = $1`, acc.finding.String()).Scan(&end)
	if end == nil {
		t.Error("a restored acceptance has no end")
	}
}
