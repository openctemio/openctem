package integration

import (
	"database/sql"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The one-time repair: a closed finding with no close date takes the time of
// the latest timeline entry that moved it into its status; one with no such
// entry keeps no date (none is invented); an existing date is untouched; a
// second run changes nothing.
func TestClosedAtRepair_FromTheTimeline(t *testing.T) {
	const dir = "../../migrations"
	db := testdb.PrivateDatabase(t, "migclosedat", dir)
	v := testdb.MigrationVersion(t, dir, "finding_closed_at_from_timeline")
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("%v\n%s", err, q)
		}
	}
	tenant := createTestTenant(t, db, "closedat")
	asset := shared.NewID()
	exec(`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, 'ca-host', 'host')`, asset.String(), tenant.String())
	finding := func(status string) shared.ID {
		id := shared.NewID()
		exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status)
			VALUES ($1, $2, $3, 'sast', 't', 'm', 'high', $4, $5)`, id.String(), tenant.String(), asset.String(), "ca-"+id.String(), status)
		exec(`UPDATE findings SET resolved_at = NULL WHERE id = $1`, id.String())
		return id
	}
	entry := func(tid, id shared.ID, kind, newStatus string, at time.Time) {
		exec(`INSERT INTO finding_activities (tenant_id, finding_id, activity_type, actor_type, changes, created_at)
			VALUES ($1, $2, $3, 'system', jsonb_build_object('new_status', $4::text), $5)`, tid.String(), id.String(), kind, newStatus, at)
	}
	closedAt := time.Now().Add(-48 * time.Hour).UTC().Truncate(time.Second)
	withEntry := finding("accepted")
	entry(tenant, withEntry, "status_changed", "confirmed", closedAt.Add(-24*time.Hour))
	entry(tenant, withEntry, "status_changed", "accepted", closedAt)
	noEntry := finding("false_positive")
	entry(tenant, noEntry, "comment_added", "", closedAt)
	kept := finding("resolved")
	keptAt := time.Now().Add(-5 * time.Hour).UTC().Truncate(time.Second)
	exec(`UPDATE findings SET resolved_at = $2 WHERE id = $1`, kept.String(), keptAt)
	entry(tenant, kept, "status_changed", "resolved", closedAt)

	testdb.Migrate(t, db, dir, v, v, true)
	testdb.Migrate(t, db, dir, v, v, false)
	testdb.Migrate(t, db, dir, v, v, false) // idempotent: nothing more matches

	read := func(id shared.ID) sql.NullTime {
		var at sql.NullTime
		if err := db.QueryRow(`SELECT resolved_at FROM findings WHERE id = $1`, id.String()).Scan(&at); err != nil {
			t.Fatal(err)
		}
		return at
	}
	if at := read(withEntry); !at.Valid || !at.Time.Equal(closedAt) {
		t.Errorf("close date from the timeline = %v, want %v", at, closedAt)
	}
	if at := read(noEntry); at.Valid {
		t.Errorf("a finding with no closing entry got a date %v", at.Time)
	}
	if at := read(kept); !at.Valid || !at.Time.Equal(keptAt) {
		t.Errorf("an existing close date changed: %v, want %v", at, keptAt)
	}
}
