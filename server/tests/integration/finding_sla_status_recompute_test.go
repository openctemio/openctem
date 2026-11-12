package integration

import (
	"database/sql"
	"testing"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type slaRow struct {
	db     *sql.DB
	tenant shared.ID
	asset  shared.ID
}

func (s slaRow) insert(t *testing.T, status, deadline, slaStatus string) shared.ID {
	t.Helper()
	id := shared.NewID()
	if _, err := s.db.Exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status, sla_deadline)
		VALUES ($1, $2, $3, 'sast', 'sla-tool', 'm', 'high', $4, $5, NOW() + $6::interval)`,
		id.String(), s.tenant.String(), s.asset.String(), "sla-"+id.String(), status, deadline); err != nil {
		t.Fatal(err)
	}
	if slaStatus != "" {
		// Bypass the trigger's recompute (it runs only on status / deadline
		// changes), as the escalation job and old rows do.
		if _, err := s.db.Exec(`UPDATE findings SET sla_status = $2 WHERE id = $1`, id.String(), slaStatus); err != nil {
			t.Fatal(err)
		}
	}
	return id
}

func (s slaRow) move(t *testing.T, id shared.ID, status string) string {
	t.Helper()
	var got string
	if err := s.db.QueryRow(`UPDATE findings SET status = $2::varchar,
			resolved_at = CASE WHEN $2::varchar IN ('resolved', 'false_positive', 'accepted', 'duplicate') THEN NOW() END
		WHERE id = $1 RETURNING sla_status`, id.String(), status).Scan(&got); err != nil {
		t.Fatal(err)
	}
	return got
}

// sla_status follows every status change, whatever path writes it.
func TestSLAStatus_RecomputedOnEveryStatusChange(t *testing.T) {
	db := setupTestDB(t)
	tenant := createTestTenant(t, db, "sla-recompute")
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM tenants WHERE id = $1`, tenant.String())
		_ = db.Close()
	})
	asset := shared.NewID()
	if _, err := db.Exec(`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, 'sla-host', 'host')`,
		asset.String(), tenant.String()); err != nil {
		t.Fatal(err)
	}
	s := slaRow{db: db, tenant: tenant, asset: asset}

	// A warning the escalation job set survives a move between open statuses;
	// a fix by the deadline is on track (met).
	warned := s.insert(t, "confirmed", "5 days", "warning")
	if got := s.move(t, warned, "in_progress"); got != "warning" {
		t.Errorf("confirmed -> in_progress with a warning: sla_status = %s, want warning", got)
	}
	if got := s.move(t, warned, "resolved"); got != "on_track" {
		t.Errorf("resolved before the deadline: sla_status = %s, want on_track (met)", got)
	}

	// Past the deadline: a reopen is overdue; a fix after it is exceeded (missed).
	late := s.insert(t, "resolved", "-2 days", "on_track")
	if got := s.move(t, late, "confirmed"); got != "overdue" {
		t.Errorf("reopened past the deadline: sla_status = %s, want overdue", got)
	}
	if got := s.move(t, late, "resolved"); got != "exceeded" {
		t.Errorf("resolved after the deadline: sla_status = %s, want exceeded (missed)", got)
	}

	// A disposition leaves the SLA.
	for _, st := range []string{"accepted", "false_positive"} {
		id := s.insert(t, "confirmed", "-1 day", "overdue")
		if got := s.move(t, id, st); got != "not_applicable" {
			t.Errorf("%s: sla_status = %s, want not_applicable", st, got)
		}
	}
}

// The one-time repair recomputes stale values and leaves correct ones.
func TestSLAStatus_MigrationRepairsStaleValues(t *testing.T) {
	const dir = "../../migrations"
	db := testdb.PrivateDatabase(t, "migslastatus", dir)
	v := testdb.MigrationVersion(t, dir, "finding_sla_status_recompute")
	testdb.Migrate(t, db, dir, v, v, true)
	tenant := createTestTenant(t, db, "sla-mig")
	asset := shared.NewID()
	if _, err := db.Exec(`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, 'sla-mig', 'host')`,
		asset.String(), tenant.String()); err != nil {
		t.Fatal(err)
	}
	s := slaRow{db: db, tenant: tenant, asset: asset}
	cases := map[shared.ID]string{
		s.insert(t, "accepted", "-3 days", "exceeded"):      "not_applicable",
		s.insert(t, "false_positive", "5 days", "on_track"): "not_applicable",
		s.insert(t, "confirmed", "-1 day", "on_track"):      "overdue",
		s.insert(t, "confirmed", "5 days", "warning"):       "warning",
		s.insert(t, "new", "5 days", "on_track"):            "on_track",
	}
	if _, err := db.Exec(`UPDATE findings SET resolved_at = NOW() WHERE status IN ('accepted', 'false_positive')`); err != nil {
		t.Fatal(err)
	}
	testdb.Migrate(t, db, dir, v, v, false)
	for id, want := range cases {
		var got string
		if err := db.QueryRow(`SELECT sla_status FROM findings WHERE id = $1`, id.String()).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("finding %s: sla_status = %s, want %s", id, got, want)
		}
	}
}
