package integration

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/infra/controller"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// fixedSLA gives every finding a deadline a week after the start it is given.
type fixedSLA struct{}

func (fixedSLA) CalculateSLADeadlineForPriority(_ context.Context, _, _, _ string, _ vulnerability.Severity, from time.Time) (time.Time, error) {
	return from.Add(7 * 24 * time.Hour), nil
}

func (f *acceptanceFixture) expiryController() *controller.ApprovalExpirationController {
	return controller.NewApprovalExpirationController(
		postgres.NewFindingAcceptanceExpiryRepository(f.pdb),
		fixedSLA{}, nil)
}

// acceptEnded makes the fixture's finding an accepted risk whose end has
// passed, with the approved request that accepted it. Returns the request id.
func (f *acceptanceFixture) acceptEnded(t *testing.T, findingID shared.ID) string {
	t.Helper()
	ended := time.Now().Add(-time.Hour)
	f.exec(t, `UPDATE findings SET status = 'accepted', resolution = 'risk ok', resolved_at = NOW() - INTERVAL '30 days',
			acceptance_expires_at = $2, sla_deadline = NOW() - INTERVAL '20 days', sla_status = 'overdue'
		WHERE id = $1`, findingID.String(), ended)
	approval := shared.NewID()
	f.exec(t, `INSERT INTO finding_status_approvals (id, tenant_id, finding_id, requested_status, requested_by,
			justification, approved_by, approved_at, status, expires_at)
		VALUES ($1, (SELECT tenant_id FROM findings WHERE id = $2), $2, 'accepted', $3, 'risk ok', $4, NOW() - INTERVAL '30 days', 'approved', $5)`,
		approval.String(), findingID.String(), f.requester.String(), f.approver.String(), ended)
	return approval.String()
}

func (f *acceptanceFixture) approvalStatus(t *testing.T, id string) string {
	t.Helper()
	var st string
	if err := f.db.QueryRow(`SELECT status FROM finding_status_approvals WHERE id = $1`, id).Scan(&st); err != nil {
		t.Fatal(err)
	}
	return st
}

func (f *acceptanceFixture) activities(t *testing.T, findingID shared.ID, kind string) int {
	t.Helper()
	var n int
	if err := f.db.QueryRow(`SELECT COUNT(*) FROM finding_activities WHERE tenant_id = $1 AND finding_id = $2 AND activity_type = $3`,
		f.tenant.String(), findingID.String(), kind).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// An ended acceptance reopens the finding to confirmed, starts a new SLA clock
// from the reopen (on track), expires its approved request and writes the
// timeline, all together. Another tenant's acceptance that has not ended is
// untouched; a finding that moved on keeps its status while its request is
// marked expired.
func TestAcceptanceExpiry_OneTransaction(t *testing.T) {
	f := newAcceptanceFixture(t)
	ctx := context.Background()
	approval := f.acceptEnded(t, f.findingID)

	// Another tenant: accepted until next month.
	otherAsset, otherFinding := shared.NewID(), shared.NewID()
	f.exec(t, `INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, 'acc-other', 'repository')`,
		otherAsset.String(), f.other.String())
	f.exec(t, `INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status, acceptance_expires_at)
		VALUES ($1, $2, $3, 'sast', 'acc-tool', 'm', 'high', $4, 'accepted', NOW() + INTERVAL '30 days')`,
		otherFinding.String(), f.other.String(), otherAsset.String(), "acc-other-"+otherFinding.String())

	// A finding of the tenant that was reopened and resolved since its request.
	moved := shared.NewID()
	f.exec(t, `INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status)
		VALUES ($1, $2, $3, 'sast', 'acc-tool', 'm', 'high', $4, 'confirmed')`,
		moved.String(), f.tenant.String(), f.assetID.String(), "acc-moved-"+moved.String())
	movedApproval := f.acceptEnded(t, moved)
	f.exec(t, `UPDATE findings SET status = 'resolved' WHERE id = $1`, moved.String())

	before := time.Now()
	n, err := f.expiryController().Reconcile(ctx)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if n != 1 {
		t.Errorf("reopened %d findings, want 1", n)
	}

	var status string
	var resolution sql.NullString
	var resolvedAt, deadline sql.NullTime
	var slaStatus string
	var end sql.NullTime
	if err := f.db.QueryRow(`SELECT status, resolution, resolved_at, sla_deadline, sla_status, acceptance_expires_at
		FROM findings WHERE id = $1`, f.findingID.String()).
		Scan(&status, &resolution, &resolvedAt, &deadline, &slaStatus, &end); err != nil {
		t.Fatal(err)
	}
	if status != "confirmed" || resolution.Valid || resolvedAt.Valid || end.Valid {
		t.Errorf("finding: status=%s resolution=%v resolved_at=%v end=%v, want confirmed with nothing left of the acceptance",
			status, resolution, resolvedAt, end)
	}
	if !deadline.Valid || deadline.Time.Before(before.Add(7*24*time.Hour-time.Minute)) || slaStatus != "on_track" {
		t.Errorf("SLA: deadline=%v status=%s, want a new clock (a week from the reopen, on track)", deadline, slaStatus)
	}
	if got := f.approvalStatus(t, approval); got != "expired" {
		t.Errorf("approval status = %s, want expired", got)
	}
	if f.activities(t, f.findingID, "acceptance_expired") != 1 || f.activities(t, f.findingID, "sla_restarted") != 1 {
		t.Errorf("timeline: want one acceptance_expired and one sla_restarted entry")
	}

	var otherStatus string
	if err := f.db.QueryRow(`SELECT status FROM findings WHERE id = $1`, otherFinding.String()).Scan(&otherStatus); err != nil {
		t.Fatal(err)
	}
	if otherStatus != "accepted" {
		t.Errorf("other tenant's running acceptance changed to %s", otherStatus)
	}
	var movedStatus string
	if err := f.db.QueryRow(`SELECT status FROM findings WHERE id = $1`, moved.String()).Scan(&movedStatus); err != nil {
		t.Fatal(err)
	}
	if movedStatus != "resolved" || f.approvalStatus(t, movedApproval) != "expired" {
		t.Errorf("moved finding: status=%s request=%s, want resolved (untouched) and expired", movedStatus, f.approvalStatus(t, movedApproval))
	}

	// A second run changes nothing.
	if n, err := f.expiryController().Reconcile(ctx); err != nil || n != 0 {
		t.Errorf("second run reopened %d (%v), want 0", n, err)
	}
}

// When any part of the end fails, nothing is written: the finding stays
// accepted, the request approved, the timeline empty, and the next run
// completes it. (Before, the request was expired first and a failed finding
// update left the finding accepted for good.)
func TestAcceptanceExpiry_FailureLeavesNothingHalfDone(t *testing.T) {
	f := newAcceptanceFixture(t)
	ctx := context.Background()
	approval := f.acceptEnded(t, f.findingID)

	mdb, err := sql.Open("postgres", testdb.MigratorURL())
	if err != nil {
		t.Fatal(err)
	}
	defer mdb.Close()
	fn := "test_fail_acc_" + f.findingID.String()[:8]
	if _, err := mdb.Exec(`CREATE FUNCTION ` + fn + `() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			IF NEW.finding_id = '` + f.findingID.String() + `' AND NEW.activity_type = 'acceptance_expired' THEN
				RAISE EXCEPTION 'injected failure';
			END IF;
			RETURN NEW;
		END $$`); err != nil {
		t.Fatal(err)
	}
	if _, err := mdb.Exec(`CREATE TRIGGER ` + fn + ` BEFORE INSERT ON finding_activities FOR EACH ROW EXECUTE FUNCTION ` + fn + `()`); err != nil {
		t.Fatal(err)
	}
	dropped := false
	drop := func() {
		if !dropped {
			_, _ = mdb.Exec(`DROP TRIGGER IF EXISTS ` + fn + ` ON finding_activities`)
			_, _ = mdb.Exec(`DROP FUNCTION IF EXISTS ` + fn + `()`)
			dropped = true
		}
	}
	defer drop()

	if n, _ := f.expiryController().Reconcile(ctx); n != 0 {
		t.Fatalf("reopened %d with the failure injected, want 0", n)
	}
	if st, _ := f.state(t); st != "accepted" {
		t.Errorf("finding status after a failed end = %s, want accepted (rolled back)", st)
	}
	if got := f.approvalStatus(t, approval); got != "approved" {
		t.Errorf("request status after a failed end = %s, want approved (rolled back)", got)
	}

	drop()
	if n, err := f.expiryController().Reconcile(ctx); err != nil || n != 1 {
		t.Fatalf("retry reopened %d (%v), want 1", n, err)
	}
	if st, _ := f.state(t); st != "confirmed" {
		t.Errorf("finding status after the retry = %s, want confirmed", st)
	}
	if got := f.approvalStatus(t, approval); got != "expired" {
		t.Errorf("request status after the retry = %s, want expired", got)
	}
}

// The one-time repair: accepted findings with no end get the 90-day default
// and a timeline note in their own tenant; an accepted finding with an end is
// untouched; running it again changes nothing.
func TestAcceptanceExpiry_MigrationGivesMissingEnds(t *testing.T) {
	const dir = "../../migrations"
	db := testdb.PrivateDatabase(t, "migaccend", dir)
	v := testdb.MigrationVersion(t, dir, "finding_acceptance_end_default")
	testdb.Migrate(t, db, dir, v, v, true)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("%v\n%s", err, q)
		}
	}
	type row struct{ tenant, finding shared.ID }
	var noEnd []row
	kept := time.Now().Add(10 * 24 * time.Hour).UTC().Truncate(time.Second)
	var withEnd shared.ID
	for i, name := range []string{"acc-mig-a", "acc-mig-b"} {
		tn := createTestTenant(t, db, name)
		asset, id := shared.NewID(), shared.NewID()
		exec(`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, $3, 'host')`, asset.String(), tn.String(), name)
		exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status)
			VALUES ($1, $2, $3, 'sast', 't', 'm', 'high', $4, 'accepted')`, id.String(), tn.String(), asset.String(), "acc-mig-"+id.String())
		noEnd = append(noEnd, row{tn, id})
		if i == 0 {
			withEnd = shared.NewID()
			exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status, acceptance_expires_at)
				VALUES ($1, $2, $3, 'sast', 't', 'm', 'high', $4, 'accepted', $5)`,
				withEnd.String(), tn.String(), asset.String(), "acc-mig-"+withEnd.String(), kept)
		}
	}
	testdb.Migrate(t, db, dir, v, v, false)
	testdb.Migrate(t, db, dir, v, v, true)
	testdb.Migrate(t, db, dir, v, v, false)

	for _, r := range noEnd {
		var end sql.NullTime
		var notes int
		if err := db.QueryRow(`SELECT acceptance_expires_at,
				(SELECT COUNT(*) FROM finding_activities a WHERE a.tenant_id = $2 AND a.finding_id = f.id
				  AND a.changes->>'reason' = 'acceptance_end_default')
			FROM findings f WHERE f.id = $1`, r.finding.String(), r.tenant.String()).Scan(&end, &notes); err != nil {
			t.Fatal(err)
		}
		if !end.Valid || time.Until(end.Time) < 89*24*time.Hour || time.Until(end.Time) > 90*24*time.Hour+time.Minute {
			t.Errorf("finding %s end = %v, want about 90 days from now", r.finding, end)
		}
		if notes != 1 {
			t.Errorf("finding %s timeline notes in its tenant = %d, want exactly 1", r.finding, notes)
		}
	}
	var got time.Time
	if err := db.QueryRow(`SELECT acceptance_expires_at FROM findings WHERE id = $1`, withEnd.String()).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if !got.Equal(kept) {
		t.Errorf("an existing end changed: %v, want %v", got, kept)
	}
}
