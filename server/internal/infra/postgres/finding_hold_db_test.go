package postgres

import (
	"context"
	"database/sql"
	"slices"
	"testing"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/server/pkg/domain/asset"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/vulnerability"
)

func assetName(t *testing.T, db *sql.DB, id shared.ID) string {
	t.Helper()
	var n string
	if err := db.QueryRowContext(context.Background(), `SELECT name FROM assets WHERE id = $1`, id.String()).Scan(&n); err != nil {
		t.Fatalf("asset name: %v", err)
	}
	return n
}

func verification(t *testing.T, db *sql.DB, id shared.ID) (string, []string) {
	t.Helper()
	var s string
	var r pq.StringArray
	if err := db.QueryRowContext(context.Background(), `SELECT verification_state, hold_reasons FROM findings WHERE id = $1`, id.String()).Scan(&s, &r); err != nil {
		t.Fatalf("verification: %v", err)
	}
	return s, r
}

// The findings a command's report sighted first on a throttled host are
// held, once; nothing else is: another host, a finding that was there
// before, a checked one, another report, another tenant.
func TestHoldGapFindings_DB(t *testing.T) {
	ctx := context.Background()
	f := newCoverageFixture(t)
	repo := NewFindingRepository(&DB{DB: f.db})
	cmd, report := f.run(t, f.scan, "completed", f.host, f.otherHost)
	host := asset.HostOf(assetName(t, f.db, f.host))

	fresh := f.finding(t, f.host, "nuclei", report, nil)
	f.exec(t, `UPDATE findings SET severity = 'critical' WHERE id = $1`, fresh)
	otherHost := f.finding(t, f.otherHost, "nuclei", report, nil)
	older := f.finding(t, f.host, "nuclei", report, nil)
	f.exec(t, `UPDATE findings SET first_detected_at = NOW() - interval '2 days' WHERE id = $1`, older)
	checked := f.finding(t, f.host, "nuclei", report, nil)
	f.exec(t, `UPDATE findings SET verification_state = 'verified' WHERE id = $1`, checked)

	// SECURITY: another tenant with the same host name and a report under
	// the same report id (its own command) must never be touched, whether
	// the call names this tenant's command or is made for the other tenant.
	g := newCoverageFixture(t)
	g.exec(t, `UPDATE assets SET name = $1 WHERE id = $2`, assetName(t, f.db, f.host), g.host)
	gCmd := shared.NewID()
	g.exec(t, `INSERT INTO commands (id, tenant_id, sensor_id, type, status, payload, result)
		VALUES ($1, $2, $3, 'scan', 'completed', '{}', '{}')`, gCmd, g.tenant, g.sensor)
	g.exec(t, `INSERT INTO ingest_reports (id, tenant_id, sensor_id, report_id, command_id, state, media_type,
			header_digest, header, tool_name, expires_at)
		VALUES ($1, $2, $3, $4, $5, 'completed', 'application/vnd.ctis+json', 'd', '{}', 'nuclei', NOW() + interval '1 hour')`,
		shared.NewID(), g.tenant, g.sensor, report, gCmd)
	foreign := g.finding(t, g.host, "nuclei", report, nil)

	// This tenant's command, asked for under the other tenant: nothing.
	if got, err := repo.HoldGapFindings(ctx, g.tenant, cmd, "", []string{host}, []string{vulnerability.HoldTargetThrottled}); err != nil || len(got) != 0 {
		t.Fatalf("held across tenants: %v (%v)", got, err)
	}

	// Another report of the same command: narrowed away.
	got, err := repo.HoldGapFindings(ctx, f.tenant, cmd, shared.NewID().String(), []string{host}, []string{vulnerability.HoldTargetThrottled})
	if err != nil || len(got) != 0 {
		t.Fatalf("another report held %v (%v)", got, err)
	}

	got, err = repo.HoldGapFindings(ctx, f.tenant, cmd, "", []string{host}, []string{vulnerability.HoldTargetThrottled})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != fresh || got[0].Severity != "critical" {
		t.Fatalf("held %+v, want only the fresh critical finding", got)
	}
	if s, r := verification(t, f.db, fresh); s != "held" || !slices.Equal(r, []string{"target_throttled"}) {
		t.Fatalf("fresh: %s %v", s, r)
	}
	for name, id := range map[string]shared.ID{"other host": otherHost, "older": older, "foreign tenant": foreign} {
		if s, _ := verification(t, f.db, id); s != "unchecked" {
			t.Errorf("%s: %s, want unchecked", name, s)
		}
	}
	if s, _ := verification(t, f.db, checked); s != "verified" {
		t.Errorf("checked finding downgraded to %s", s)
	}

	// Idempotent: a second call changes nothing and announces nothing.
	if again, err := repo.HoldGapFindings(ctx, f.tenant, cmd, report, []string{host}, []string{vulnerability.HoldTargetThrottled}); err != nil || len(again) != 0 {
		t.Fatalf("second call held %v (%v)", again, err)
	}

	// IsHeld is tenant-pinned.
	if held, err := repo.IsHeld(ctx, f.tenant, fresh); err != nil || !held {
		t.Fatalf("IsHeld own: %v %v", held, err)
	}
	if held, err := repo.IsHeld(ctx, g.tenant, fresh); err != nil || held {
		t.Fatalf("IsHeld across tenants: %v %v", held, err)
	}
}

// The columns reach the domain and back, the CHECKs refuse what is not a
// state or a reason, and a sighting releases a held finding but never holds
// one that was not.
func TestFindingVerification_RoundTripAndUpsert_DB(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewFindingRepository(&DB{DB: db})
	tenant := seedTestTenant(ctx, t, db)
	host := seedPracticeAsset(ctx, t, db, tenant, "host", true)

	held := newPracticeFinding(t, tenant, host, vulnerability.FindingSourceDAST, "nuclei", "")
	held.Hold(vulnerability.HoldEdgeBlockPage, "made_up", vulnerability.HoldEdgeBlockPage)
	if err := repo.Create(ctx, held); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := repo.GetByID(ctx, tenant, held.ID())
	if err != nil {
		t.Fatal(err)
	}
	if !got.IsHeld() || !slices.Equal(got.HoldReasons(), []string{vulnerability.HoldEdgeBlockPage}) {
		t.Fatalf("read back %s %v", got.VerificationState(), got.HoldReasons())
	}

	for _, q := range []string{
		`UPDATE findings SET verification_state = 'maybe' WHERE id = $1`,
		`UPDATE findings SET hold_reasons = '{not_a_reason}' WHERE id = $1`,
		`UPDATE findings SET verification_state = 'unchecked', hold_reasons = '{soft_404}' WHERE id = $1`,
	} {
		if _, err := db.ExecContext(ctx, q, held.ID().String()); err == nil {
			t.Errorf("accepted: %s", q)
		}
	}

	// A clean sighting (same fingerprint, unchecked) releases the held one.
	clean := newPracticeFinding(t, tenant, host, vulnerability.FindingSourceDAST, "nuclei", "")
	clean.SetFingerprint(held.Fingerprint())
	if _, err := repo.CreateBatchWithResult(ctx, []*vulnerability.Finding{clean}); err != nil {
		t.Fatal(err)
	}
	if s, r := verification(t, db, held.ID()); s != "unchecked" || len(r) != 0 {
		t.Fatalf("after a clean sighting: %s %v, want released", s, r)
	}

	// A held sighting of a finding that was not held leaves it as it was.
	again := newPracticeFinding(t, tenant, host, vulnerability.FindingSourceDAST, "nuclei", "")
	again.SetFingerprint(held.Fingerprint())
	again.Hold(vulnerability.HoldThrottledResponse)
	if _, err := repo.CreateBatchWithResult(ctx, []*vulnerability.Finding{again}); err != nil {
		t.Fatal(err)
	}
	if s, _ := verification(t, db, held.ID()); s != "unchecked" {
		t.Fatalf("a held sighting downgraded an unchecked finding to %s", s)
	}
}

// A held finding counts in no risk input of its asset; released, it counts.
func TestHeldFindingOutOfAssetRisk_DB(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewFindingRepository(&DB{DB: db})
	assets := NewAssetRepository(&DB{DB: db})
	tenant := seedTestTenant(ctx, t, db)
	host := seedPracticeAsset(ctx, t, db, tenant, "host", true)

	f := newPracticeFinding(t, tenant, host, vulnerability.FindingSourceDAST, "nuclei", "")
	f.Hold(vulnerability.HoldTargetThrottled)
	if err := repo.Create(ctx, f); err != nil {
		t.Fatal(err)
	}
	count := func() int {
		a, err := assets.GetByID(ctx, tenant, host)
		if err != nil {
			t.Fatal(err)
		}
		return a.FindingCount()
	}
	if n := count(); n != 0 {
		t.Fatalf("held finding counted: %d", n)
	}
	if _, err := db.ExecContext(ctx, `UPDATE findings SET severity = 'critical' WHERE id = $1`, f.ID().String()); err != nil {
		t.Fatal(err)
	}
	if _, crit, err := repo.KEVCriticalCountsByAsset(ctx, tenant); err != nil || crit[host.String()] != 0 {
		t.Fatalf("held finding in critical counts: %v (%v)", crit, err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE findings SET verification_state = 'unchecked', hold_reasons = '{}' WHERE id = $1`, f.ID().String()); err != nil {
		t.Fatal(err)
	}
	if n := count(); n != 1 {
		t.Fatalf("released finding not counted: %d", n)
	}
}
