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

// A held finding sighted again by a later run goes through the enrichment
// (or sighting-only) path, which never touches its state; the later run's
// evaluation releases it when its result does not name the host as
// throttled. It then re-enters the asset's risk inputs (and the asset is
// queued for a rescore). Nothing else is released: a host the later run
// names as throttled, a hold that came from the matched response, a
// finding the later run did not see, another tenant.
func TestReleaseRunFindings_EnrichPath_DB(t *testing.T) {
	ctx := context.Background()
	f := newCoverageFixture(t)
	repo := NewFindingRepository(&DB{DB: f.db})
	host := asset.HostOf(assetName(t, f.db, f.host))
	otherHost := asset.HostOf(assetName(t, f.db, f.otherHost))

	cmd1, r1 := f.run(t, f.scan, "completed", f.host, f.otherHost)
	enriched := f.finding(t, f.host, "nuclei", r1, nil)
	f.exec(t, `UPDATE findings SET severity = 'critical' WHERE id = $1`, enriched)
	sighted := f.finding(t, f.host, "nuclei", r1, nil)
	gapped := f.finding(t, f.otherHost, "nuclei", r1, nil)
	unseen := f.finding(t, f.host, "nuclei", r1, nil)
	if got, err := repo.HoldGapFindings(ctx, f.tenant, cmd1, "", []string{host, otherHost}, []string{vulnerability.HoldTargetThrottled}); err != nil || len(got) != 4 {
		t.Fatalf("hold: %v (%v)", got, err)
	}
	response := f.finding(t, f.host, "nuclei", r1, nil)
	f.exec(t, `UPDATE findings SET verification_state = 'held', hold_reasons = '{edge_block_page}' WHERE id = $1`, response)

	// The later run sights them again: enrichment for three, the
	// sighting-only update for one.
	cmd2, r2 := f.run(t, f.scan, "completed", f.host, f.otherHost)
	loaded, err := repo.GetByIDs(ctx, f.tenant, []shared.ID{enriched, gapped, response})
	if err != nil || len(loaded) != 3 {
		t.Fatalf("load: %v (%v)", loaded, err)
	}
	for _, x := range loaded {
		x.SetScanID(r2)
	}
	if _, err := repo.EnrichBatchByFingerprints(ctx, f.tenant, loaded, r2); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.UpdateScanIDBatchByFingerprints(ctx, f.tenant, []string{"fp-" + sighted.String()}, r2, "nuclei"); err != nil {
		t.Fatal(err)
	}
	// The sighting paths alone leave the hold in place (the defect).
	for _, id := range []shared.ID{enriched, sighted} {
		if s, _ := verification(t, f.db, id); s != "held" {
			t.Fatalf("sighting changed the state to %s", s)
		}
	}

	// SECURITY: another tenant asking for this command releases nothing.
	g := newCoverageFixture(t)
	if got, err := repo.ReleaseRunFindings(ctx, g.tenant, cmd2, nil, []string{vulnerability.HoldTargetThrottled}); err != nil || len(got) != 0 {
		t.Fatalf("released across tenants: %v (%v)", got, err)
	}
	// The earlier, throttled command's own reports no longer hold the
	// sighting (scan_id moved on): evaluating it again releases nothing.
	if got, err := repo.ReleaseRunFindings(ctx, f.tenant, cmd1, []string{host, otherHost}, []string{vulnerability.HoldTargetThrottled}); err != nil || len(got) != 0 {
		t.Fatalf("throttled run released %v (%v)", got, err)
	}

	clearQueue := func() { f.exec(t, `DELETE FROM asset_risk_queue WHERE tenant_id = $1`, f.tenant) }
	queued := func() bool {
		var q bool
		if err := f.db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM asset_risk_queue WHERE asset_id = $1)`, f.host.String()).Scan(&q); err != nil {
			t.Fatal(err)
		}
		return q
	}
	clearQueue()
	got, err := repo.ReleaseRunFindings(ctx, f.tenant, cmd2, []string{otherHost}, []string{vulnerability.HoldTargetThrottled})
	if err != nil {
		t.Fatal(err)
	}
	if !sameIDs(got, []shared.ID{enriched, sighted}) {
		t.Fatalf("released %v, want the two findings seen again on the clean host", got)
	}
	for _, id := range []shared.ID{enriched, sighted} {
		if s, r := verification(t, f.db, id); s != "unchecked" || len(r) != 0 {
			t.Errorf("released: %s %v", s, r)
		}
	}
	for name, id := range map[string]shared.ID{"gapped host": gapped, "response hold": response, "not seen again": unseen} {
		if s, _ := verification(t, f.db, id); s != "held" {
			t.Errorf("%s: %s, want held", name, s)
		}
	}
	// Back in the risk inputs, and the asset is queued for a rescore.
	if _, crit, err := repo.KEVCriticalCountsByAsset(ctx, f.tenant); err != nil || crit[f.host.String()] != 1 {
		t.Fatalf("released critical not counted: %v (%v)", crit, err)
	}
	if !queued() {
		t.Fatal("asset not queued for a rescore after the release")
	}
	// Idempotent.
	if again, err := repo.ReleaseRunFindings(ctx, f.tenant, cmd2, []string{otherHost}, []string{vulnerability.HoldTargetThrottled}); err != nil || len(again) != 0 {
		t.Fatalf("second release %v (%v)", again, err)
	}
	// Holding queues the asset too.
	clearQueue()
	f.exec(t, `UPDATE findings SET verification_state = 'held', hold_reasons = '{target_throttled}' WHERE id = $1`, enriched)
	if !queued() {
		t.Fatal("asset not queued for a rescore after a hold")
	}
}

// One command sends the held-critical notice once, however many callers.
func TestOnceHeldNotice_DB(t *testing.T) {
	ctx := context.Background()
	f := newCoverageFixture(t)
	repo := NewFindingRepository(&DB{DB: f.db})
	cmd := shared.NewID()
	clean := func(tenant shared.ID) {
		t.Cleanup(func() {
			_, _ = f.db.ExecContext(context.Background(), `DELETE FROM notification_outbox WHERE tenant_id = $1`, tenant.String())
		})
	}
	clean(f.tenant)
	send := func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO notification_outbox (tenant_id, event_type, aggregate_type, aggregate_id, title)
			VALUES ($1, 'finding_held_critical', 'scan', $2, 't')`, f.tenant.String(), cmd.String())
		return err
	}
	results := make(chan bool, 8)
	for range 8 {
		go func() {
			ok, err := repo.OnceHeldNotice(ctx, f.tenant, cmd, "finding_held_critical", send)
			if err != nil {
				t.Error(err)
			}
			results <- ok
		}()
	}
	sent := 0
	for range 8 {
		if <-results {
			sent++
		}
	}
	var n int
	if err := f.db.QueryRowContext(ctx, `SELECT count(*) FROM notification_outbox WHERE tenant_id = $1`, f.tenant.String()).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if sent != 1 || n != 1 {
		t.Fatalf("sent %d, rows %d, want one", sent, n)
	}
	// SECURITY: another tenant's command with the same id is its own.
	g := newCoverageFixture(t)
	clean(g.tenant)
	ok, err := repo.OnceHeldNotice(ctx, g.tenant, cmd, "finding_held_critical", func(*sql.Tx) error { return nil })
	if err != nil || !ok {
		t.Fatalf("another tenant's notice suppressed: %v (%v)", ok, err)
	}
}

func sameIDs(a, b []shared.ID) bool {
	if len(a) != len(b) {
		return false
	}
	for _, x := range a {
		if !slices.Contains(b, x) {
			return false
		}
	}
	return true
}
