package postgres

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/server/pkg/domain/advisory"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/threatalert"
)

func testCard(t *testing.T) *advisory.Card {
	t.Helper()
	raw, err := os.ReadFile("../../../pkg/domain/advisory/testdata/OCA-2026-9001.json")
	if err != nil {
		t.Fatal(err)
	}
	c, err := advisory.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func cleanupCards(db *sql.DB) {
	_, _ = db.ExecContext(context.Background(), `DELETE FROM vuln_events WHERE vuln_id LIKE 'OCA-2026-9%';
		DELETE FROM advisory_cards WHERE card_id LIKE 'OCA-2026-9%';
		DELETE FROM advisory_card_stream;
		DELETE FROM cve_records WHERE cve_id LIKE 'CVE-2026-9000%';
		DELETE FROM threat_alerts WHERE vuln_id LIKE 'OCA-2026-9%' OR vuln_id LIKE 'CVE-2026-9000%'`)
}

func stream(seq uint64, sum string) advisory.StreamApplied {
	return advisory.StreamApplied{Sequence: seq, FileSHA256: strings.Repeat(sum, 64), AsOf: time.Date(2026, 11, 18, 19, 0, 0, 0, time.UTC)}
}

// reportedTestCard is the fixture in the fast lane: reported, no reviewer.
func reportedTestCard(t *testing.T, id string) *advisory.Card {
	t.Helper()
	c := testCard(t)
	c.ID = id
	c.Review = advisory.Review{State: advisory.StateReported, Author: "author1"}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	return c
}

// A card is stored once per revision: a replay changes nothing, a new
// revision replaces it and keeps the old one, a withdrawal is an event;
// exploitation is read per vulnerability. Requires DATABASE_URL.
func TestAdvisoryCardApply_DB(t *testing.T) {
	db := catalogTestDB(t)
	ctx := context.Background()
	cleanupCards(db)
	t.Cleanup(func() { cleanupCards(db) })
	repo := NewAdvisoryCardRepository(&DB{DB: db})
	now := time.Date(2026, 11, 18, 20, 0, 0, 0, time.UTC)

	c := testCard(t)
	if sum, err := repo.AppliedFile(ctx); err != nil || sum != "" {
		t.Fatalf("applied file before any stream: %q %v", sum, err)
	}
	res, err := repo.Apply(ctx, []*advisory.Card{c}, stream(42, "a"), now)
	if err != nil || res.Published != 1 {
		t.Fatal(res, err)
	}
	if res, _ = repo.Apply(ctx, []*advisory.Card{c}, stream(43, "b"), now); res.Unchanged != 1 {
		t.Fatalf("replay: %+v", res)
	}
	if sum, err := repo.AppliedFile(ctx); err != nil || sum != strings.Repeat("b", 64) {
		t.Fatalf("applied file %q %v", sum, err)
	}
	ex, err := repo.ExploitationFor(ctx, []string{"CVE-2026-90001", "CVE-2099-0001"})
	if err != nil || ex["CVE-2026-90001"] != advisory.ExploitPoCPublic || len(ex) != 1 {
		t.Fatalf("%v %v", ex, err)
	}

	c2 := testCard(t)
	c2.Revision, c2.Exploitation.Status = 2, string(advisory.ExploitInTheWild)
	c2.History = append(c2.History, advisory.Change{Revision: 2, At: now, Note: "Exploited."})
	if res, err = repo.Apply(ctx, []*advisory.Card{c2}, stream(44, "c"), now); err != nil || res.Updated != 1 {
		t.Fatal(res, err)
	}
	// An older revision never rolls the card back.
	if res, _ = repo.Apply(ctx, []*advisory.Card{c}, stream(45, "d"), now); res.Unchanged != 1 {
		t.Fatalf("rollback: %+v", res)
	}
	c3 := testCard(t)
	c3.Revision, c3.Review.State, c3.Review.WithdrawnReason = 3, advisory.StateWithdrawn, "Vendor retracted."
	if res, err = repo.Apply(ctx, []*advisory.Card{c3}, stream(46, "e"), now); err != nil || res.Withdrawn != 1 {
		t.Fatal(res, err)
	}
	if ex, _ = repo.ExploitationFor(ctx, []string{"CVE-2026-90001"}); len(ex) != 0 {
		t.Fatalf("a withdrawn card still states exploitation: %v", ex)
	}
	var revs, events int
	_ = db.QueryRowContext(ctx, `SELECT count(*) FROM advisory_card_revisions WHERE card_id = $1`, c.ID).Scan(&revs)
	_ = db.QueryRowContext(ctx, `SELECT count(*) FROM vuln_events WHERE vuln_id = $1 AND kind LIKE 'card_%'`, c.ID).Scan(&events)
	if revs != 3 || events != 3 {
		t.Fatalf("revisions %d, events %d; want 3 and 3", revs, events)
	}
}

// One alert per organization and card: the card fans out to the
// organizations running its products, and each sees only its own assets:
// a version-less asset is possible, a version in a card range likely, a
// fixed version left out. Grouped per-vulnerability alerts resolve only in
// the organization planned. Requires DATABASE_URL.
func TestThreatAlertCardKey_DB(t *testing.T) {
	db := catalogTestDB(t)
	ctx := context.Background()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("exec %q: %v", q, err)
		}
	}
	cleanupCards(db)
	t.Cleanup(func() { cleanupCards(db) })
	c := testCard(t)
	c.Severity.Level = "medium" // under the critical CVE record it groups
	if _, err := NewAdvisoryCardRepository(&DB{DB: db}).Apply(ctx, []*advisory.Card{c}, stream(1, "a"), time.Now()); err != nil {
		t.Fatal(err)
	}

	var product string
	exec(`INSERT INTO software_products (part, vendor, name, cpe_vendor, cpe_product, source)
		VALUES ('a', 'example', 'examplehttpd', 'example', 'examplehttpd', 'curated') ON CONFLICT DO NOTHING`)
	if err := db.QueryRowContext(ctx, `SELECT id FROM software_products WHERE tenant_id IS NULL AND part = 'a'
		AND cpe_vendor = 'example' AND cpe_product = 'examplehttpd'`).Scan(&product); err != nil {
		t.Fatal(err)
	}
	// One statement per call: a parameterised query cannot hold several.
	dropProduct := func() {
		for _, q := range []string{`DELETE FROM asset_software WHERE product_id = $1`,
			`DELETE FROM software_versions WHERE product_id = $1`, `DELETE FROM software_products WHERE id = $1`} {
			_, _ = db.ExecContext(context.Background(), q, product)
		}
	}
	t.Cleanup(dropProduct)
	exec(`DELETE FROM software_versions WHERE product_id = $1 AND NOT EXISTS (
		SELECT 1 FROM asset_software s WHERE s.software_version_id = software_versions.id)`, product)
	unknownV, inRange, fixed := shared.NewID(), shared.NewID(), shared.NewID()
	exec(`INSERT INTO software_versions (id, product_id, raw, normalized) VALUES ($1, $2, '', NULL), ($3, $2, '2.4.8', '2.4.8'), ($4, $2, '2.4.9', '2.4.9')`,
		unknownV.String(), product, inRange.String(), fixed.String())

	tA, tB := seedTestTenant(ctx, t, db), seedTestTenant(ctx, t, db)
	a1, a2, b1 := seedTestAsset(ctx, t, db, tA), seedTestAsset(ctx, t, db, tA), seedTestAsset(ctx, t, db, tB)
	sw := func(tenant, asset shared.ID, version shared.ID) {
		exec(`INSERT INTO asset_software (tenant_id, asset_id, product_id, software_version_id, location, source, confidence)
			VALUES ($1, $2, $3, $4, '', 'technology', 80)`, tenant.String(), asset.String(), product, version.String())
	}
	sw(tA, a1, unknownV)
	sw(tA, a2, inRange)
	sw(tB, b1, fixed)

	repo := NewThreatAlertRepository(&DB{DB: db})
	got, err := repo.TenantsAffectedBy(ctx, []string{c.ID})
	if err != nil || len(got[c.ID]) != 2 {
		t.Fatalf("card fan-out %v %v", got, err)
	}
	assetsA, err := repo.AffectedAssets(ctx, tA, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[shared.ID]threatalert.MatchKind{}
	for _, a := range assetsA {
		kinds[a.AssetID] = a.Kind
	}
	if len(assetsA) != 2 || kinds[a1] != threatalert.MatchPossible || kinds[a2] != threatalert.MatchLikely {
		t.Fatalf("A sees %+v", assetsA)
	}
	assetsB, err := repo.AffectedAssets(ctx, tB, c.ID)
	if err != nil || len(assetsB) != 0 {
		t.Fatalf("B (fixed version) sees %+v %v", assetsB, err)
	}

	exec(`INSERT INTO cve_records (cve_id, severity) VALUES ('CVE-2026-90001', 'critical')`)
	v, err := repo.Vuln(ctx, c.ID, time.Time{})
	if err != nil || v == nil || v.CardID != c.ID || v.Exploitation != advisory.ExploitPoCPublic || len(v.Grouped) != 2 ||
		v.Severity != "critical" || len(v.ExploitationSources) != 1 || v.LastEventKind != "card_published" {
		t.Fatalf("%+v %v", v, err)
	}
	groups, err := repo.CardsGrouping(ctx, []string{"CVE-2026-90001", "CVE-2099-0001"})
	if err != nil || groups["CVE-2026-90001"] != c.ID || len(groups) != 1 {
		t.Fatalf("%v %v", groups, err)
	}

	actor := shared.NewID()
	exec(`INSERT INTO threat_alerts (tenant_id, vuln_id, level, tier, state, state_note, state_changed_by, ets)
		VALUES ($1, 'CVE-2026-90001', 'digest', 'possible', 'remediating', 'Patch window on Friday.', $2, 30)`, tA.String(), actor.String())
	exec(`INSERT INTO threat_alerts (tenant_id, vuln_id, level, tier, state, ets)
		VALUES ($1, 'CVE-2026-90001', 'digest', 'possible', 'new', 30)`, tB.String())
	// The card's alert carries on the strongest open triage, per
	// organization.
	if st, err := repo.GroupedTriage(ctx, tA, v.Grouped); err != nil || st != threatalert.StateRemediating {
		t.Fatalf("triage A %s %v", st, err)
	}
	if st, err := repo.GroupedTriage(ctx, tB, v.Grouped); err != nil || st != threatalert.StateNew {
		t.Fatalf("triage B %s %v", st, err)
	}
	n, err := repo.ResolveGrouped(ctx, tA, c.ID, v.Grouped, time.Now())
	if err != nil || n != 1 {
		t.Fatalf("resolved %d %v", n, err)
	}
	var note, grouped string
	var by sql.NullString
	var digest bool
	_ = db.QueryRowContext(ctx, `SELECT state_note, state_changed_by, COALESCE(grouped_into_card, ''), digest_pending FROM threat_alerts
		WHERE tenant_id = $1 AND vuln_id = 'CVE-2026-90001'`, tA.String()).Scan(&note, &by, &grouped, &digest)
	if note != "Patch window on Friday." || by.String != actor.String() || grouped != c.ID || !digest {
		t.Fatalf("grouping lost the person's triage: note %q by %q card %q digest %v", note, by.String, grouped, digest)
	}
	var stateB string
	_ = db.QueryRowContext(ctx, `SELECT state FROM threat_alerts WHERE tenant_id = $1 AND vuln_id = 'CVE-2026-90001'`, tB.String()).Scan(&stateB)
	if stateB != "new" {
		t.Fatalf("another organization's alert changed: %s", stateB)
	}
	items, err := repo.GroupedInto(ctx, c.ID)
	if err != nil || len(items) != 1 || items[0].TenantID != tA {
		t.Fatalf("%v %v", items, err)
	}
}

// At an equal revision only a withdrawal is applied, and both bodies are
// kept; a withdrawn card never comes back at the same revision.
// Requires DATABASE_URL.
func TestAdvisoryCardSameRevision_DB(t *testing.T) {
	db := catalogTestDB(t)
	ctx := context.Background()
	cleanupCards(db)
	t.Cleanup(func() { cleanupCards(db) })
	repo := NewAdvisoryCardRepository(&DB{DB: db})
	now := time.Date(2026, 11, 18, 20, 0, 0, 0, time.UTC)

	c := testCard(t)
	if _, err := repo.Apply(ctx, []*advisory.Card{c}, stream(1, "a"), now); err != nil {
		t.Fatal(err)
	}
	w := testCard(t)
	w.Review.State, w.Review.WithdrawnReason = advisory.StateWithdrawn, "Vendor retracted."
	if res, err := repo.Apply(ctx, []*advisory.Card{w}, stream(2, "b"), now); err != nil || res.Withdrawn != 1 {
		t.Fatal(res, err)
	}
	if res, err := repo.Apply(ctx, []*advisory.Card{testCard(t)}, stream(3, "c"), now); err != nil || res.Unchanged != 1 {
		t.Fatalf("withdrawn -> reviewed at an equal revision applied: %+v %v", res, err)
	}
	var state string
	var bodies int
	_ = db.QueryRowContext(ctx, `SELECT review_state FROM advisory_cards WHERE card_id = $1`, c.ID).Scan(&state)
	_ = db.QueryRowContext(ctx, `SELECT count(*) FROM advisory_card_revisions WHERE card_id = $1 AND revision = 1`, c.ID).Scan(&bodies)
	if state != advisory.StateWithdrawn || bodies != 2 {
		t.Fatalf("state %s, revision-1 bodies %d; want withdrawn and 2", state, bodies)
	}
}

// A reported card (fast lane) alerts but scores nothing from its own
// exploitation and groups nothing. Requires DATABASE_URL.
func TestAdvisoryCardReported_DB(t *testing.T) {
	db := catalogTestDB(t)
	ctx := context.Background()
	cleanupCards(db)
	t.Cleanup(func() { cleanupCards(db) })
	c := reportedTestCard(t, "OCA-2026-9003")
	if res, err := NewAdvisoryCardRepository(&DB{DB: db}).Apply(ctx, []*advisory.Card{c}, stream(1, "a"), time.Now()); err != nil || res.Published != 1 {
		t.Fatal(res, err)
	}
	repo := NewThreatAlertRepository(&DB{DB: db})
	if ex, err := exploitationFor(ctx, &DB{DB: db}, c.VulnIDs()); err != nil || len(ex) != 0 {
		t.Fatalf("a reported card's exploitation counted: %v %v", ex, err)
	}
	if g, err := repo.CardsGrouping(ctx, c.VulnIDs()); err != nil || len(g) != 0 {
		t.Fatalf("a reported card groups CVE alerts: %v %v", g, err)
	}
	v, err := repo.Vuln(ctx, c.ID, time.Time{})
	if err != nil || v == nil || !v.CardReported || v.Exploitation != "" || len(v.ExploitationSources) != 0 {
		t.Fatalf("%+v %v", v, err)
	}
}

// A card keeps the KEV listing and the EPSS score of a grouped CVE that has
// no cve_records row yet (CISA lists a CVE before its record arrives), so the
// card alert is never weaker than the alert it replaces. Requires DATABASE_URL.
func TestAdvisoryCardKEVWithoutRecord_DB(t *testing.T) {
	db := catalogTestDB(t)
	ctx := context.Background()
	cleanupCards(db)
	t.Cleanup(func() {
		cleanupCards(db)
		_, _ = db.ExecContext(context.Background(), `DELETE FROM kev_catalog WHERE cve_id LIKE 'CVE-2026-9000%';
			DELETE FROM epss_scores WHERE cve_id LIKE 'CVE-2026-9000%'`)
	})
	c := testCard(t)
	if res, err := NewAdvisoryCardRepository(&DB{DB: db}).Apply(ctx, []*advisory.Card{c}, stream(1, "a"), time.Now()); err != nil || res.Published != 1 {
		t.Fatal(res, err)
	}
	ids := c.VulnIDs()
	var cve string
	for _, id := range ids {
		if strings.HasPrefix(id, "CVE-2026-9000") {
			cve = id
			break
		}
	}
	if cve == "" {
		t.Fatalf("fixture groups no CVE-2026-9000x id: %v", ids)
	}
	// No cve_records row for it (cleanupCards removed them): only the lists.
	if _, err := db.ExecContext(ctx, `INSERT INTO kev_catalog (cve_id, vendor_project, product, vulnerability_name, date_added, due_date, known_ransomware_campaign_use)
		VALUES ($1, 'Vendor', 'Widget', 'Widget RCE', '2026-11-18', '2026-12-09', 'Known')`, cve); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO epss_scores (cve_id, epss_score, model_version) VALUES ($1, 0.87654, 'v2025')`, cve); err != nil {
		t.Fatal(err)
	}
	v, err := NewThreatAlertRepository(&DB{DB: db}).Vuln(ctx, c.ID, time.Time{})
	if err != nil || v == nil {
		t.Fatal(v, err)
	}
	if !v.InKEV || !v.KEVRansomware || v.KEVDateAdded == nil {
		t.Fatalf("card lost the KEV listing of a CVE with no record: inKEV=%v ransomware=%v added=%v", v.InKEV, v.KEVRansomware, v.KEVDateAdded)
	}
	if v.EPSS == nil || *v.EPSS < 0.87 || *v.EPSS > 0.88 {
		t.Fatalf("card lost the EPSS score of a CVE with no record: %v", v.EPSS)
	}
}
