package postgres

import (
	"context"
	"database/sql"
	"os"
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
		DELETE FROM threat_alerts WHERE vuln_id LIKE 'OCA-2026-9%' OR vuln_id LIKE 'CVE-2026-9000%'`)
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
	res, err := repo.Apply(ctx, []*advisory.Card{c}, 42, now)
	if err != nil || res.Published != 1 {
		t.Fatal(res, err)
	}
	if res, _ = repo.Apply(ctx, []*advisory.Card{c}, 43, now); res.Unchanged != 1 {
		t.Fatalf("replay: %+v", res)
	}
	asOf, err := repo.AsOf(ctx)
	if err != nil || !asOf.Equal(*c.Review.ReviewedAt) {
		t.Fatalf("as of %v %v", asOf, err)
	}
	ex, err := repo.ExploitationFor(ctx, []string{"CVE-2026-90001", "CVE-2099-0001"})
	if err != nil || ex["CVE-2026-90001"] != advisory.ExploitPoCPublic || len(ex) != 1 {
		t.Fatalf("%v %v", ex, err)
	}

	c2 := testCard(t)
	c2.Revision, c2.Exploitation.Status = 2, string(advisory.ExploitInTheWild)
	c2.History = append(c2.History, advisory.Change{Revision: 2, At: now, Note: "Exploited."})
	if res, err = repo.Apply(ctx, []*advisory.Card{c2}, 44, now); err != nil || res.Updated != 1 {
		t.Fatal(res, err)
	}
	// An older revision never rolls the card back.
	if res, _ = repo.Apply(ctx, []*advisory.Card{c}, 45, now); res.Unchanged != 1 {
		t.Fatalf("rollback: %+v", res)
	}
	c3 := testCard(t)
	c3.Revision, c3.Review.State, c3.Review.WithdrawnReason = 3, advisory.StateWithdrawn, "Vendor retracted."
	if res, err = repo.Apply(ctx, []*advisory.Card{c3}, 46, now); err != nil || res.Withdrawn != 1 {
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
	if _, err := NewAdvisoryCardRepository(&DB{DB: db}).Apply(ctx, []*advisory.Card{c}, 1, time.Now()); err != nil {
		t.Fatal(err)
	}

	var product string
	exec(`INSERT INTO software_products (part, vendor, name, cpe_vendor, cpe_product, source)
		VALUES ('a', 'example', 'examplehttpd', 'example', 'examplehttpd', 'curated') ON CONFLICT DO NOTHING`)
	if err := db.QueryRowContext(ctx, `SELECT id FROM software_products WHERE tenant_id IS NULL AND part = 'a'
		AND cpe_vendor = 'example' AND cpe_product = 'examplehttpd'`).Scan(&product); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM asset_software WHERE product_id = $1;
			DELETE FROM software_versions WHERE product_id = $1; DELETE FROM software_products WHERE id = $1`, product)
	})
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

	v, err := repo.Vuln(ctx, c.ID, time.Time{})
	if err != nil || v == nil || v.CardID != c.ID || v.Exploitation != advisory.ExploitPoCPublic || len(v.Grouped) != 2 ||
		v.Severity != "critical" || len(v.ExploitationSources) != 1 || v.LastEventKind != "card_published" {
		t.Fatalf("%+v %v", v, err)
	}
	groups, err := repo.CardsGrouping(ctx, []string{"CVE-2026-90001", "CVE-2099-0001"})
	if err != nil || groups["CVE-2026-90001"] != c.ID || len(groups) != 1 {
		t.Fatalf("%v %v", groups, err)
	}

	for _, tenant := range []shared.ID{tA, tB} {
		exec(`INSERT INTO threat_alerts (tenant_id, vuln_id, level, tier, state, ets)
			VALUES ($1, 'CVE-2026-90001', 'digest', 'possible', 'new', 30)`, tenant.String())
	}
	n, err := repo.ResolveGrouped(ctx, tA, c.ID, v.Grouped, time.Now())
	if err != nil || n != 1 {
		t.Fatalf("resolved %d %v", n, err)
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
