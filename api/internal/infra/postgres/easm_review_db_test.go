package postgres

import (
	"context"
	"sort"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/easm"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// The review queue, bulk decisions and the asset-list attribution filter
// against the real schema: tenant isolation, data-scope narrowing, deleted
// assets, and the legacy (no record) semantics. Requires DATABASE_URL.
func TestEASMReviewQueue(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	repo := NewAttributionRepository(&DB{DB: db})
	tenant := seedTestTenant(ctx, t, db)
	other := seedTestTenant(ctx, t, db)

	review := seedTestAsset(ctx, t, db, tenant).String()
	candidate := seedTestAsset(ctx, t, db, tenant).String()
	rejected := seedTestAsset(ctx, t, db, tenant).String()
	confirmed := seedTestAsset(ctx, t, db, tenant).String()
	legacy := seedTestAsset(ctx, t, db, tenant).String()
	deleted := seedTestAsset(ctx, t, db, tenant).String()
	foreign := seedTestAsset(ctx, t, db, other).String()

	save := func(tid shared.ID, id string, st attribution.State, c int) {
		t.Helper()
		if err := repo.SaveAutomatic(ctx, tid, id, attribution.Decision{State: st, Confidence: c, Reason: attribution.RuleAssertedRoot}); err != nil {
			t.Fatal(err)
		}
	}
	save(tenant, review, attribution.StateNeedsReview, 85)
	save(tenant, candidate, attribution.StateCandidate, 30)
	save(tenant, confirmed, attribution.StateConfirmed, 99)
	save(tenant, deleted, attribution.StateNeedsReview, 85)
	save(other, foreign, attribution.StateNeedsReview, 85)
	if _, err := repo.SaveDecision(ctx, tenant, rejected, attribution.StateRejected, ""); err != nil {
		t.Fatal(err)
	}
	if err := repo.UpsertEvidence(ctx, tenant, []attribution.Evidence{{AssetID: review, Rule: attribution.RuleAssertedRoot,
		Technique: "cert_transparency", Source: "crt.sh", Weight: 0.85}}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE assets SET deleted_at = now() WHERE id = $1`, deleted); err != nil {
		t.Fatal(err)
	}

	queue := func(scope *shared.ID, q easm.ReviewQuery) []string {
		t.Helper()
		if q.States == nil {
			q.States = []attribution.State{attribution.StateNeedsReview, attribution.StateCandidate}
		}
		if q.Limit == 0 {
			q.Limit = 50
		}
		page, err := repo.ListForReview(ctx, tenant, scope, q)
		if err != nil {
			t.Fatal(err)
		}
		if page.Total != len(page.Items) {
			t.Fatalf("total %d != items %d", page.Total, len(page.Items))
		}
		ids := make([]string, len(page.Items))
		for i, it := range page.Items {
			ids[i] = it.AssetID
			if it.AssetID == review && (len(it.Evidence) != 1 || it.Evidence[0].Source != "crt.sh") {
				t.Errorf("evidence = %+v", it.Evidence)
			}
		}
		return ids
	}

	// Most confident first; no foreign, deleted, rejected or confirmed rows.
	if got := queue(nil, easm.ReviewQuery{}); len(got) != 2 || got[0] != review || got[1] != candidate {
		t.Fatalf("queue = %v, want [review candidate]", got)
	}
	if got := queue(nil, easm.ReviewQuery{MinConfidence: 50}); len(got) != 1 || got[0] != review {
		t.Fatalf("min confidence = %v", got)
	}
	if got := queue(nil, easm.ReviewQuery{States: []attribution.State{attribution.StateRejected}}); len(got) != 1 || got[0] != rejected {
		t.Fatalf("rejected tab = %v", got)
	}
	if got := queue(nil, easm.ReviewQuery{Search: "%"}); len(got) != 0 {
		t.Fatalf("LIKE wildcard not escaped: %v", got)
	}

	// A member scoped to the candidate sees only it.
	user := shared.NewID()
	if _, err := db.ExecContext(ctx, `INSERT INTO users (id, email, name) VALUES ($1, $2, 'scoped')`, user.String(), user.String()+"@easm.test"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, user.String()) })
	if _, err := db.ExecContext(ctx, `INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id) VALUES ($1, $2, $3)`,
		user.String(), tenant.String(), candidate); err != nil {
		t.Fatal(err)
	}
	if got := queue(&user, easm.ReviewQuery{}); len(got) != 1 || got[0] != candidate {
		t.Fatalf("scoped queue = %v", got)
	}

	// Bulk decision: the foreign and deleted assets are not written; the
	// previous states come back ("" for the legacy asset).
	prev, err := repo.SaveDecisions(ctx, tenant, []string{review, legacy, foreign, deleted}, attribution.StateConfirmed, user.String())
	if err != nil {
		t.Fatal(err)
	}
	if len(prev) != 2 || prev[review] != attribution.StateNeedsReview || prev[legacy] != "" {
		t.Fatalf("prev = %v", prev)
	}
	var st string
	_ = db.QueryRowContext(ctx, `SELECT state FROM asset_attributions WHERE asset_id = $1`, foreign).Scan(&st)
	if st != "needs_review" {
		t.Fatalf("foreign tenant's attribution changed to %q", st)
	}
	recs, _ := repo.Records(ctx, tenant, []string{review, legacy})
	if !recs[review].HumanDecided || recs[review].State != attribution.StateConfirmed || !recs[legacy].HumanDecided {
		t.Fatalf("records = %+v", recs)
	}
	// Automation leaves a decided row alone.
	save(tenant, review, attribution.StateNeedsReview, 85)
	if recs, _ = repo.Records(ctx, tenant, []string{review}); recs[review].State != attribution.StateConfirmed {
		t.Fatal("automation overrode a review-queue decision")
	}

	// Asset-list filter.
	assets := NewAssetRepository(&DB{DB: db})
	list := func(values ...string) []string {
		t.Helper()
		af, _, err := attribution.ParseFilter(values)
		if err != nil {
			t.Fatal(err)
		}
		res, err := assets.List(ctx, asset.NewFilter().WithTenantID(tenant.String()).WithAttribution(af), asset.NewListOptions(), pagination.New(1, 100))
		if err != nil {
			t.Fatal(err)
		}
		ids := make([]string, len(res.Data))
		for i, a := range res.Data {
			ids[i] = a.ID().String()
		}
		sort.Strings(ids)
		return ids
	}
	want := func(ids ...string) []string { sort.Strings(ids); return ids }
	eq := func(a, b []string) bool {
		if len(a) != len(b) {
			return false
		}
		for i := range a {
			if a[i] != b[i] {
				return false
			}
		}
		return true
	}
	// review and legacy are now decided confirmed; confirmed is automatic.
	unrecorded := seedTestAsset(ctx, t, db, tenant).String()
	cases := map[string]struct {
		in   []string
		want []string
	}{
		"confirmed includes unrecorded": {[]string{"confirmed"}, want(review, legacy, confirmed, unrecorded)},
		"unknown is unrecorded only":    {[]string{"unknown"}, want(unrecorded)},
		"unconfirmed is the queue":      {[]string{"unconfirmed"}, want(candidate)},
		"rejected":                      {[]string{"rejected"}, want(rejected)},
		"approved hides queue+rejected": {[]string{"approved"}, want(review, legacy, confirmed, unrecorded)},
	}
	for name, tc := range cases {
		if got := list(tc.in...); !eq(got, tc.want) {
			t.Errorf("%s: got %v, want %v", name, got, tc.want)
		}
	}
}
