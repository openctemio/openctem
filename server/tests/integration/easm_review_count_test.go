package integration

// The attack surface Review badge on a real database: it counts exactly the
// decisions the Review tab lists. Discovered names (in the inventory
// already) and an addresses card that offers nothing (only shared or CDN
// addresses) are not decisions; names that need review are. Another
// organization's items never count.

import (
	"context"
	"testing"

	easmapp "github.com/openctemio/openctem/api/internal/app/easm"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func TestEASMReviewCount_EqualsReviewTab(t *testing.T) {
	db := openLifecycleDB(t)
	ctx := context.Background()
	pg := &postgres.DB{DB: db}
	tenantA := seedLifecycleTenant(ctx, t, db)
	tenantB := seedLifecycleTenant(ctx, t, db)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	add := func(tenant shared.ID, name, typ string, st attribution.State) shared.ID {
		id := seedOwnedAsset(t, db, tenant, name, typ)
		automatic(t, db, tenant, id, st)
		return id
	}

	rules := ruleService(db)
	org := func(context.Context, shared.ID) (string, error) { return "Count Org", nil }
	h := handler.NewEASMHandler(easmapp.NewService(postgres.NewEASMSummaryRepository(pg), nil), logger.NewNop()).
		SetSuggestions(easmapp.NewSuggestionService(postgres.NewAttributionRepository(pg), ownershipGate(db), nil, org, nil)).
		SetRules(rules)
	count := func(tenant shared.ID) int {
		t.Helper()
		n, err := h.ReviewCount(ctx, tenant)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	// What the Review tab lists: the name rules over the states it asks for.
	listed := func(tenant shared.ID) int {
		t.Helper()
		rs, err := rules.Suggest(ctx, tenant, []attribution.State{attribution.StateNeedsReview, attribution.StateCandidate}, 50)
		if err != nil {
			t.Fatal(err)
		}
		return easmapp.NameRuleCards(rs)
	}

	// Discovered names under many parents: before, each parent counted as
	// a waiting rule (up to 50) although the tab lists none.
	for _, n := range []string{"a.one.count-a.example", "b.two.count-a.example", "c.three.count-a.example", "d.four.count-a.example"} {
		add(tenantA, n, "subdomain", attribution.StateDiscovered)
	}
	// An in-scope name resolving to a CDN edge address only: the card lists
	// it apart and offers nothing.
	exec(`INSERT INTO scope_targets (tenant_id, target_type, pattern) VALUES ($1, 'domain', 'www.count-a.example')`, tenantA.String())
	www := add(tenantA, "www.count-a.example", "subdomain", attribution.StateConfirmed)
	edge := add(tenantA, "104.16.9.9", "ip_address", attribution.StateNeedsReview)
	exec(`INSERT INTO asset_relationships (tenant_id, source_asset_id, target_asset_id, relationship_type) VALUES ($1, $2, $3, 'resolves_to')`,
		tenantA.String(), www.String(), edge.String())

	if got := count(tenantA); got != 0 || listed(tenantA) != 0 {
		t.Fatalf("nothing waits, badge %d, listed %d", got, listed(tenantA))
	}
	out, err := easmapp.NewSuggestionService(postgres.NewAttributionRepository(pg), ownershipGate(db), nil, org, nil).Cards(ctx, tenantA, true)
	if err != nil || len(out.Cards) != 1 || out.Cards[0].Count != 0 || out.Cards[0].SharedCount != 1 {
		t.Fatalf("shared-only card %+v %v", out, err)
	}

	// Two names that need review under one parent: the tab lists their
	// rules and the badge says the same number.
	add(tenantA, "x.review.count-a.example", "subdomain", attribution.StateNeedsReview)
	add(tenantA, "y.review.count-a.example", "subdomain", attribution.StateCandidate)
	want := listed(tenantA)
	if want == 0 {
		t.Fatal("the names that need review produced no rule")
	}
	if got := count(tenantA); got != want {
		t.Fatalf("badge %d, Review tab lists %d", got, want)
	}

	// Another organization's waiting names never reach tenant A, and its
	// own badge counts only its own.
	add(tenantB, "z.review.count-b.example", "subdomain", attribution.StateNeedsReview)
	if got := count(tenantA); got != want {
		t.Fatalf("tenant B's name changed tenant A's badge: %d", got)
	}
	if got := count(tenantB); got != listed(tenantB) || got == 0 {
		t.Fatalf("tenant B badge %d, listed %d", got, listed(tenantB))
	}
}
