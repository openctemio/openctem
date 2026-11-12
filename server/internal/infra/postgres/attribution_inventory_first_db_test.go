package postgres

import (
	"context"
	"database/sql"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// keepReviewGate turns scope.review_before_inventory on for the tenants: an
// automatic needs_review decision is then stored as needs_review (the review
// queue) instead of discovered.
func keepReviewGate(ctx context.Context, t *testing.T, db *sql.DB, tenants ...shared.ID) {
	t.Helper()
	for _, id := range tenants {
		if _, err := db.ExecContext(ctx, `UPDATE tenants SET settings = jsonb_set(COALESCE(settings, '{}'::jsonb), '{scope}',
			COALESCE(settings->'scope', '{}'::jsonb) || '{"review_before_inventory": true}'::jsonb) WHERE id = $1`, id.String()); err != nil {
			t.Fatal(err)
		}
	}
}

// Inventory first (research/124, RFC-054 §15) on the real schema: an
// automatic needs_review decision is stored as discovered unless the
// tenant keeps the review gate; a candidate stays a candidate; automation
// never stores a person's decision state. Requires DATABASE_URL.
func TestAttributionInventoryFirst(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	repo := NewAttributionRepository(&DB{DB: db})
	open := seedTestTenant(ctx, t, db)
	gated := seedTestTenant(ctx, t, db)
	keepReviewGate(ctx, t, db, gated)

	asset := func(tid shared.ID, name, typ string) string {
		t.Helper()
		id := shared.NewID().String()
		if _, err := db.ExecContext(ctx, `INSERT INTO assets (id, tenant_id, name, asset_type, status) VALUES ($1, $2, $3, $4, 'active')`,
			id, tid.String(), name, typ); err != nil {
			t.Fatal(err)
		}
		return id
	}
	save := func(tid shared.ID, id string, s attribution.State) {
		t.Helper()
		if err := repo.SaveAutomatic(ctx, tid, id, attribution.Decision{State: s, Confidence: 60, Reason: attribution.RuleScanDiscovered}); err != nil {
			t.Fatal(err)
		}
	}
	rec := func(tid shared.ID, id string) attribution.Record {
		t.Helper()
		m, err := repo.Records(ctx, tid, []string{id})
		if err != nil {
			t.Fatal(err)
		}
		return m[id]
	}

	a := asset(open, "found.example.com", "subdomain")
	g := asset(gated, "found.example.com", "subdomain")
	save(open, a, attribution.StateNeedsReview)
	save(gated, g, attribution.StateNeedsReview)
	if s := rec(open, a).State; s != attribution.StateDiscovered {
		t.Fatalf("open tenant: %s, want discovered", s)
	}
	if s := rec(gated, g).State; s != attribution.StateNeedsReview {
		t.Fatalf("gated tenant: %s, want needs_review", s)
	}
	// A candidate stays a candidate (unsolicited reports never fill the
	// inventory).
	c := asset(open, "unsolicited.example.com", "subdomain")
	save(open, c, attribution.StateCandidate)
	if s := rec(open, c).State; s != attribution.StateCandidate {
		t.Fatalf("candidate stored as %s", s)
	}
	// A person's decision states cannot be stored by automation.
	if err := repo.SaveAutomatic(ctx, open, a, attribution.Decision{State: attribution.StateRejected}); err == nil {
		t.Fatal("automation stored a rejection")
	}
}
