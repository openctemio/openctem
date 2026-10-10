package postgres

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Continuous discovery (RFC-071): a selector with NewOnly returns only the
// assets under the root that came into scope since the previous successful
// run: attribution confirmed since then, or first seen since then with no
// record. needs_review, candidate and rejected names never; another tenant's
// rows never. Requires DATABASE_URL.
func TestScanSelectorRepository_NewSinceLastRun(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	r := NewScanSelectorRepository(&DB{DB: sqlDB})

	tenant, other := shared.NewID(), shared.NewID()
	for _, id := range []shared.ID{tenant, other} {
		if _, err := sqlDB.ExecContext(ctx, `INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, id.String(), "new-"+id.String()); err != nil {
			t.Fatalf("tenant: %v", err)
		}
	}
	t.Cleanup(func() {
		for _, id := range []shared.ID{tenant, other} {
			_, _ = sqlDB.ExecContext(context.Background(), `DELETE FROM asset_attributions WHERE tenant_id = $1`, id.String())
			_, _ = sqlDB.ExecContext(context.Background(), `DELETE FROM assets WHERE tenant_id = $1`, id.String())
			_, _ = sqlDB.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, id.String())
		}
	})
	now := time.Now().UTC()
	lastRun := now.Add(-24 * time.Hour)
	add := func(tid shared.ID, name string, firstSeen time.Time, state string, decided time.Time) {
		t.Helper()
		id := shared.NewID().String()
		if _, err := sqlDB.ExecContext(ctx, `INSERT INTO assets (id, tenant_id, name, asset_type, status, exposure, criticality, first_seen, last_seen)
			VALUES ($1, $2, $3, 'subdomain', 'active', 'public', 'medium', $4, $5)`, id, tid.String(), name, firstSeen, now); err != nil {
			t.Fatalf("asset %s: %v", name, err)
		}
		if state == "" {
			return
		}
		if _, err := sqlDB.ExecContext(ctx, `INSERT INTO asset_attributions (asset_id, tenant_id, state, confidence, decided_at, updated_at)
			VALUES ($1, $2, $3, 90, $4, $4)`, id, tid.String(), state, decided); err != nil {
			t.Fatalf("attribution %s: %v", name, err)
		}
	}
	old := now.AddDate(0, 0, -30)
	add(tenant, "fresh-confirmed.new.example", old, "confirmed", now.Add(-time.Hour)) // found long ago, confirmed today
	add(tenant, "old-confirmed.new.example", old, "confirmed", old)                   // confirmed before the last run
	add(tenant, "fresh-unrecorded.new.example", now.Add(-time.Hour), "", time.Time{}) // auto-joined child, new
	add(tenant, "old-unrecorded.new.example", old, "", time.Time{})
	add(tenant, "review.new.example", now.Add(-time.Hour), "needs_review", now.Add(-time.Hour))
	add(tenant, "rejected.new.example", now.Add(-time.Hour), "rejected", now.Add(-time.Hour))
	add(other, "leak.new.example", now.Add(-time.Hour), "confirmed", now.Add(-time.Hour))

	names := func(q scan.SelectorQuery) []string {
		t.Helper()
		q.UnderDomain, q.Limit = "new.example", 100
		got, err := r.ListSelectorAssets(ctx, q)
		if err != nil {
			t.Fatalf("list %+v: %v", q, err)
		}
		out := make([]string, 0, len(got))
		for _, m := range got {
			out = append(out, m.Name)
		}
		slices.Sort(out)
		return out
	}
	got := names(scan.SelectorQuery{TenantID: tenant, NewOnly: true, NewSince: &lastRun})
	if want := []string{"fresh-confirmed.new.example", "fresh-unrecorded.new.example"}; !slices.Equal(got, want) {
		t.Fatalf("new since last run = %v, want %v", got, want)
	}
	// First run: every confirmed or unrecorded asset, never needs_review or rejected.
	got = names(scan.SelectorQuery{TenantID: tenant, NewOnly: true})
	if want := []string{"fresh-confirmed.new.example", "fresh-unrecorded.new.example", "old-confirmed.new.example", "old-unrecorded.new.example"}; !slices.Equal(got, want) {
		t.Fatalf("first run = %v, want %v", got, want)
	}
	if got := names(scan.SelectorQuery{TenantID: other, NewOnly: true, NewSince: &lastRun}); !slices.Equal(got, []string{"leak.new.example"}) {
		t.Fatalf("other tenant = %v: one tenant's rows must not answer for another", got)
	}
}
