package postgres

import (
	"context"
	"sort"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// The expiry filter reads every property of format expiry (a certificate's
// not_after, a domain's expires_at). A malformed or missing value never
// matches and never fails the list; another tenant's assets never match.
func TestAssetExpiryFilter_List(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewAssetRepository(&DB{DB: db})
	tenant := seedTestTenant(ctx, t, db)
	other := seedTestTenant(ctx, t, db)

	now := time.Now().UTC()
	day := 24 * time.Hour
	add := func(tn shared.ID, name, typ, props string) {
		t.Helper()
		if _, err := db.ExecContext(ctx,
			`INSERT INTO assets (id, tenant_id, name, asset_type, properties) VALUES ($1, $2, $3, $4, $5::jsonb)`,
			shared.NewID().String(), tn.String(), name, typ, props); err != nil {
			t.Fatalf("insert %s: %v", name, err)
		}
	}
	ts := func(d time.Duration) string { return now.Add(d).Format(time.RFC3339) }
	add(tenant, "expired.example", "certificate", `{"not_after": "`+ts(-2*day)+`"}`)
	add(tenant, "soon.example", "certificate", `{"not_after": "`+ts(10*day)+`"}`)
	add(tenant, "later.example", "certificate", `{"not_after": "`+ts(200*day)+`"}`)
	add(tenant, "garbled.example", "certificate", `{"not_after": "next tuesday"}`)
	add(tenant, "domain.example", "domain", `{"expires_at": "`+ts(20*day)+`"}`)
	add(tenant, "host.example", "host", `{}`)
	add(other, "other-tenant.example", "certificate", `{"not_after": "`+ts(5*day)+`"}`)

	list := func(f asset.Filter) []string {
		t.Helper()
		res, err := repo.List(ctx, f.WithTenantID(tenant.String()), asset.NewListOptions(), pagination.New(1, 50))
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		names := make([]string, 0, len(res.Data))
		for _, a := range res.Data {
			names = append(names, a.Name())
		}
		sort.Strings(names)
		return names
	}
	equal := func(got []string, want ...string) bool {
		if len(got) != len(want) {
			return false
		}
		for i := range got {
			if got[i] != want[i] {
				return false
			}
		}
		return true
	}

	f := asset.NewFilter()
	f.ExpiresBefore = &now
	if got := list(f); !equal(got, "expired.example") {
		t.Errorf("expired = %v, want [expired.example]", got)
	}

	in30 := now.Add(30 * day)
	f = asset.NewFilter()
	f.ExpiresAfter = &now
	f.ExpiresBefore = &in30
	if got := list(f); !equal(got, "domain.example", "soon.example") {
		t.Errorf("expiring in 30 days = %v, want [domain.example soon.example]", got)
	}
}
