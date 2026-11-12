package postgres

// The scan list's server-side sort (sort=, RFC-048 §3.5): each whitelisted
// field orders the whole list (not one page), NULL timestamps sort last, the
// order is stable across pages, and another tenant's scans never appear.

import (
	"context"
	"reflect"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

func TestScanList_ServerSort_DB(t *testing.T) {
	ctx := context.Background()
	db := openScanDB(t)
	repo := NewScanRepository(&DB{DB: db})
	tenantA := seedScanTriggerTenant(ctx, t, db)
	tenantB := seedScanTriggerTenant(ctx, t, db)

	seed := func(tenant shared.ID, name string, totalRuns int, lastRun string) {
		t.Helper()
		var last any
		if lastRun != "" {
			last = lastRun
		}
		if _, err := db.ExecContext(ctx,
			`INSERT INTO scans (id, tenant_id, name, scan_type, scanner_name, total_runs, last_run_at)
			 VALUES ($1, $2, $3, 'single', 'nuclei', $4, $5::timestamptz)`,
			shared.NewID().String(), tenant.String(), name, totalRuns, last); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(),
			`DELETE FROM scans WHERE tenant_id IN ($1, $2)`, tenantA.String(), tenantB.String())
	})
	seed(tenantA, "bravo", 5, "2026-10-01T10:00:00Z")
	seed(tenantA, "alpha", 1, "")
	seed(tenantA, "delta", 9, "2026-10-03T10:00:00Z")
	seed(tenantA, "charlie", 3, "2026-09-20T10:00:00Z")
	// Tenant B's scan would sort first by every key; it must never appear.
	seed(tenantB, "aaa-other-tenant", 99, "2026-10-04T10:00:00Z")

	names := func(sortRaw string, page, perPage int) []string {
		t.Helper()
		s, err := scan.ParseListSort(sortRaw)
		if err != nil {
			t.Fatal(err)
		}
		res, err := repo.List(ctx, scan.Filter{TenantID: &tenantA, Sort: s}, pagination.New(page, perPage))
		if err != nil {
			t.Fatalf("list sort=%q: %v", sortRaw, err)
		}
		if res.Total != 4 {
			t.Fatalf("sort=%q total = %d, want 4 (tenant A only)", sortRaw, res.Total)
		}
		out := make([]string, 0, len(res.Data))
		for _, sc := range res.Data {
			out = append(out, sc.Name)
		}
		return out
	}

	for _, tc := range []struct {
		sort string
		want []string
	}{
		{"", []string{"alpha", "bravo", "charlie", "delta"}},
		{"-name", []string{"delta", "charlie", "bravo", "alpha"}},
		{"-total_runs", []string{"delta", "bravo", "charlie", "alpha"}},
		{"total_runs", []string{"alpha", "charlie", "bravo", "delta"}},
		// Never-run "alpha" is last in both directions.
		{"-last_run_at", []string{"delta", "bravo", "charlie", "alpha"}},
		{"last_run_at", []string{"charlie", "bravo", "delta", "alpha"}},
	} {
		if got := names(tc.sort, 1, 10); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("sort=%q → %v, want %v", tc.sort, got, tc.want)
		}
	}

	// The sort spans pages: page 2 of size 2 continues page 1.
	p1, p2 := names("-total_runs", 1, 2), names("-total_runs", 2, 2)
	if got := append(p1, p2...); !reflect.DeepEqual(got, []string{"delta", "bravo", "charlie", "alpha"}) {
		t.Errorf("paged -total_runs → %v", got)
	}
}
