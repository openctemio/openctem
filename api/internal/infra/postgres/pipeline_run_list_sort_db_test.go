package postgres

// The runs list's server-side sort (sort=, RFC-048 §3.5) and the scan names on
// its rows: each whitelisted key orders the whole list, the order is stable
// across pages, and another tenant's runs and scans never appear or get named.

import (
	"context"
	"reflect"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/pipeline"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

func TestRunList_ServerSortAndScanNames_DB(t *testing.T) {
	ctx := context.Background()
	db := openScanDB(t)
	repo := NewPipelineRunRepository(&DB{DB: db})
	tenantA, scanA := seedCounterScan(ctx, t, db)
	tenantB, scanB := seedCounterScan(ctx, t, db)

	// Runs in creation order r1..r4 with findings 5, 0, 9, 3; r2 never started.
	seed := func(tenant, scan shared.ID, findings int, started bool, createdAt string) shared.ID {
		t.Helper()
		run := seedCounterRun(ctx, t, repo, tenant, scan)
		startedAt := any(nil)
		if started {
			startedAt = createdAt
		}
		if _, err := db.ExecContext(ctx,
			`UPDATE pipeline_runs SET total_findings = $2, created_at = $3::timestamptz, started_at = $4::timestamptz WHERE id = $1`,
			run.ID.String(), findings, createdAt, startedAt); err != nil {
			t.Fatalf("shape run: %v", err)
		}
		return run.ID
	}
	r1 := seed(tenantA, scanA, 5, true, "2026-10-01T10:00:00Z")
	r2 := seed(tenantA, scanA, 0, false, "2026-10-02T10:00:00Z")
	r3 := seed(tenantA, scanA, 9, true, "2026-10-03T10:00:00Z")
	r4 := seed(tenantA, scanA, 3, true, "2026-10-04T10:00:00Z")
	// Tenant B's run is newest and has the most findings: it must never appear.
	seed(tenantB, scanB, 99, true, "2026-10-05T10:00:00Z")

	ids := func(sortRaw string, page, perPage int) []shared.ID {
		t.Helper()
		s, err := pipeline.ParseRunListSort(sortRaw)
		if err != nil {
			t.Fatal(err)
		}
		res, err := repo.List(ctx, pipeline.RunFilter{TenantID: &tenantA, Sort: s}, pagination.New(page, perPage))
		if err != nil {
			t.Fatalf("list sort=%q: %v", sortRaw, err)
		}
		if res.Total != 4 {
			t.Fatalf("sort=%q total = %d, want 4 (tenant A only)", sortRaw, res.Total)
		}
		out := make([]shared.ID, 0, len(res.Data))
		for _, r := range res.Data {
			out = append(out, r.ID)
		}
		return out
	}

	for _, tc := range []struct {
		sort string
		want []shared.ID
	}{
		{"", []shared.ID{r4, r3, r2, r1}},
		{"created_at", []shared.ID{r1, r2, r3, r4}},
		{"-total_findings", []shared.ID{r3, r1, r4, r2}},
		{"total_findings", []shared.ID{r2, r4, r1, r3}},
		// Never-started r2 is last in both directions.
		{"-started_at", []shared.ID{r4, r3, r1, r2}},
		{"started_at", []shared.ID{r1, r3, r4, r2}},
	} {
		if got := ids(tc.sort, 1, 10); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("sort=%q → %v, want %v", tc.sort, got, tc.want)
		}
	}
	if got := append(ids("-total_findings", 1, 2), ids("-total_findings", 2, 2)...); !reflect.DeepEqual(got, []shared.ID{r3, r1, r4, r2}) {
		t.Errorf("paged -total_findings → %v", got)
	}

	// Scan names are read for the caller's tenant only.
	names, err := repo.ScanNames(ctx, tenantA, []shared.ID{scanA, scanB})
	if err != nil {
		t.Fatal(err)
	}
	if names[scanA] != "counter probe" {
		t.Errorf("own scan name = %q", names[scanA])
	}
	if _, leaked := names[scanB]; leaked {
		t.Error("another tenant's scan was named")
	}
	if empty, err := repo.ScanNames(ctx, tenantA, nil); err != nil || len(empty) != 0 {
		t.Errorf("no ids: %v %v", empty, err)
	}
}
