package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/toolbudget"
)

// The learned per-target duration converges on the samples, stays within the
// tool's band whatever the samples are, and is per tenant.
func TestToolDurationStats_LearnsBoundedPerTenant(t *testing.T) {
	ctx := context.Background()
	db := openScanDB(t)
	tenant := seedScanTriggerTenant(ctx, t, db)
	other := seedScanTriggerTenant(ctx, t, db)
	repo := NewToolDurationStatsRepository(&DB{DB: db})
	floor, ceiling := time.Second, time.Minute

	if _, ok, err := repo.ToolStats(ctx, tenant, "httpx"); err != nil || ok {
		t.Fatalf("nothing learned yet: %v %v", ok, err)
	}
	for range 40 {
		if err := repo.ObservePerTarget(ctx, tenant, " HTTPX ", 10*time.Second, floor, ceiling); err != nil {
			t.Fatal(err)
		}
	}
	s, ok, err := repo.ToolStats(ctx, tenant, "httpx")
	if err != nil || !ok || s.Samples != 40 {
		t.Fatalf("stats %+v %v %v", s, ok, err)
	}
	if s.Mean < 9*time.Second || s.Mean > 11*time.Second {
		t.Fatalf("mean %s, want about 10s", s.Mean)
	}
	if s.P95 < floor || s.P95 > ceiling {
		t.Fatalf("p95 %s outside the band", s.P95)
	}
	// A hostile run of huge samples cannot leave the band.
	for range 50 {
		if err := repo.ObservePerTarget(ctx, tenant, "httpx", 1000*time.Hour, floor, ceiling); err != nil {
			t.Fatal(err)
		}
	}
	s, _, _ = repo.ToolStats(ctx, tenant, "httpx")
	if s.Mean > ceiling || s.P95 > ceiling {
		t.Fatalf("stats %+v left the %s ceiling", s, ceiling)
	}
	// Another tenant learned nothing.
	if _, ok, _ := repo.ToolStats(ctx, other, "httpx"); ok {
		t.Fatal("stats leaked to another tenant")
	}
	// Lookup gives the learned budget once there are enough samples.
	if b := toolbudget.Lookup(ctx, repo, tenant, "httpx"); b.Expected <= toolbudget.For("httpx").Expected {
		t.Fatalf("learned expected %s, default %s", b.Expected, toolbudget.For("httpx").Expected)
	}
}
