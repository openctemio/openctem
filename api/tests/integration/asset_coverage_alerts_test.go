package integration

// Coverage gap detection (RFC-093, owner decision D4) on a migrated
// database: a broken probe that settles every input with no output, a pair
// that failed three times and a pair never covered for more than twice its
// cadence each raise one alert to the tenant's administrators and its
// integrations, at most once a day across services; another tenant's
// ledger raises nothing for it.

import (
	"context"
	"fmt"
	"sync"
	"testing"

	coverageapp "github.com/openctemio/openctem/api/internal/app/coverage"
	"github.com/openctemio/openctem/api/internal/app/outbox"
	scanapp "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/pkg/domain/notification"
	"github.com/openctemio/openctem/api/pkg/domain/scangov"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type recAlerts struct {
	mu     sync.Mutex
	inApp  []notification.NotificationParams
	events []outbox.EnqueueParams
	admin  shared.ID
}

func (r *recAlerts) Notify(_ context.Context, p notification.NotificationParams) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.inApp = append(r.inApp, p)
	return nil
}

func (r *recAlerts) Enqueue(_ context.Context, p outbox.EnqueueParams) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, p)
	return nil
}

func (r *recAlerts) ActiveAdminIDs(context.Context, shared.ID) ([]shared.ID, error) {
	return []shared.ID{r.admin}, nil
}

type noStarter struct{}

func (noStarter) StartCoverage(context.Context, scanapp.CoverageInput) (*scanapp.CoverageResult, error) {
	return nil, fmt.Errorf("not used")
}

func TestAssetCoverage_GapAlerts(t *testing.T) {
	g := newCovRig(t)
	ctx := context.Background()
	a := g.r.newTenant()
	b := g.r.newTenant()

	// 20 open web ports whose probe ran today and found no origin: a broken
	// probe. One address whose port scan failed 3 times. One address never
	// port-scanned since its row was planned 20 days ago.
	for i := 0; i < 20; i++ {
		id := g.asset(a, fmt.Sprintf("198.51.100.%d:443:tcp", i+1), "service", "open_port", `{"port": 443}`)
		g.exec(`INSERT INTO asset_coverage (tenant_id, asset_id, capability, state, last_outcome, last_success_at, last_attempt_at)
			VALUES ($1, $2, 'probe.http', 'covered', 'no_output', now() - interval '1 hour', now() - interval '1 hour')`, a.tenant, id)
	}
	sub := g.asset(a, "198.51.100.150", "ip_address", "", "")
	g.exec(`INSERT INTO asset_coverage (tenant_id, asset_id, capability, state, fail_streak, last_success_at)
		VALUES ($1, $2, 'scan.ports', 'failed', 3, now())`, a.tenant, sub)
	ip := g.asset(a, "198.51.100.200", "ip_address", "", "")
	g.exec(`INSERT INTO asset_coverage (tenant_id, asset_id, capability, state, created_at)
		VALUES ($1, $2, 'lookup.asn', 'due', now() - interval '20 days')`, a.tenant, ip)
	// Tenant B: healthy.
	bip := g.asset(b, "198.51.100.201", "ip_address", "", "")
	g.exec(`INSERT INTO asset_coverage (tenant_id, asset_id, capability, state, last_success_at)
		VALUES ($1, $2, 'scan.ports', 'covered', now())`, b.tenant, bip)

	rec := &recAlerts{admin: shared.NewID()}
	newSvc := func() *coverageapp.Service {
		s := coverageapp.NewService(g.repo, logger.NewNop())
		s.EnablePlanning(g.repo, noStarter{}, coverageapp.GovernanceSwitch{Modes: fixedMode{m: scangov.ModeOff}}, coverageapp.Config{DailyBudget: 1})
		s.EnableAlerts(g.repo, rec, rec, rec)
		return s
	}
	// Daily budget already used up so nothing is planned; the pass still
	// detects. The reconcile adds rows for rules the fixture lacks; that is
	// fine (new rows are not gaps yet).
	if _, err := newSvc().RunTenant(ctx, a.tenant); err != nil {
		t.Fatal(err)
	}
	kinds := map[string]bool{}
	for _, e := range rec.events {
		if e.TenantID != a.tenant || e.EventType != "coverage_gap" {
			t.Fatalf("unexpected event %+v", e)
		}
		kinds[fmt.Sprint(e.Metadata["capability"], "/", e.Metadata["kind"])] = true
	}
	for _, k := range []string{"probe.http/output_drop", "scan.ports/failing", "lookup.asn/gap"} {
		if !kinds[k] {
			t.Errorf("missing alert %s (got %v)", k, kinds)
		}
	}
	if len(rec.inApp) != len(rec.events) || rec.inApp[0].AudienceID == nil || *rec.inApp[0].AudienceID != rec.admin ||
		rec.inApp[0].NotificationType != notification.TypeCoverageGap {
		t.Fatalf("in-app alerts = %+v", rec.inApp)
	}

	// Another service instance (a restart, another replica) does not send
	// them again the same day.
	n := len(rec.events)
	if _, err := newSvc().RunTenant(ctx, a.tenant); err != nil {
		t.Fatal(err)
	}
	if len(rec.events) != n {
		t.Fatalf("alerts sent again: %d -> %d", n, len(rec.events))
	}
	// Tenant B is healthy: nothing for it.
	if _, err := newSvc().RunTenant(ctx, b.tenant); err != nil {
		t.Fatal(err)
	}
	for _, e := range rec.events[n:] {
		t.Errorf("healthy tenant alerted: %+v", e)
	}
}
