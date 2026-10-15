package integration

import (
	"context"
	"sync"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/finding"
	"github.com/openctemio/openctem/api/pkg/domain/scoring"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// No alert storms (docs/architecture/scoring-versions.md): a recompute caused
// by a scoring change sends one summary per change and tenant, not one
// priority event per finding; other recomputes keep their per-finding events.

type capturePriorityEvents struct {
	mu  sync.Mutex
	got []finding.PriorityChangeEvent
}

func (c *capturePriorityEvents) Publish(_ context.Context, ev finding.PriorityChangeEvent) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.got = append(c.got, ev)
	return nil
}

func (c *capturePriorityEvents) forTenant(tid shared.ID) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, ev := range c.got {
		if ev.TenantID == tid && ev.PreviousClass != nil {
			n++
		}
	}
	return n
}

type captureScoringSummaries struct {
	mu  sync.Mutex
	got []scoring.ChangeSummary
}

func (c *captureScoringSummaries) PublishScoringSummary(_ context.Context, s scoring.ChangeSummary) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.got = append(c.got, s)
	return nil
}

func (c *captureScoringSummaries) forTenant(tid shared.ID) []scoring.ChangeSummary {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []scoring.ChangeSummary
	for _, s := range c.got {
		if s.TenantID == tid {
			out = append(out, s)
		}
	}
	return out
}

func TestScoringSummary_OneNotificationPerChange(t *testing.T) {
	fx := newScoringFixture(t)
	events := &capturePriorityEvents{}
	summaries := &captureScoringSummaries{}
	fx.cls.SetChangePublisher(events)
	fx.recl.SetSummaryPublisher(summaries)

	tid := fx.newTenant(t)
	other := fx.newTenant(t)
	var assets []shared.ID
	for _, name := range []string{"a", "b", "c"} {
		aid := fx.newAsset(t, tid, "github.com/acme/summary-"+name)
		fx.newFinding(t, tid, aid, vulnerability.SeverityHigh, "summary-"+name)
		assets = append(assets, aid)
	}
	oaid := fx.newAsset(t, other, "github.com/acme/summary-other")
	fx.newFinding(t, other, oaid, vulnerability.SeverityHigh, "summary-other")
	fx.drain(t, append(assets, oaid)...)
	before := events.forTenant(tid)

	// The tenant's rule raises every high finding to P0.
	fx.addRule(t, tid, "high", "P0")
	fx.drain(t, assets...)

	if got := events.forTenant(tid) - before; got != 0 {
		t.Fatalf("%d per-finding priority events for a scoring change, want 0", got)
	}
	got := summaries.forTenant(tid)
	if len(got) != 1 {
		t.Fatalf("summaries = %d, want exactly 1: %+v", len(got), got)
	}
	s := got[0]
	if s.Changed != 3 || s.Raised != 3 || s.RaisedToP0 != 3 || s.Source != "priority_rules" {
		t.Fatalf("summary = %+v, want 3 raised to P0 by priority rules", s)
	}
	if len(summaries.forTenant(other)) != 0 {
		t.Fatal("another tenant got a summary for this tenant's change")
	}

	// A change that is not a scoring change keeps its per-finding event:
	// a finding moved to critical severity on an asset of the tenant.
	if _, err := fx.db.Exec(`DELETE FROM priority_override_rules WHERE tenant_id = $1`, tid.String()); err != nil {
		t.Fatal(err)
	}
	fx.drain(t, assets...)
	if n := len(summaries.forTenant(tid)); n != 2 {
		t.Fatalf("summaries after the rule removal = %d, want 2 (one per change)", n)
	}
	fx.addRule(t, tid, "critical", "P0")
	fx.drain(t, assets...)
	mark := events.forTenant(tid)
	if _, err := fx.db.Exec(`UPDATE findings SET severity = 'critical' WHERE tenant_id = $1 AND asset_id = $2`, tid.String(), assets[0].String()); err != nil {
		t.Fatal(err)
	}
	fx.drain(t, assets[0])
	if events.forTenant(tid) == mark {
		t.Fatal("a severity change sent no per-finding priority event")
	}
}
