package integration

import (
	"context"
	"database/sql"
	"errors"
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

// intoP0 counts the tenant's events that moved a classified finding into P0.
func (c *capturePriorityEvents) intoP0(tid shared.ID) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, ev := range c.got {
		if ev.TenantID == tid && ev.PreviousClass != nil && ev.NewClass == vulnerability.PriorityP0 {
			n++
		}
	}
	return n
}

type captureScoringSummaries struct {
	mu  sync.Mutex
	got []scoring.ChangeSummary
}

func (c *captureScoringSummaries) PublishScoringSummaryInTx(_ context.Context, _ *sql.Tx, s scoring.ChangeSummary) error {
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

	// Moves into P0 keep their own event (ticket, workflow); the summary
	// still counts them.
	if got := events.forTenant(tid) - before; got != 3 || events.intoP0(tid) != 3 {
		t.Fatalf("%d per-finding events (%d into P0) for a change raising 3 findings to P0, want 3 into P0", got, events.intoP0(tid))
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
	beforeDrop := events.forTenant(tid)
	fx.drain(t, assets...)
	if got := events.forTenant(tid) - beforeDrop; got != 0 {
		t.Fatalf("%d per-finding events for a scoring change that lowered priorities, want 0 (the summary covers them)", got)
	}
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

// A scoring change that raises findings but not into P0 sends no per-finding
// event: only the summary.
func TestScoringSummary_RaiseBelowP0IsSummaryOnly(t *testing.T) {
	fx := newScoringFixture(t)
	events := &capturePriorityEvents{}
	summaries := &captureScoringSummaries{}
	fx.cls.SetChangePublisher(events)
	fx.recl.SetSummaryPublisher(summaries)

	tid := fx.newTenant(t)
	aid := fx.newAsset(t, tid, "github.com/acme/summary-p1")
	fid := fx.newFinding(t, tid, aid, vulnerability.SeverityLow, "summary-p1")
	fx.drain(t, aid)
	if c := fx.row(t, tid, fid).class; c == "P0" || c == "P1" {
		t.Fatalf("baseline class %s, want below P1 for this test", c)
	}
	before := events.forTenant(tid)
	fx.addRule(t, tid, "low", "P1")
	fx.drain(t, aid)
	if c := fx.row(t, tid, fid).class; c != "P1" {
		t.Fatalf("class after the rule = %s, want P1", c)
	}
	if got := events.forTenant(tid) - before; got != 0 {
		t.Fatalf("%d per-finding events for a raise to P1 by a scoring change, want 0", got)
	}
	if got := summaries.forTenant(tid); len(got) != 1 || got[0].Raised != 1 || got[0].RaisedToP0 != 0 {
		t.Fatalf("summaries = %+v, want one with 1 raised, 0 to P0", got)
	}
}

// failingSummaries fails its first send for each change, then captures.
type failingSummaries struct {
	captureScoringSummaries
	failed map[int64]bool
}

func (f *failingSummaries) PublishScoringSummaryInTx(ctx context.Context, tx *sql.Tx, s scoring.ChangeSummary) error {
	f.mu.Lock()
	first := !f.failed[s.ChangeID]
	f.failed[s.ChangeID] = true
	f.mu.Unlock()
	if first {
		return errors.New("outbox unavailable")
	}
	return f.captureScoringSummaries.PublishScoringSummaryInTx(ctx, tx, s)
}

// A summary whose enqueue fails is not marked notified: the next pass
// sends it.
func TestScoringSummary_FailedEnqueueIsRetried(t *testing.T) {
	fx := newScoringFixture(t)
	summaries := &failingSummaries{failed: map[int64]bool{}}
	fx.recl.SetSummaryPublisher(summaries)

	tid := fx.newTenant(t)
	aid := fx.newAsset(t, tid, "github.com/acme/summary-retry")
	fx.newFinding(t, tid, aid, vulnerability.SeverityHigh, "summary-retry")
	fx.drain(t, aid)
	fx.addRule(t, tid, "high", "P0")
	fx.drain(t, aid) // the send fails

	if n := len(summaries.forTenant(tid)); n != 0 {
		t.Fatalf("summaries after a failed send = %d, want 0", n)
	}
	var pending int
	if err := fx.db.QueryRow(`SELECT COUNT(*) FROM scoring_change_impacts WHERE tenant_id = $1 AND notified_at IS NULL`,
		tid.String()).Scan(&pending); err != nil {
		t.Fatal(err)
	}
	if pending != 1 {
		t.Fatalf("pending summaries after a failed send = %d, want 1 (not marked notified)", pending)
	}

	// The next pass retries.
	if _, err := fx.recl.ProcessQueue(context.Background(), 500, 500); err != nil {
		t.Fatal(err)
	}
	got := summaries.forTenant(tid)
	if len(got) != 1 || got[0].RaisedToP0 != 1 {
		t.Fatalf("summaries after the retry = %+v, want one with 1 raised to P0", got)
	}
	if err := fx.db.QueryRow(`SELECT COUNT(*) FROM scoring_change_impacts WHERE tenant_id = $1 AND notified_at IS NULL`,
		tid.String()).Scan(&pending); err != nil {
		t.Fatal(err)
	}
	if pending != 0 {
		t.Fatalf("pending summaries after the retry = %d, want 0", pending)
	}
}
