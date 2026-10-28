package controller

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/threat"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// A KEV source that answers 304 for days must not stop the findings from
// being reconciled with the catalog: findings created since a catalog
// change still need the KEV flag and escalation (RFC-117 hourly refresh).
func TestSweepDue(t *testing.T) {
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name    string
		changed bool
		last    time.Time
		want    bool
	}{
		{"changed catalog", true, now.Add(-time.Minute), true},
		{"first run, unchanged", false, time.Time{}, true},
		{"unchanged within a day", false, now.Add(-time.Hour), false},
		{"unchanged for a day", false, now.Add(-findingSweepEvery), true},
	}
	for _, c := range cases {
		if got := sweepDue(c.changed, c.last, now); got != c.want {
			t.Errorf("%s: sweepDue = %v, want %v", c.name, got, c.want)
		}
	}
}

type sweepQueue struct{ enqueued, refreshed int }

func (q *sweepQueue) EnqueueIntelChanges(context.Context) (int64, error) { q.enqueued++; return 1, nil }
func (q *sweepQueue) RefreshFindingEPSS(context.Context) (int64, error)  { q.refreshed++; return 1, nil }

type sweepEscalator struct{ n int }

func (e *sweepEscalator) EscalateKEVFindings(context.Context) (threat.KEVEscalationResult, error) {
	e.n++
	return threat.KEVEscalationResult{Flagged: 2}, nil
}

type sweepEvents struct{ kev, epss int }

func (e *sweepEvents) EmitKEV(context.Context) (int, error)  { e.kev++; return 0, nil }
func (e *sweepEvents) EmitEPSS(context.Context) (int, error) { e.epss++; return 0, nil }

// The same work runs after a direct sync and after the importer applied the
// feed from a signed release: the sweeper is the one function behind both.
func TestIntelSweeperRun(t *testing.T) {
	ctx := context.Background()
	q, esc, ev := &sweepQueue{}, &sweepEscalator{}, &sweepEvents{}
	kev := NewIntelSweeper(esc, q, logger.NewNop())
	kev.SetEventEmitter(ev)
	if got := kev.Run(ctx, "kev", true, true); got != 2 {
		t.Fatalf("processed %d, want the 2 flagged findings", got)
	}
	if q.enqueued != 1 || q.refreshed != 0 || esc.n != 1 || ev.kev != 1 || ev.epss != 0 {
		t.Fatalf("queue %+v escalator %d events %+v", q, esc.n, ev)
	}
	// Nothing changed and a sweep ran lately: no sweep, the event log is
	// still read.
	kev.Run(ctx, "kev", false, true)
	if q.enqueued != 1 || esc.n != 1 || ev.kev != 2 {
		t.Fatalf("an unchanged feed swept again: queue %+v escalator %d events %+v", q, esc.n, ev)
	}
	// A failed source never reads the event log.
	kev.Run(ctx, "kev", false, false)
	if ev.kev != 2 {
		t.Fatalf("events read after a failed sync: %+v", ev)
	}

	epss := NewIntelSweeper(nil, q, logger.NewNop())
	epss.SetEventEmitter(ev)
	epss.Run(ctx, "epss", true, true)
	if q.refreshed != 1 || ev.epss != 1 {
		t.Fatalf("EPSS: queue %+v events %+v", q, ev)
	}
}
