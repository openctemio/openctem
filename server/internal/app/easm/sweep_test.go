package easm

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/easmdns"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type sweepLog struct{ calls []string }

type fakeCT struct{ log *sweepLog }

func (f fakeCT) MonitorTenant(_ context.Context, id shared.ID) (int, error) {
	f.log.calls = append(f.log.calls, "ct:"+id.String())
	return 1, nil
}

type fakeDNS struct{ log *sweepLog }

func (f fakeDNS) MonitorTenant(_ context.Context, id shared.ID) (easmdns.RunResult, error) {
	f.log.calls = append(f.log.calls, "dangling:"+id.String())
	return easmdns.RunResult{}, nil
}

func (f fakeDNS) MonitorEmail(_ context.Context, id shared.ID) (easmdns.RunResult, error) {
	f.log.calls = append(f.log.calls, "email:"+id.String())
	return easmdns.RunResult{}, errors.New("resolver down")
}

type memLimiter struct {
	held map[shared.ID]time.Time
	now  time.Time
	err  error
}

func (m *memLimiter) Acquire(_ context.Context, id shared.ID, window time.Duration) (bool, time.Time, error) {
	if m.err != nil {
		return false, time.Time{}, m.err
	}
	if until, ok := m.held[id]; ok && until.After(m.now) {
		return false, until, nil
	}
	m.held[id] = m.now.Add(window)
	return true, time.Time{}, nil
}

// research/22 P0-11: run-now runs CT then both DNS checks for the caller's
// tenant only, at most once per 15 minutes per tenant; a seed sweep is not
// limited; a limiter failure refuses.
func TestSweepService(t *testing.T) {
	log := &sweepLog{}
	lim := &memLimiter{held: map[shared.ID]time.Time{}, now: time.Now()}
	svc := NewSweepService(fakeCT{log}, fakeDNS{log}, lim, nil)
	svc.run = func(f func()) { f() }
	a, b := shared.NewID(), shared.NewID()

	ticket, _, err := svc.RunNow(context.Background(), a)
	if err != nil || !ticket.CTIncluded || !ticket.DNSIncluded || ticket.NextRunNowAt.Sub(ticket.StartedAt) != RunNowInterval {
		t.Fatalf("first run-now: %+v %v", ticket, err)
	}
	want := []string{"ct:" + a.String(), "dangling:" + a.String(), "email:" + a.String()}
	if len(log.calls) != 3 || log.calls[0] != want[0] || log.calls[1] != want[1] || log.calls[2] != want[2] {
		t.Fatalf("calls = %v, want CT then DNS for tenant A only", log.calls)
	}
	if _, until, err := svc.RunNow(context.Background(), a); !errors.Is(err, ErrSweepTooSoon) || until.IsZero() {
		t.Fatalf("second run-now: %v %v", until, err)
	}
	if _, _, err := svc.RunNow(context.Background(), b); err != nil {
		t.Fatalf("tenant B limited by A: %v", err)
	}
	lim.now = lim.now.Add(RunNowInterval + time.Second)
	if _, _, err := svc.RunNow(context.Background(), a); err != nil {
		t.Fatalf("after 15 minutes: %v", err)
	}

	log.calls = nil
	svc.SweepForSeed(a) // not limited
	if len(log.calls) != 3 {
		t.Fatalf("seed sweep calls = %v", log.calls)
	}

	lim.err = errors.New("db down")
	if _, _, err := svc.RunNow(context.Background(), b); err == nil {
		t.Fatal("a limiter failure must refuse")
	}
	if _, _, err := NewSweepService(nil, nil, nil, nil).RunNow(context.Background(), a); err == nil {
		t.Fatal("run-now without a limiter must refuse")
	}
	var nilSvc *SweepService
	nilSvc.SweepForSeed(a)

	// Parts the platform turned off are skipped.
	log.calls = nil
	only := NewSweepService(nil, fakeDNS{log}, &memLimiter{held: map[shared.ID]time.Time{}, now: time.Now()}, nil)
	only.run = func(f func()) { f() }
	tk, _, _ := only.RunNow(context.Background(), a)
	if tk.CTIncluded || len(log.calls) != 2 {
		t.Fatalf("CT off platform-wide: %+v %v", tk, log.calls)
	}
}
