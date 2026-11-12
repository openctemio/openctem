package stepup

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

func TestValidate_CriticalFloor(t *testing.T) {
	ok := []Rule{{Mode: ModeEveryTime}, {Mode: ModeWindow, Window: Window10m}}
	for _, r := range ok {
		p := DefaultPolicy()
		p.Critical = r
		if err := p.Validate(); err != nil {
			t.Errorf("critical %+v: %v", r, err)
		}
	}
	below := []Rule{{Mode: ModeOff}, {Mode: ModeWindow, Window: Window1h}, {Mode: ModeWindow, Window: Window4h},
		{Mode: ModeWindow, Window: Window8h}, {Mode: ModeWindow, Window: WindowSession}}
	for _, r := range below {
		p := DefaultPolicy()
		p.Critical = r
		if err := p.Validate(); !errors.Is(err, ErrBelowFloor) {
			t.Errorf("critical %+v: got %v, want ErrBelowFloor", r, err)
		}
	}
}

func TestValidate_SensitiveAndRoutineMayBeOff(t *testing.T) {
	p := Policy{Critical: Rule{Mode: ModeEveryTime}, Sensitive: Rule{Mode: ModeOff}, Routine: Rule{Mode: ModeWindow, Window: WindowSession}}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestValidate_RefusesUnknownValues(t *testing.T) {
	for _, r := range []Rule{{Mode: "sometimes"}, {Mode: ModeWindow, Window: "2h"}, {Mode: ModeWindow}, {Mode: ModeOff, Window: Window1h}, {}} {
		p := DefaultPolicy()
		p.Sensitive = r
		if err := p.Validate(); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("sensitive %+v: got %v, want a validation error", r, err)
		}
	}
}

func TestEffective(t *testing.T) {
	if got := Effective(nil); got != LegacyPolicy() {
		t.Errorf("no stored policy: got %+v, want the legacy policy", got)
	}
	stored := Policy{Critical: Rule{Mode: ModeOff}, Sensitive: Rule{Mode: "bogus"}, Routine: Rule{Mode: ModeEveryTime}}
	got := Effective(&stored)
	if got.Critical != (Rule{Mode: ModeWindow, Window: Window10m}) {
		t.Errorf("a stored critical below the floor must be clamped, got %+v", got.Critical)
	}
	if got.Sensitive != LegacyPolicy().Sensitive || got.Routine != (Rule{Mode: ModeEveryTime}) {
		t.Errorf("got %+v", got)
	}
}

func TestDefaults(t *testing.T) {
	if err := DefaultPolicy().Validate(); err != nil {
		t.Fatal(err)
	}
	if err := LegacyPolicy().Validate(); err != nil {
		t.Fatal(err)
	}
	if DefaultPolicy().Routine.Mode != ModeOff || LegacyPolicy().Routine.Mode != ModeOff {
		t.Error("routine is off by default")
	}
}

func TestLooser(t *testing.T) {
	a := LegacyPolicy()
	b := a
	b.Sensitive = Rule{Mode: ModeWindow, Window: Window1h}
	if !Looser(a, b) || Looser(b, a) {
		t.Error("a longer window is looser")
	}
	c := a
	c.Critical = Rule{Mode: ModeEveryTime}
	if Looser(a, c) || !Looser(c, a) {
		t.Error("every_time is stricter than a window")
	}
	d := a
	d.Routine = Rule{Mode: ModeWindow, Window: WindowSession}
	if Looser(a, d) || !Looser(d, a) {
		t.Error("off is the loosest")
	}
}

func TestRequestState(t *testing.T) {
	var nilState *RequestState
	nilState.MarkSpent()
	nilState.Record(Applied{})
	if nilState.Spent() {
		t.Error("nil state")
	}
	ctx := WithRequestState(context.Background())
	s := StateFrom(ctx)
	if _, ok := s.Strictest(); ok {
		t.Error("nothing recorded yet")
	}
	s.Record(Applied{Tier: TierRoutine, Mode: ModeOff})
	s.Record(Applied{Tier: TierCritical, Mode: ModeEveryTime})
	s.Record(Applied{Tier: TierSensitive, Mode: ModeOff})
	if a, _ := s.Strictest(); a.Tier != TierCritical {
		t.Errorf("strictest = %+v", a)
	}
	s.MarkSpent()
	if !s.Spent() {
		t.Error("spent")
	}
}

type plainGate struct{ called string }

func (g *plainGate) RequireRecentAuth(context.Context, string) error { g.called = "plain"; return nil }

type tieredGate struct{ plainGate }

func (g *tieredGate) RequireRecentAuthTier(_ context.Context, _ string, t Tier) error {
	g.called = string(t)
	return nil
}

func TestRequire_FallsBackToCritical(t *testing.T) {
	p := &plainGate{}
	_ = Require(context.Background(), p, "u", TierRoutine)
	if p.called != "plain" {
		t.Error("a plain gate checks as critical")
	}
	tg := &tieredGate{}
	_ = Require(context.Background(), tg, "u", TierSensitive)
	if tg.called != "sensitive" {
		t.Errorf("got %q", tg.called)
	}
}
