package coverage

import (
	"context"
	"testing"

	"github.com/openctemio/contract/outcome"

	covdom "github.com/openctemio/openctem/api/pkg/domain/coverage"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// A pair no task carried is classified by what the run did: platform side
// only when nothing was planned.
func TestUnmatchedOutcome(t *testing.T) {
	for _, c := range []struct {
		name  string
		rs    covdom.RunState
		tasks int
		want  string
	}{
		{"sensor reached none of the targets", covdom.RunState{Status: "failed", Unreachable: true}, 1, string(outcome.Unreachable)},
		{"tasks ran without the target", covdom.RunState{Status: "completed"}, 2, covdom.OutcomeNotScanned},
		{"partial run, tasks ran", covdom.RunState{Status: "partial"}, 1, covdom.OutcomeNotScanned},
		{"no task planned", covdom.RunState{Status: "completed"}, 0, covdom.OutcomeNotDispatched},
		{"run failed before any task", covdom.RunState{Status: "failed"}, 0, covdom.OutcomeNotDispatched},
		{"failed run with tasks, not unreachable", covdom.RunState{Status: "failed"}, 1, covdom.OutcomeNotDispatched},
	} {
		if got := unmatchedOutcome(c.rs, c.tasks); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
	// Only the platform's outcome alerts the administrators; the others are
	// the organization's gaps.
	if covdom.IsPlatformSide(covdom.OutcomeNotScanned) || covdom.IsPlatformSide(string(outcome.Unreachable)) {
		t.Fatal("not_scanned and unreachable must not be platform side")
	}
	if !covdom.IsPlatformSide(covdom.OutcomeNotDispatched) {
		t.Fatal("not_dispatched with no task planned stays platform side")
	}
}

type fakeAddresses struct {
	m     map[string][]string
	asked []string
}

func (f *fakeAddresses) AddressesOf(_ context.Context, _ shared.ID, names []string) (map[string][]string, error) {
	f.asked = append(f.asked, names...)
	return f.m, nil
}

// A name takes the best verdict of the addresses it resolves to, and keeps
// no verdict when none of its addresses was in the run.
func TestAttributeAddresses(t *testing.T) {
	s := &Service{logger: logger.NewDefault()}
	f := &fakeAddresses{m: map[string][]string{
		"a.example": {"192.0.2.1", "192.0.2.2"},
		"b.example": {"192.0.2.9"},
	}}
	s.addresses = f
	queued := []covdom.DueTarget{{Name: "a.example"}, {Name: "b.example"}, {Name: "192.0.2.1"}}
	v := map[string]covdom.Verdict{
		"192.0.2.1": {Kind: covdom.VerdictFailed, Outcome: string(outcome.Unreachable)},
		"192.0.2.2": {Kind: covdom.VerdictCovered},
	}
	s.attributeAddresses(context.Background(), shared.NewID(), queued, v)
	if v["a.example"].Kind != covdom.VerdictCovered {
		t.Fatalf("a.example = %+v, want the covered address to win", v["a.example"])
	}
	if _, ok := v["b.example"]; ok {
		t.Fatal("b.example has no address in the run: no verdict")
	}
	for _, n := range f.asked {
		if n == "192.0.2.1" {
			t.Fatal("a target that already has a verdict is not looked up")
		}
	}
}
