package scanworkflow

import (
	"errors"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestParseDepth(t *testing.T) {
	for in, want := range map[string]Depth{"": DepthStandard, "passive": DepthPassive, " Deep ": DepthDeep, "standard": DepthStandard} {
		got, err := ParseDepth(in)
		if err != nil || got != want {
			t.Errorf("ParseDepth(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := ParseDepth("full"); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("an unknown depth must be refused, got %v", err)
	}
}

func TestRunPolicy_Validate(t *testing.T) {
	ok := RunPolicy{MinDepth: DepthDeep, Depths: map[Depth]DepthOverlay{DepthStandard: {MaxTargets: 500}}}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	bad := []RunPolicy{
		{MinDepth: "full"},
		{MinDepth: "Deep"}, // stored lower-case only
		{Depths: map[Depth]DepthOverlay{"full": {}}},
		{Depths: map[Depth]DepthOverlay{DepthDeep: {MaxTargets: -1}}},
		{Depths: map[Depth]DepthOverlay{DepthDeep: {MaxTargets: MaxPolicyTargets + 1}}},
	}
	for i, p := range bad {
		if err := p.Validate(); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("case %d: %+v accepted (%v)", i, p, err)
		}
	}
}

// A passive depth runs only steps that send nothing to the targets; a step
// with a minimum depth is skipped below it; everything else runs.
func TestRunPolicy_DepthSkipReason(t *testing.T) {
	deepOnly := RunPolicy{MinDepth: DepthDeep}
	cases := []struct {
		p       RunPolicy
		d       Depth
		tier    int
		skipped string
	}{
		{RunPolicy{}, DepthPassive, 0, ""},
		{RunPolicy{}, DepthPassive, 1, "Passive depth"},
		{RunPolicy{}, DepthStandard, 1, ""},
		{deepOnly, DepthStandard, 0, "Deep depth or deeper"},
		{deepOnly, DepthDeep, 1, ""},
		{deepOnly, DepthPassive, 1, "Passive depth"},
	}
	for i, c := range cases {
		got := c.p.DepthSkipReason(c.d, c.tier)
		if (c.skipped == "") != (got == "") || !strings.Contains(got, c.skipped) {
			t.Errorf("case %d: %q, want containing %q", i, got, c.skipped)
		}
	}
}

// The depth's params win over the step's config; the config is not changed.
func TestRunPolicy_ConfigAt(t *testing.T) {
	cfg := map[string]any{"top_n": 100, "exclude": []string{"10.0.0.1"}}
	p := RunPolicy{Depths: map[Depth]DepthOverlay{DepthDeep: {Params: map[string]any{"top_n": 1000}}}}
	got := p.ConfigAt(cfg, DepthDeep)
	if got["top_n"] != 1000 || got["exclude"] == nil {
		t.Fatalf("deep config = %v", got)
	}
	if cfg["top_n"] != 100 {
		t.Fatal("ConfigAt changed the step's config")
	}
	if p.ConfigAt(cfg, DepthStandard)["top_n"] != 100 {
		t.Fatal("a depth without params must keep the config")
	}
}

func TestRunPolicy_StoredForm(t *testing.T) {
	if b, _ := MarshalPolicy(RunPolicy{}); string(b) != "{}" {
		t.Fatalf("zero policy stored as %s", b)
	}
	p := RunPolicy{MinDepth: DepthDeep, Optional: true, Depths: map[Depth]DepthOverlay{DepthDeep: {Params: map[string]any{"top_n": float64(1000)}, MaxTargets: 50}}}
	b, err := MarshalPolicy(p)
	if err != nil {
		t.Fatal(err)
	}
	back, err := UnmarshalPolicy(b)
	if err != nil || back.MinDepth != DepthDeep || !back.Optional || back.Depths[DepthDeep].MaxTargets != 50 || back.Depths[DepthDeep].Params["top_n"] != float64(1000) {
		t.Fatalf("round trip = %+v, %v", back, err)
	}
	if z, err := UnmarshalPolicy(nil); err != nil || !z.IsZero() {
		t.Fatalf("empty column = %+v, %v", z, err)
	}
	// A deep copy: changing the clone's params leaves the original alone.
	c := p.Clone()
	c.Depths[DepthDeep].Params["top_n"] = 1
	if p.Depths[DepthDeep].Params["top_n"] != float64(1000) {
		t.Fatal("Clone shares the params map")
	}
}

// A workflow that sets no policy keeps the digest it had before policies,
// so its runs do not pin a new version; a policy changes the digest.
func TestSpecDigest_ZeroPolicyUnchanged(t *testing.T) {
	step := &Step{ID: shared.NewID(), StepKey: "ports", Capabilities: []string{"scan.ports"}, Condition: AlwaysCondition()}
	w := &Workflow{Steps: []*Step{step}}
	before, _ := SpecOf(w).Digest()
	if SpecOf(w).Steps[0].RunPolicy != nil {
		t.Fatal("a zero policy must be left out of the spec")
	}
	step.RunPolicy = RunPolicy{MinDepth: DepthDeep}
	after, _ := SpecOf(w).Digest()
	if before == after {
		t.Fatal("a policy must change the digest")
	}
	back := SpecOf(w).Workflow(w)
	if back.Steps[0].RunPolicy.MinDepth != DepthDeep {
		t.Fatal("a pinned run must read the step's policy from its version")
	}
}
