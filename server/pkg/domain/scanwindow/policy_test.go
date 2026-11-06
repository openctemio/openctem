package scanwindow

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestNewPolicy_Validation(t *testing.T) {
	now := utc("2026-10-07T10:00:00Z")
	gid := shared.NewID().String()
	ok := Spec{
		Name: " Business hours ", Kind: KindAllow, MinTier: TierActive, Timezone: "Europe/Berlin", Enabled: true,
		Slots:        []Slot{{Days: []int{5, 1, 1}, Start: "9:00", End: "17:00"}},
		Selector:     Selector{Tags: []string{"prod", "PROD", "business-hours"}, AssetGroupIDs: []string{gid, gid}, Criticalities: []string{"Critical"}},
		GraceMinutes: 15, RateLimitRPS: 10, MaxConcurrent: 2,
	}
	p, err := NewPolicy(shared.NewID(), ok, nil, now)
	if err != nil {
		t.Fatalf("valid policy refused: %v", err)
	}
	if p.Name != "Business hours" || p.Slots[0].Start != "09:00" || len(p.Slots[0].Days) != 2 {
		t.Errorf("policy not normalised: %+v", p)
	}
	if len(p.Selector.Tags) != 2 || len(p.Selector.AssetGroupIDs) != 1 || p.Selector.Criticalities[0] != "critical" {
		t.Errorf("selector not normalised: %+v", p.Selector)
	}
	if p.Selector.Empty() || !p.Selector.UsesAssets() || p.Selector.UsesScope() {
		t.Errorf("selector flags wrong: %+v", p.Selector)
	}

	bad := map[string]func(s *Spec){
		"empty name":            func(s *Spec) { s.Name = " " },
		"long name":             func(s *Spec) { s.Name = strings.Repeat("x", 101) },
		"long description":      func(s *Spec) { s.Description = strings.Repeat("x", 1001) },
		"unknown kind":          func(s *Spec) { s.Kind = "deny" },
		"tier 3":                func(s *Spec) { s.MinTier = 3 },
		"no timezone":           func(s *Spec) { s.Timezone = "" },
		"Local timezone":        func(s *Spec) { s.Timezone = "Local" },
		"unknown timezone":      func(s *Spec) { s.Timezone = "Mars/Olympus" },
		"no windows":            func(s *Spec) { s.Slots = nil },
		"day 0":                 func(s *Spec) { s.Slots = []Slot{{Days: []int{0}, Start: "01:00", End: "02:00"}} },
		"no days":               func(s *Spec) { s.Slots = []Slot{{Start: "01:00", End: "02:00"}} },
		"bad start":             func(s *Spec) { s.Slots = []Slot{{Days: []int{1}, Start: "24:00", End: "02:00"}} },
		"too many slots":        func(s *Spec) { s.Slots = make([]Slot, MaxSlots+1) },
		"one-off without times": func(s *Spec) { s.Slots, s.OneOffs = nil, []OneOff{{}} },
		"one-off ends first": func(s *Spec) {
			s.Slots, s.OneOffs = nil, []OneOff{{StartsAt: now.Add(time.Hour), EndsAt: now}}
		},
		"one-off over 31 days": func(s *Spec) {
			s.Slots, s.OneOffs = nil, []OneOff{{StartsAt: now, EndsAt: now.Add(32 * 24 * time.Hour)}}
		},
		"too many one-offs":   func(s *Spec) { s.OneOffs = make([]OneOff, MaxOneOffs+1) },
		"bad group id":        func(s *Spec) { s.Selector.AssetGroupIDs = []string{"x"} },
		"bad asset type":      func(s *Spec) { s.Selector.AssetTypes = []string{"spaceship"} },
		"bad criticality":     func(s *Spec) { s.Selector.Criticalities = []string{"urgent"} },
		"empty tag":           func(s *Spec) { s.Selector.Tags = []string{" "} },
		"too many tags":       func(s *Spec) { s.Selector.Tags = make([]string, 51) },
		"negative grace":      func(s *Spec) { s.GraceMinutes = -1 },
		"grace over 4h":       func(s *Spec) { s.GraceMinutes = 241 },
		"negative rate":       func(s *Spec) { s.RateLimitRPS = -1 },
		"blackout with a cap": func(s *Spec) { s.Kind = KindBlackout },
	}
	for name, mutate := range bad {
		s := ok
		s.Selector = cloneSelector(ok.Selector)
		mutate(&s)
		if _, err := NewPolicy(shared.NewID(), s, nil, now); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%s: err = %v, want a validation error", name, err)
		}
	}
}

func TestPolicy_UpdateRollsBackOnError(t *testing.T) {
	now := utc("2026-10-07T10:00:00Z")
	p, err := NewPolicy(shared.NewID(), Spec{Name: "freeze", Kind: KindBlackout, MinTier: 1, Timezone: "UTC",
		OneOffs: []OneOff{{StartsAt: now, EndsAt: now.Add(time.Hour)}}}, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	spec := p.Spec()
	spec.Timezone = "nowhere"
	if err := p.Update(spec, now); err == nil {
		t.Fatal("invalid update accepted")
	}
	if p.Timezone != "UTC" {
		t.Errorf("a refused update changed the policy: %+v", p)
	}
	spec = p.Spec()
	spec.Name = "renamed"
	if err := p.Update(spec, now.Add(time.Minute)); err != nil || p.Name != "renamed" || !p.UpdatedAt.After(now) {
		t.Fatalf("update: %v %+v", err, p)
	}
}

func TestSelector_Empty(t *testing.T) {
	if !(Selector{}).Empty() {
		t.Error("zero selector must select everything")
	}
	if (Selector{ScanZoneIDs: []string{"z"}}).Empty() {
		t.Error("a zone selector is not empty")
	}
	if !(Selector{ProgramIDs: []string{"p"}}).UsesScope() {
		t.Error("a program selector uses the scope")
	}
}
