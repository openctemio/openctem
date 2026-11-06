package scanworkflow

// Depth and step run policies: how much of a workflow runs and with which
// standard params. Design: docs/architecture/scan-stages.md §1.5.
//
// A scan picks a depth (passive, standard or deep). Every step of its
// workflow reacts to it:
//
//   - passive runs only the steps that send nothing to a target (T0);
//   - a step with a minimum depth is skipped below it, with the reason;
//   - the step's standard params for the depth are merged over its config
//     at dispatch, and its target cap for the depth bounds what the hop
//     router hands it (lower-only).
//
// A depth never raises a tier: intensity, the scope entry's tier and the
// claim's tier check still decide. A policy holds standard params only (no
// tool extras), checked against the capability contract when it is saved.

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Depth is how much of a workflow a scan runs.
type Depth string

// Depths, from the least to the most work.
const (
	DepthPassive  Depth = "passive"
	DepthStandard Depth = "standard"
	DepthDeep     Depth = "deep"
)

// DefaultDepth is the depth of a scan that chose none.
const DefaultDepth = DepthStandard

// Depths lists every depth, least first.
func Depths() []Depth { return []Depth{DepthPassive, DepthStandard, DepthDeep} }

// ParseDepth reads passive, standard or deep (case-insensitive). An empty
// string is the default depth.
func ParseDepth(s string) (Depth, error) {
	d := Depth(strings.ToLower(strings.TrimSpace(s)))
	if d == "" {
		return DefaultDepth, nil
	}
	if slices.Contains(Depths(), d) {
		return d, nil
	}
	return "", fmt.Errorf("%w: depth must be passive, standard or deep", shared.ErrValidation)
}

// rank orders depths; an unknown depth ranks as standard (it never widens).
func (d Depth) rank() int {
	switch d {
	case DepthPassive:
		return 0
	case DepthDeep:
		return 2
	}
	return 1
}

// AtLeast reports whether d is min or deeper.
func (d Depth) AtLeast(min Depth) bool { return d.rank() >= min.rank() }

// Label is the depth's name in messages.
func (d Depth) Label() string {
	switch d {
	case DepthPassive:
		return "Passive"
	case DepthDeep:
		return "Deep"
	}
	return "Standard"
}

// MaxPolicyTargets bounds a policy's target cap (the run cap).
const MaxPolicyTargets = 10000

// DepthOverlay is what a step changes at one depth.
type DepthOverlay struct {
	// Params are standard params of the step's capability, merged over the
	// step's config at dispatch.
	Params map[string]any `json:"params,omitempty"`
	// MaxTargets caps the targets the hop router hands the step (0: the
	// stage's own cap). Lower-only: it never raises the stage or run cap.
	MaxTargets int `json:"max_targets,omitempty"`
}

// RunPolicy is how a step runs across depths.
type RunPolicy struct {
	// MinDepth skips the step below this depth ("" or passive: every depth
	// its tier allows).
	MinDepth Depth `json:"min_depth,omitempty"`
	// Depths holds the overlays per depth.
	Depths map[Depth]DepthOverlay `json:"depths,omitempty"`
	// Optional marks a step that waits for a tool: when no implementation
	// of its capability is available it is skipped with the reason instead
	// of failing, and the workflow check accepts a planned capability on it.
	Optional bool `json:"optional,omitempty"`
}

// IsZero reports whether the policy changes nothing.
func (p RunPolicy) IsZero() bool {
	return (p.MinDepth == "" || p.MinDepth == DepthPassive) && len(p.Depths) == 0 && !p.Optional
}

// Validate checks the depths and the caps. The params are checked against
// the capability contract by the caller (stage.ValidateStandardParams).
func (p RunPolicy) Validate() error {
	if p.MinDepth != "" {
		if _, err := ParseDepth(string(p.MinDepth)); err != nil || Depth(strings.ToLower(string(p.MinDepth))) != p.MinDepth {
			return fmt.Errorf("%w: run_policy.min_depth must be passive, standard or deep", shared.ErrValidation)
		}
	}
	for d, o := range p.Depths {
		if !slices.Contains(Depths(), d) {
			return fmt.Errorf("%w: run_policy.depths: %q is not a depth (passive, standard or deep)", shared.ErrValidation, d)
		}
		if o.MaxTargets < 0 || o.MaxTargets > MaxPolicyTargets {
			return fmt.Errorf("%w: run_policy.depths.%s.max_targets must be between 0 and %d", shared.ErrValidation, d, MaxPolicyTargets)
		}
	}
	return nil
}

// Overlay is the step's overlay at depth d (zero when it has none).
func (p RunPolicy) Overlay(d Depth) DepthOverlay { return p.Depths[d] }

// ConfigAt is the step's config at depth d: config with the depth's params
// merged over it. config itself is not changed.
func (p RunPolicy) ConfigAt(config map[string]any, d Depth) map[string]any {
	params := p.Depths[d].Params
	if len(params) == 0 {
		return config
	}
	out := make(map[string]any, len(config)+len(params))
	for k, v := range config {
		out[k] = v
	}
	for k, v := range params {
		out[k] = v
	}
	return out
}

// Clone is a deep copy (params maps included).
func (p RunPolicy) Clone() RunPolicy {
	out := RunPolicy{MinDepth: p.MinDepth, Optional: p.Optional}
	if len(p.Depths) > 0 {
		out.Depths = make(map[Depth]DepthOverlay, len(p.Depths))
		for d, o := range p.Depths {
			c := DepthOverlay{MaxTargets: o.MaxTargets}
			if o.Params != nil {
				c.Params = make(map[string]any, len(o.Params))
				for k, v := range o.Params {
					c.Params[k] = v
				}
			}
			out.Depths[d] = c
		}
	}
	return out
}

// MarshalPolicy is the stored form ("{}" for a zero policy).
func MarshalPolicy(p RunPolicy) ([]byte, error) {
	if p.IsZero() {
		return []byte("{}"), nil
	}
	return json.Marshal(p)
}

// UnmarshalPolicy reads the stored form; empty or null is the zero policy.
func UnmarshalPolicy(b []byte) (RunPolicy, error) {
	var p RunPolicy
	if len(b) == 0 || string(b) == "null" {
		return p, nil
	}
	if err := json.Unmarshal(b, &p); err != nil {
		return RunPolicy{}, fmt.Errorf("run policy: %w", err)
	}
	return p, nil
}

// DepthSkipReason is why a step is skipped at depth d: below its minimum
// depth, or an active step (tier above 0) at passive depth. "" when it runs.
func (p RunPolicy) DepthSkipReason(d Depth, tier int) string {
	if d == DepthPassive && tier > 0 {
		return "skipped: this step sends traffic to the targets, and the scan runs at Passive depth"
	}
	if p.MinDepth != "" && !d.AtLeast(p.MinDepth) {
		return fmt.Sprintf("skipped: this step runs at %s depth or deeper, and the scan runs at %s depth", p.MinDepth.Label(), d.Label())
	}
	return ""
}
