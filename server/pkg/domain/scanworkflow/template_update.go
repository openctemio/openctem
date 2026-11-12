package scanworkflow

// Template updates (docs/architecture/scan-stages.md#template-updates). A
// tenant's copy of a system template keeps its lineage: the template it was
// made from and the template's spec as the copy last took it (the base).
// When the template changes, the changes since the base are offered to the
// copy; a person applies them (or dismisses them). A copy is never changed
// on its own.
//
// Only additive changes are offered, and only where the copy still has what
// the template had: a step the template added (and the copy does not have),
// and the dependencies of a step the template rewired (when the copy's step
// still depends on what the base had). A step the template removed, renamed
// or reconfigured is not offered: the copy's step is the tenant's.

import (
	"context"
	"slices"
	"sort"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Template change kinds.
const (
	// ChangeAddStep: the template has a step the copy lacks.
	ChangeAddStep = "add_step"
	// ChangeDependsOn: the template rewired a step the copy has as the base had it.
	ChangeDependsOn = "depends_on"
)

// TemplateChange is one change of the template offered to a copy.
type TemplateChange struct {
	Kind         string   `json:"kind"`
	StepKey      string   `json:"step_key"`
	Name         string   `json:"name"`
	Capabilities []string `json:"capabilities,omitempty"`
	Tool         string   `json:"tool,omitempty"`
	// DependsOnBefore is the copy's dependencies now (depends_on only).
	DependsOnBefore []string `json:"depends_on_before,omitempty"`
	// DependsOn is what the step depends on once applied.
	DependsOn []string `json:"depends_on"`
}

// Lineage is where a tenant's copy comes from.
type Lineage struct {
	SourceTemplateID shared.ID
	// Base is the template's spec as the copy last took it; nil: the
	// copy's own spec is the base (a copy made before lineage was kept).
	Base *Spec
}

// LineageStore keeps the lineage of the tenant's copies. Every call is
// scoped to the tenant: another tenant's workflow has none and is never
// written.
type LineageStore interface {
	// GetLineage returns the copy's lineage; nil when it has none.
	GetLineage(ctx context.Context, tenantID, workflowID shared.ID) (*Lineage, error)
	// SetLineage records the copy's source template and base.
	SetLineage(ctx context.Context, tenantID, workflowID, sourceTemplateID shared.ID, base Spec) error
}

func byKey(s Spec) map[string]SpecStep {
	out := make(map[string]SpecStep, len(s.Steps))
	for _, st := range s.Steps {
		out[st.StepKey] = st
	}
	return out
}

func sameSet(a, b []string) bool {
	x, y := slices.Clone(a), slices.Clone(b)
	sort.Strings(x)
	sort.Strings(y)
	return slices.Equal(slices.Compact(x), slices.Compact(y))
}

// TemplateChanges lists the template's changes since base that the copy can
// take (see the package comment), in the template's step order.
func TemplateChanges(base, template, copySpec Spec) []TemplateChange {
	inBase, inCopy := byKey(base), byKey(copySpec)
	steps := slices.Clone(template.Steps)
	sort.SliceStable(steps, func(i, j int) bool { return steps[i].StepOrder < steps[j].StepOrder })

	// The keys the copy has once the added steps are in.
	after := make(map[string]bool, len(copySpec.Steps)+len(steps))
	for k := range inCopy {
		after[k] = true
	}
	for _, st := range steps {
		if _, was := inBase[st.StepKey]; !was {
			after[st.StepKey] = true
		}
	}
	keep := func(deps []string) []string {
		out := make([]string, 0, len(deps))
		for _, d := range deps {
			if after[d] {
				out = append(out, d)
			}
		}
		return out
	}

	var out []TemplateChange
	for _, st := range steps {
		was, inB := inBase[st.StepKey]
		have, inC := inCopy[st.StepKey]
		switch {
		case !inB && !inC:
			out = append(out, TemplateChange{Kind: ChangeAddStep, StepKey: st.StepKey, Name: st.Name,
				Capabilities: st.Capabilities, Tool: st.Tool, DependsOn: keep(st.DependsOn)})
		case inB && inC && !sameSet(was.DependsOn, st.DependsOn) && sameSet(have.DependsOn, was.DependsOn):
			deps := keep(st.DependsOn)
			if sameSet(deps, have.DependsOn) {
				continue
			}
			out = append(out, TemplateChange{Kind: ChangeDependsOn, StepKey: st.StepKey, Name: have.Name,
				DependsOnBefore: have.DependsOn, DependsOn: deps})
		}
	}
	return out
}

// ApplyTemplateChanges returns the copy's steps with the changes applied:
// rewired steps get their new dependencies, and added steps are the
// template's steps (without their id, appended after the copy's steps).
func ApplyTemplateChanges(copySpec, template Spec, changes []TemplateChange) []SpecStep {
	tpl := byKey(template)
	rewire := map[string][]string{}
	var added []SpecStep
	for _, c := range changes {
		switch c.Kind {
		case ChangeDependsOn:
			rewire[c.StepKey] = c.DependsOn
		case ChangeAddStep:
			st, ok := tpl[c.StepKey]
			if !ok {
				continue
			}
			st.ID = ""
			st.DependsOn = c.DependsOn
			added = append(added, st)
		}
	}
	out := make([]SpecStep, 0, len(copySpec.Steps)+len(added))
	for _, st := range copySpec.Steps {
		if deps, ok := rewire[st.StepKey]; ok {
			st.DependsOn = deps
		}
		out = append(out, st)
	}
	next := len(out)
	for _, st := range added {
		next++
		st.StepOrder = next
		out = append(out, st)
	}
	return out
}
