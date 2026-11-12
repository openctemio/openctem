package scan

import "github.com/openctemio/openctem/api/pkg/domain/scanworkflow"

// StepAtDepth is the step as it runs at depth: its config with the depth's
// overlay merged over it. The step itself is not changed: the result is a
// copy. The capability's depth defaults are filled in once the tool is
// resolved (StepTool.WithDepthDefaults): a default never makes a tool that
// does not take that param ineligible.
func StepAtDepth(step *scanworkflow.Step, depth scanworkflow.Depth) *scanworkflow.Step {
	if step == nil {
		return nil
	}
	cp := *step
	cp.Config = step.RunPolicy.ConfigAt(step.Config, depth)
	return &cp
}

// WithDepthDefaults is step (a step at depth, before WithTool) with the
// capability's defaults at depth (stage.DepthDefaults) for the standard
// params the step leaves unset and the resolved tool takes. It is the
// lowest layer: the step's config, its depth overlay and any scan value
// replace it. The step itself is not changed.
func (t StepTool) WithDepthDefaults(step *scanworkflow.Step, depth scanworkflow.Depth) *scanworkflow.Step {
	if step == nil || !t.HasStage {
		return step
	}
	defs := t.Stage.DepthDefaults(string(depth))
	if len(defs) == 0 {
		return step
	}
	var cfg map[string]any
	for p, v := range defs {
		if cur, set := step.Config[p]; set && cur != nil {
			continue
		}
		if !t.takesParam(p) {
			continue
		}
		if cfg == nil {
			cfg = make(map[string]any, len(step.Config)+len(defs))
			for k, val := range step.Config {
				cfg[k] = val
			}
		}
		cfg[p] = v
	}
	if cfg == nil {
		return step
	}
	cp := *step
	cp.Config = cfg
	return &cp
}

// takesParam reports whether the resolved tool maps standard param p.
func (t StepTool) takesParam(p string) bool {
	if t.Declared {
		_, ok := t.params[p]
		return ok
	}
	_, ok := t.Stage.ToolParamKey(t.Name, p)
	return ok
}
