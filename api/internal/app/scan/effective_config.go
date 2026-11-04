package scan

import (
	"bytes"
	"encoding/json"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
)

// RunContextKeyStepParams is the run context key of a scan's per-step
// overrides of standard params: {step_key: {param: value}}.
const RunContextKeyStepParams = "step_params"

// EffectiveConfigOf records the standard params a step's command carries and
// the layer each came from. step is the step as it runs at the run's depth
// (its RunPolicy still holds the depth overlay), config the command's final
// config (what the sensor receives). Only the capability's standard params
// are listed, so no header or credential value can reach the record.
//
// The layer of a value is the highest one that sets it to that value:
// stage_fixed, scan_override, depth_overlay, template_step; a port scan's
// default top ports are default_port_set. A value no layer explains is left
// out rather than guessed. The capability default layer is not recorded yet.
func EffectiveConfigOf(run *scanrun.Run, step *scanworkflow.Step, resolved StepTool, config map[string]any) scanrun.EffectiveConfig {
	depth := RunDepth(run)
	out := scanrun.EffectiveConfig{Params: map[string]scanrun.ParamValue{}, Tool: resolved.Name,
		Capability: resolved.Capability(), Depth: string(depth)}
	if !resolved.HasStage || step == nil {
		return out
	}
	overlay := step.RunPolicy.Overlay(depth).Params
	var scanOverride map[string]any
	if all, ok := run.Context[RunContextKeyStepParams].(map[string]any); ok {
		scanOverride, _ = all[step.StepKey].(map[string]any)
	}
	var fixed map[string]any
	if f := resolved.Stage.WithStageToolConfig(resolved.Name, nil); len(f) > 0 {
		fixed = f
	}
	for _, p := range resolved.Stage.Params {
		key := p.Name
		if k, ok := resolved.toolParamKey(p.Name); ok && k != "" {
			key = k
		}
		final, set := config[key]
		if !set || final == nil {
			continue
		}
		src := ""
		switch {
		case layerHas(resolved.Name, fixed, p.Name, key, final):
			src = scanrun.ParamSourceStageFixed
		case layerHas(resolved.Name, scanOverride, p.Name, key, final):
			src = scanrun.ParamSourceScanOverride
		case layerHas(resolved.Name, overlay, p.Name, key, final):
			src = scanrun.ParamSourceDepthOverlay
		case layerHas(resolved.Name, step.Config, p.Name, key, final):
			src = scanrun.ParamSourceTemplateStep
		case resolved.Stage.Key == stage.ScanPorts && p.Name == "top_n":
			src = scanrun.ParamSourceDefaultPortSet
		}
		if src != "" {
			out.Params[p.Name] = scanrun.ParamValue{Value: final, Source: src}
		}
	}
	return out.Bounded()
}

// toolParamKey is the tool's config key of a standard param.
func (t StepTool) toolParamKey(param string) (string, bool) {
	if t.Declared {
		k, ok := t.params[param]
		return k, ok
	}
	return t.Stage.ToolParamKey(t.Name, param)
}

// layerHas reports whether the layer sets the param (under its standard
// name or the tool's key) to the final value, compared after the same
// normalisation the command applies.
func layerHas(tool string, layer map[string]any, name, key string, final any) bool {
	for _, k := range []string{key, name} {
		v, ok := layer[k]
		if !ok {
			continue
		}
		if n, err := scanworkflow.NormalizeStepConfig(tool, map[string]any{k: v}); err == nil {
			if nv, ok := n[k]; ok {
				v = nv
			}
		}
		if sameJSON(v, final) {
			return true
		}
	}
	return false
}

func sameJSON(a, b any) bool {
	x, err1 := json.Marshal(a)
	y, err2 := json.Marshal(b)
	return err1 == nil && err2 == nil && bytes.Equal(x, y)
}
