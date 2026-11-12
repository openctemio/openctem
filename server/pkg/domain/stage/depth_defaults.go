package stage

// The capability default layer of a step's standard params, per run depth
// (research 426 decision OD-1; docs/architecture/scan-stages.md §1.5): the
// lowest layer, under the workflow step's config and its depth overlay, so
// any step, scan or run value replaces it.
//
// vuln.templates: low to critical at standard depth, info to critical at
// deep. Info matches (technology, panels, TLS and header posture) are filed
// as info exposures, not findings (docs/architecture/exposure-taxonomy.md).

import "slices"

// ParamSeverity is the severity standard param of vuln.templates.
const ParamSeverity = "severity"

// Severities of vuln.templates at each depth.
var (
	StandardTemplateSeverities = []string{"critical", "high", "medium", "low"}
	DeepTemplateSeverities     = []string{"critical", "high", "medium", "low", "info"}
)

// DepthDefaults are the stage's default standard params at depth ("passive",
// "standard" or "deep"; nil when it has none). A new map each call.
func (s Stage) DepthDefaults(depth string) map[string]any {
	if s.Key != VulnTemplates {
		return nil
	}
	switch depth {
	case "standard":
		return map[string]any{ParamSeverity: slices.Clone(StandardTemplateSeverities)}
	case "deep":
		return map[string]any{ParamSeverity: slices.Clone(DeepTemplateSeverities)}
	}
	return nil
}

// WithDepthDefaults is config with the stage's depth defaults filled in for
// the standard params config does not set (config is not changed; it is
// returned as is when nothing is filled).
func (s Stage) WithDepthDefaults(depth string, config map[string]any) map[string]any {
	defs := s.DepthDefaults(depth)
	fill := false
	for k := range defs {
		if v, set := config[k]; !set || v == nil {
			fill = true
		}
	}
	if !fill {
		return config
	}
	out := make(map[string]any, len(config)+len(defs))
	for k, v := range config {
		out[k] = v
	}
	for k, v := range defs {
		if cur, set := out[k]; !set || cur == nil {
			out[k] = v
		}
	}
	return out
}
