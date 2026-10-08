package scan

import (
	"context"
	"fmt"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"

	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
)

// A wildcard pattern (*.example.com) names a set of hosts, not a host. The
// target validator accepts it, so it used to reach an active scanner as a
// literal target: live, a nuclei scan was dispatched against
// "*.vndirect.com.vn" and the sensor's local policy refused it ("cannot
// resolve"), a run that could never have worked.
//
// Rules:
//   - a discovery (passive) tool takes the pattern as its root domain: the
//     run hands "example.com" to subfinder, never "*.example.com";
//   - any other tool refuses it, with WILDCARD_TARGET, at create, at edit
//     and at trigger (a refused trigger is a blocked run). The way forward
//     is a discovery scan seeded with the root, or the known assets that
//     match the pattern.
//
// A workflow takes the pattern when every step that starts the run (no
// dependencies) is passive; later steps get what discovery found.
//
// Security: this is a correctness gate in front of the ownership and scope
// gates, which still run on the root domain like on any other target.

// CodeWildcardTarget refuses a wildcard pattern given to an active tool.
const CodeWildcardTarget = "WILDCARD_TARGET"

// IsWildcardTarget reports whether t is a wildcard host pattern (*.x).
func IsWildcardTarget(t string) bool {
	return strings.HasPrefix(strings.TrimSpace(t), "*.")
}

// WildcardRoot is the domain a wildcard pattern stands under: "*.x" -> "x".
func WildcardRoot(t string) string {
	return strings.ToLower(strings.TrimPrefix(strings.TrimSpace(t), "*."))
}

// firstWildcard returns the first wildcard pattern in targets, or "".
func firstWildcard(targets []string) string {
	for _, t := range targets {
		if IsWildcardTarget(t) {
			return strings.TrimSpace(t)
		}
	}
	return ""
}

// wildcardTargetsToRoots replaces every wildcard pattern with its root
// domain, keeping order and dropping duplicates (case-insensitive).
func wildcardTargetsToRoots(targets []string) []string {
	out := make([]string, 0, len(targets))
	seen := make(map[string]bool, len(targets))
	for _, t := range targets {
		v := strings.TrimSpace(t)
		if IsWildcardTarget(v) {
			v = WildcardRoot(v)
		}
		if v == "" || seen[strings.ToLower(v)] {
			continue
		}
		seen[strings.ToLower(v)] = true
		out = append(out, v)
	}
	return out
}

// wildcardRefusal is the WILDCARD_TARGET error for pattern and the tool that
// cannot take it.
func wildcardRefusal(pattern, tool string) error {
	root := WildcardRoot(pattern)
	return shared.NewDomainError(CodeWildcardTarget, fmt.Sprintf(
		"Target %q is a pattern, not a host: %s cannot scan it. Discover the subdomains of %s with a discovery scan "+
			"(for example the External discovery preset, seeded with %s), or scan the known assets that match %s.",
		pattern, tool, root, root, pattern), shared.ErrValidation)
}

// wildcardTaker reports whether the scan's tools take a wildcard pattern as
// its root domain, and otherwise names the tool that does not.
func (s *Service) wildcardTaker(ctx context.Context, sc *scan.Scan) (bool, string, error) {
	if sc.ScanType != scan.ScanTypeWorkflow {
		return stage.PassiveTool(sc.ScannerName), sc.ScannerName, nil
	}
	if sc.ScanWorkflowID == nil {
		return false, "this workflow", nil
	}
	steps, err := s.stepRepo.GetByScanWorkflowID(ctx, *sc.ScanWorkflowID)
	if err != nil {
		return false, "", fmt.Errorf("failed to get scan workflow steps: %w", err)
	}
	for _, st := range steps {
		if len(st.DependsOn) > 0 {
			continue
		}
		if !passiveStep(st) {
			return false, stepToolLabel(st), nil
		}
	}
	return true, "", nil
}

// passiveStep reports whether a step is passive work: its tool is a passive
// tool of the stage catalog, or its capabilities name a passive stage.
func passiveStep(st *scanworkflow.Step) bool {
	if st.Tool != "" {
		return stage.PassiveTool(st.Tool)
	}
	sg, err := stage.ForCapabilities(st.Capabilities)
	return err == nil && sg.Tier.Passive()
}

func stepToolLabel(st *scanworkflow.Step) string {
	if st.Tool != "" {
		return fmt.Sprintf("%s (step %q)", st.Tool, st.StepKey)
	}
	return fmt.Sprintf("step %q", st.StepKey)
}

// refuseWildcardTargets refuses a scan whose direct targets hold a wildcard
// pattern its tools cannot take. Used at create and edit.
func (s *Service) refuseWildcardTargets(ctx context.Context, sc *scan.Scan) error {
	pattern := firstWildcard(sc.Targets)
	if pattern == "" {
		return nil
	}
	ok, tool, err := s.wildcardTaker(ctx, sc)
	if err != nil {
		return err
	}
	if !ok {
		return wildcardRefusal(pattern, tool)
	}
	return nil
}

// applyWildcardTargets is the trigger-time rule: a pattern the scan's tools
// cannot take refuses the run; otherwise it returns a copy of the scan for
// this run in which every pattern is its root domain, in the targets and in
// a scanner_config "targets" list. The stored scan is never changed.
func (s *Service) applyWildcardTargets(ctx context.Context, sc *scan.Scan) (*scan.Scan, error) {
	pattern := firstWildcard(sc.Targets)
	if pattern == "" {
		if cfgTargets, ok := sc.ScannerConfig["targets"]; ok {
			pattern = firstWildcard(anyStrings(cfgTargets))
		}
	}
	if pattern == "" {
		return sc, nil
	}
	ok, tool, err := s.wildcardTaker(ctx, sc)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, wildcardRefusal(pattern, tool)
	}
	run := *sc
	run.Targets = wildcardTargetsToRoots(sc.Targets)
	if cfgTargets, ok := sc.ScannerConfig["targets"]; ok {
		cfg := make(map[string]any, len(sc.ScannerConfig))
		for k, v := range sc.ScannerConfig {
			cfg[k] = v
		}
		cfg["targets"] = wildcardTargetsToRoots(anyStrings(cfgTargets))
		run.ScannerConfig = cfg
	}
	return &run, nil
}

// anyStrings reads a JSON string list ([]string or []any of strings).
func anyStrings(v any) []string {
	switch ts := v.(type) {
	case []string:
		return ts
	case []any:
		out := make([]string, 0, len(ts))
		for _, x := range ts {
			if str, ok := x.(string); ok {
				out = append(out, str)
			}
		}
		return out
	}
	return nil
}
