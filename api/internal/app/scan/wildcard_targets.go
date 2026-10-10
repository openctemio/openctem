package scan

import (
	"context"
	"fmt"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A wildcard pattern (*.example.com) names a set of hosts, not a host. It is
// a dynamic selector (RFC-068, target_selectors.go): each run expands it to
// the apex and every name the inventory holds under it, and a subdomain
// discovery tool (subfinder) takes the apex alone. It never reaches a
// scanner as a literal host: live, a nuclei scan was dispatched against
// "*.example.co.uk" and the sensor's local policy refused it ("cannot
// resolve").
//
// Security: a correctness rule in front of the ownership and scope gates,
// which decide the apex and every expanded name like any other target.

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

// refuseWildcardTargets checks the wildcard selectors of a scan when it is
// saved: each must be *.<domain>, and not a root the platform lets nobody
// cover (a public suffix, a shared provider apex, a denied name).
func (s *Service) refuseWildcardTargets(_ context.Context, sc *scan.Scan) error {
	return validateSelectorTargets(sc.Targets)
}

// applyWildcardTargets is the trigger-time rule for a scan whose only tool
// is subdomain discovery: it returns a copy of the scan for this run in
// which every pattern is its apex, in the targets and in a scanner_config
// "targets" list. Any other scan keeps its patterns, which the run expands
// (expandSelectors). A pattern in scanner_config "targets" of another tool
// would reach the sensor as written, so it refuses the run. The stored scan
// is never changed.
func (s *Service) applyWildcardTargets(_ context.Context, sc *scan.Scan) (*scan.Scan, error) {
	if err := validateSelectorTargets(sc.Targets); err != nil {
		return nil, err
	}
	cfgTargets, hasCfg := sc.ScannerConfig["targets"]
	rootsOnly := sc.ScanType != scan.ScanTypeWorkflow && rootsOnlyTool(sc.ScannerName)
	if hasCfg && !rootsOnly {
		if pattern := firstWildcard(anyStrings(cfgTargets)); pattern != "" {
			return nil, shared.NewDomainError(CodeWildcardTarget, fmt.Sprintf(
				"Target %q in the scanner settings is a pattern, not a host: put it in the scan's targets, where each run expands it to the known names under %s.",
				pattern, WildcardRoot(pattern)), shared.ErrValidation)
		}
	}
	if !rootsOnly || (firstWildcard(sc.Targets) == "" && (!hasCfg || firstWildcard(anyStrings(cfgTargets)) == "")) {
		return sc, nil
	}
	run := *sc
	run.Targets = wildcardTargetsToRoots(sc.Targets)
	if hasCfg {
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
