package scan

// Rollover (RFC-046 D5, §6.3): a scheduled run that reaches its deadline ends
// partial and records the targets it did not finish. The next scheduled run
// of the same scan plans those targets first, so a scan whose window is too
// short still covers everything over successive windows instead of
// rescanning the head of its list every time.
// See api/docs/rfcs/RFC-046-scans-redesign.md.

import (
	"context"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/pipeline"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
)

// planRolloverFirst moves the previous scheduled run's unfinished targets to
// the front of resolved.Targets and records the rollover in the run context.
//
// Only scheduled runs roll over: a manual, API or ad-hoc run has no "next".
// The rollover never adds a target: it only reorders the targets the gate
// resolved for this run, so a leftover target that has since been excluded by
// scope, removed from the group or archived is dropped, not scanned.
func (s *Service) planRolloverFirst(ctx context.Context, sc *scan.Scan, triggerType pipeline.TriggerType, resolved *resolvedTargets, runContext map[string]any) {
	if triggerType != pipeline.TriggerTypeSchedule || resolved == nil || len(resolved.Targets) == 0 {
		return
	}
	store, ok := s.runRepo.(pipeline.RolloverStore)
	if !ok {
		return
	}
	ro, err := store.LatestRollover(ctx, sc.TenantID, sc.ID)
	if err != nil {
		// Planning order is an optimisation; the run still scans every target.
		s.logger.Warn("failed to read rollover targets; planning in the usual order",
			"scan_id", sc.ID.String(), "error", err)
		return
	}
	if ro == nil {
		return
	}
	ordered, n := rolloverFirst(resolved.Targets, ro.Targets)
	if n == 0 {
		return
	}
	resolved.Targets = ordered
	runContext["rollover_from_run_id"] = ro.FromRunID.String()
	runContext["rollover_target_count"] = n
	s.logger.Info("planning unfinished targets of the previous run first",
		"scan_id", sc.ID.String(), "from_run_id", ro.FromRunID.String(), "count", n)
}

// rolloverFirst returns targets with the ones listed in unfinished moved to
// the front, in unfinished's order, and how many moved. Matching ignores case
// and surrounding space, as target resolution does; the spelling in targets
// is kept. Targets not in unfinished keep their order. Nothing is added.
func rolloverFirst(targets, unfinished []string) ([]string, int) {
	if len(targets) == 0 || len(unfinished) == 0 {
		return targets, 0
	}
	index := make(map[string]int, len(targets))
	for i, t := range targets {
		key := strings.ToLower(strings.TrimSpace(t))
		if _, dup := index[key]; !dup {
			index[key] = i
		}
	}
	moved := make([]bool, len(targets))
	out := make([]string, 0, len(targets))
	for _, u := range unfinished {
		i, ok := index[strings.ToLower(strings.TrimSpace(u))]
		if !ok || moved[i] {
			continue
		}
		moved[i] = true
		out = append(out, targets[i])
	}
	n := len(out)
	if n == 0 {
		return targets, 0
	}
	for i, t := range targets {
		if !moved[i] {
			out = append(out, t)
		}
	}
	return out, n
}
