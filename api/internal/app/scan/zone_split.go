package scan

// A workflow scan whose targets fall in several scan zone groups runs as one
// child run per group under a parent run, instead of being refused (owner
// rule: a scan runs what is supported). Architecture:
// docs/architecture/scan-zones.md ("Workflow runs over several zones").
//
// Each child is an ordinary workflow run created by the same path as an
// unsplit run (admitWorkflowRun, startWorkflowRun) with its own copy of the
// run context: its targets, and the zone stamp that keeps every step
// command inside the zone (private targets only through that zone's
// sensors). The unzoned public group carries no zone and routes to shared
// or organization sensors exactly as an unzoned run does. The parent
// dispatches nothing: it holds the scan's schedule occurrence and its
// concurrency slot, lists the groups, and settles from its children
// (scanrun.ZoneSplitStore).

import (
	"context"
	"errors"
	"fmt"
	"maps"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/scanzone"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Fields of the zone_split run context value.
const (
	splitKeyGroups   = "groups"
	splitKeyParent   = "parent_run_id"
	splitKeyZoneID   = "zone_id"
	splitKeyZoneName = "zone_name"
	splitKeyPart     = "part"
	splitKeyParts    = "parts"
	splitKeyTargets  = "target_count"
	splitKeyRunID    = "run_id"
	splitKeyStatus   = "status"
	splitKeyReason   = "reason"

	splitGroupStarted = "started"
	splitGroupRefused = "refused"
)

// zoneChild is one admitted child of a split before it is created.
type zoneChild struct {
	in    *workflowRunInput
	group workflowZoneGroup
}

// triggerZoneSplit starts a workflow run whose targets form several zone
// groups: every child is admitted first (routing, scan windows), then the
// parent and the admitted children are created. A group that is refused is
// listed on the parent with its reason. When every group is refused nothing
// is created and the first refusal is returned (a blocked run, as before).
// The child path takes an explicit target list and zone, so a later change
// can regroup targets (for instance after a sensor resolves names) and call
// it again.
func (s *Service) triggerZoneSplit(ctx context.Context, base workflowRunInput, routing *scanzone.Plan,
	groups []workflowZoneGroup, uncovered []scanzone.Uncovered,
) (*scanrun.Run, error) {
	var (
		admitted []zoneChild
		firstErr error
	)
	listed := make([]map[string]any, 0, len(groups))
	for _, g := range groups {
		in := s.zoneChildInput(base, routing, g)
		entry := splitGroupEntry(g)
		if err := s.admitWorkflowRun(ctx, in); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			entry[splitKeyStatus], entry[splitKeyReason] = splitGroupRefused, s.splitAdmissionReason(ctx, g, err)
			listed = append(listed, entry)
			continue
		}
		listed = append(listed, entry)
		admitted = append(admitted, zoneChild{in: in, group: g})
	}
	if len(admitted) == 0 {
		return nil, firstErr
	}

	parent, err := s.createSplitParent(ctx, base, routing, uncovered, listed)
	if err != nil {
		return nil, err
	}
	started := 0
	for i, c := range admitted {
		c.in.parent = parent
		c.in.runContext[scanrun.RunContextKeyZoneSplit] = childSplitInfo(parent, c.group, i+1, len(admitted))
		entry := findGroupEntry(listed, c.group)
		run, err := s.startWorkflowRun(ctx, c.in)
		if err != nil {
			s.logger.Warn("failed to start a zone run of a split workflow run", "run_id", parent.ID.String(),
				"zone", logger.SanitizeValue(zoneLabel(c.group)), "error", logger.SanitizeError(err))
			entry[splitKeyStatus], entry[splitKeyReason] = splitGroupRefused, splitStartFailedReason
			continue
		}
		started++
		entry[splitKeyStatus], entry[splitKeyRunID] = splitGroupStarted, run.ID.String()
	}
	parent.Context[scanrun.RunContextKeyZoneSplit] = map[string]any{splitKeyGroups: listed}
	if err := s.runRepo.Update(ctx, parent); err != nil {
		s.logger.Warn("failed to record the zone runs of a split run", "run_id", parent.ID.String(), "error", err)
	}
	if started == 0 {
		msg := "No scan zone run could start"
		if err := s.runRepo.UpdateStatus(ctx, parent.TenantID, parent.ID, scanrun.RunStatusFailed, msg); err != nil {
			s.logger.Warn("failed to fail a split run without zone runs", "run_id", parent.ID.String(), "error", err)
		}
		parent.Status = scanrun.RunStatusFailed
	}
	return parent, nil
}

// zoneChildInput is the run input of group g: a copy of the trigger's run
// context with the group's targets and zone stamp (none for the unzoned
// group, whose routing workflowRunZone decides as for an unzoned run).
func (s *Service) zoneChildInput(base workflowRunInput, routing *scanzone.Plan, g workflowZoneGroup) *workflowRunInput {
	in := base
	in.runContext = maps.Clone(base.runContext)
	delete(in.runContext, scanrun.RunContextKeyScanZoneID)
	delete(in.runContext, scanrun.RunContextKeySensorRouting)
	in.targets = g.Targets
	// The uncovered targets are listed once, on the parent.
	in.plan = planWorkflowGroup(base.sc, routing, &g, nil)
	if g.Zone != nil {
		in.runContext[scanrun.RunContextKeyScanZoneID] = g.Zone.ID.String()
	}
	// Never fails: the plan has one batch.
	_ = recordZonePlan(in.plan, in.runContext)
	return &in
}

// createSplitParent creates the parent run of a split: no steps, every
// group's targets, the uncovered ones, and the groups.
func (s *Service) createSplitParent(ctx context.Context, base workflowRunInput, routing *scanzone.Plan,
	uncovered []scanzone.Uncovered, listed []map[string]any,
) (*scanrun.Run, error) {
	sc := base.sc
	runContext := maps.Clone(base.runContext)
	delete(runContext, scanrun.RunContextKeyScanZoneID)
	plan := planWorkflowSplit(sc, routing)
	plan.Uncovered = uncovered
	plan.Warnings = uncoveredWarnings(uncovered)
	plan.Summary["uncovered_targets"] = len(uncovered)
	var all []string
	for _, b := range plan.Batches {
		all = append(all, b.Targets...)
	}
	runContext["targets"] = all
	_ = recordZonePlan(plan, runContext)
	runContext[scanrun.RunContextKeyZoneSplit] = map[string]any{splitKeyGroups: listed}

	parent, err := scanrun.NewRun(base.template.ID, sc.TenantID, nil, base.triggerType, base.triggeredBy, runContext)
	if err != nil {
		return nil, fmt.Errorf("failed to create scan run: %w", err)
	}
	parent.RetryAttempt = base.retryAttempt
	parent.ScanID = &sc.ID
	parent.ScheduledFor = base.scheduledFor
	if sc.ProfileID != nil {
		parent.ScanProfileID = sc.ProfileID
	}
	if err := s.runRepo.CreateRunIfUnderLimit(ctx, parent, MaxConcurrentRunsPerScan, MaxConcurrentRunsPerTenant); err != nil {
		return nil, err
	}
	parent.Start()
	if err := s.runRepo.Update(ctx, parent); err != nil {
		s.logger.Warn("failed to start a split run", "run_id", parent.ID.String(), "error", err)
	}
	return parent, nil
}

// splitGroupEntry is a group as the parent lists it.
func splitGroupEntry(g workflowZoneGroup) map[string]any {
	e := map[string]any{splitKeyTargets: len(g.Targets)}
	if g.Zone != nil {
		e[splitKeyZoneID], e[splitKeyZoneName] = g.Zone.ID.String(), g.Zone.Name
	}
	return e
}

// findGroupEntry is the parent's entry of g.
func findGroupEntry(listed []map[string]any, g workflowZoneGroup) map[string]any {
	want := ""
	if g.Zone != nil {
		want = g.Zone.ID.String()
	}
	for _, e := range listed {
		if id, _ := e[splitKeyZoneID].(string); id == want {
			return e
		}
	}
	return map[string]any{}
}

// childSplitInfo is a child's zone_split value.
func childSplitInfo(parent *scanrun.Run, g workflowZoneGroup, part, parts int) map[string]any {
	info := map[string]any{splitKeyParent: parent.ID.String(), splitKeyPart: part, splitKeyParts: parts}
	if g.Zone != nil {
		info[splitKeyZoneID], info[splitKeyZoneName] = g.Zone.ID.String(), g.Zone.Name
	}
	return info
}

func zoneLabel(g workflowZoneGroup) string {
	if g.Zone == nil {
		return "(no zone)"
	}
	return g.Zone.Name
}

// splitStartFailedReason is the reason a zone group shows when its zone run
// could not start, or its admission failed for a reason that is not a
// refusal: the error itself (a database or internal failure) is logged,
// never stored on the run, which the API and the console show.
const splitStartFailedReason = "the zone run could not start"

// splitAdmissionReason is the reason a zone group shows when its admission
// refused it: a refusal's own message (scope, zone, scan window), which is
// written for the reader; any other error gets splitStartFailedReason and is
// logged.
func (s *Service) splitAdmissionReason(ctx context.Context, g workflowZoneGroup, err error) string {
	var de *shared.DomainError
	if errors.As(err, &de) && de.Message != "" {
		return oneLine(de.Message)
	}
	s.logger.Warn("failed to admit a zone run of a split workflow run",
		"zone", logger.SanitizeValue(zoneLabel(g)), "error", logger.SanitizeError(err))
	return splitStartFailedReason
}
