package scan

// Scan approval governance (docs/rfcs/RFC-073-scan-approval-governance.md):
// the definition an approval covers, the facts the approval rules read, and
// the gate every run passes. The gate sits in triggerLoadedScan, so manual,
// scheduled, quick and retried runs and a run started after an approval all
// pass it.

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scangov"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
)

// ApprovalGate decides whether a run may start (*scangov.Service).
type ApprovalGate interface {
	CheckRun(ctx context.Context, sc *scan.Scan, def scangov.Definition, facts scangov.Facts, actor string) error
}

// GovernanceAssets reads the inventory facts of a scan's targets
// (*postgres.ScanApprovalRepository). Tenant-scoped.
type GovernanceAssets interface {
	TargetAssetFacts(ctx context.Context, tenantID shared.ID, names []string, groupIDs []shared.ID, wildcardRoots []string) (scangov.AssetFacts, error)
}

// SetApprovalGate wires scan approval. Without a gate every run is allowed
// (installations that do not wire governance); without assets the target
// facts are empty.
func (s *Service) SetApprovalGate(g ApprovalGate, assets GovernanceAssets) {
	s.approvalGate, s.governanceAssets = g, assets
}

// requireApproval runs the approval gate for sc.
func (s *Service) requireApproval(ctx context.Context, sc *scan.Scan, actor string) error {
	if s.approvalGate == nil {
		return nil
	}
	def, facts, err := s.GovernanceSubjectOf(ctx, sc)
	if err != nil {
		return fmt.Errorf("scan approval could not be checked, run refused: %w", err)
	}
	return s.approvalGate.CheckRun(ctx, sc, def, facts, actor)
}

// GovernanceSubject loads the tenant's scan and its definition and facts.
func (s *Service) GovernanceSubject(ctx context.Context, tenantID, scanID shared.ID) (*scan.Scan, scangov.Definition, scangov.Facts, error) {
	sc, err := s.scanRepo.GetByTenantAndID(ctx, tenantID, scanID)
	if err != nil {
		return nil, scangov.Definition{}, scangov.Facts{}, err
	}
	def, facts, err := s.GovernanceSubjectOf(ctx, sc)
	return sc, def, facts, err
}

// GovernanceSubjectOf is the definition an approval of sc covers and the
// facts the rules read. sc may be unsaved (the New Scan preview).
func (s *Service) GovernanceSubjectOf(ctx context.Context, sc *scan.Scan) (scangov.Definition, scangov.Facts, error) {
	tools, steps, toolTier, err := s.governanceTools(ctx, sc)
	if err != nil {
		return scangov.Definition{}, scangov.Facts{}, err
	}
	// The intensity rules read and approvers approve is the scan's declared
	// intensity (RFC-071), never below what its tools probe (a run above the
	// declared intensity is refused anyway).
	tier := max(sc.EffectiveIntensity().MaxTier(), toolTier)
	def := scangov.Definition{
		Targets:           append([]string(nil), sc.Targets...),
		ScanType:          string(sc.ScanType),
		ScannerName:       sc.ScannerName,
		ScannerConfig:     sc.ScannerConfig,
		WorkflowSteps:     steps,
		Intensity:         scangov.IntensityName(tier),
		ScheduleType:      string(sc.ScheduleType),
		ScheduleCron:      sc.ScheduleCron,
		ScheduleRRule:     sc.ScheduleRRule,
		ScheduleDay:       sc.ScheduleDay,
		ScheduleTimezone:  sc.ScheduleTimezone,
		SensorPreference:  string(sc.SensorPreference),
		Tags:              append([]string(nil), sc.Tags...),
		RunOnTenantRunner: sc.RunOnTenantRunner,
	}
	if o := sc.TargetOptions; o != (scan.TargetOptions{}) {
		def.TargetOptions = map[string]any{"cidr_mode": string(o.CIDRMode), "seen_within_days": o.SeenWithinDays, "include_stale": o.IncludeStale}
	}
	groups := scanGroupIDs(sc)
	for _, g := range groups {
		def.AssetGroupIDs = append(def.AssetGroupIDs, g.String())
	}
	if sc.ScanWorkflowID != nil {
		def.WorkflowID = sc.ScanWorkflowID.String()
	}
	if sc.ProfileID != nil {
		def.ProfileID = sc.ProfileID.String()
	}
	if sc.ScanZoneID != nil {
		def.ScanZoneID = sc.ScanZoneID.String()
	}
	if sc.ScheduleTime != nil {
		def.ScheduleTime = sc.ScheduleTime.UTC().Format("15:04")
	}
	if sc.ScheduleRunAt != nil {
		def.ScheduleRunAt = sc.ScheduleRunAt.UTC().Format(time.RFC3339)
	}

	facts := scangov.Facts{
		IntensityTier:    tier,
		Tools:            tools,
		WidestCIDRPrefix: -1,
		Recurring:        sc.ScheduleType != scan.ScheduleManual && sc.ScheduleType != scan.ScheduleOnce && sc.ScheduleType != "",
		SensorPlacement:  placement(sc),
		ZoneID:           def.ScanZoneID,
	}
	var names, roots []string
	for _, t := range sc.Targets {
		t = strings.ToLower(strings.TrimSpace(t))
		switch {
		case t == "":
			continue
		case strings.HasPrefix(t, "*."):
			facts.DynamicSelectors = true
			roots = append(roots, strings.TrimPrefix(t, "*."))
		default:
			if p, err := netip.ParsePrefix(t); err == nil && p.Bits() < p.Addr().BitLen() {
				facts.DynamicSelectors = true
				if facts.WidestCIDRPrefix < 0 || p.Bits() < facts.WidestCIDRPrefix {
					facts.WidestCIDRPrefix = p.Bits()
				}
				continue
			}
			names = append(names, t)
		}
		facts.TargetCount++
	}
	if s.governanceAssets != nil && (len(names) > 0 || len(groups) > 0 || len(roots) > 0) {
		af, err := s.governanceAssets.TargetAssetFacts(ctx, sc.TenantID, names, groups, roots)
		if err != nil {
			return scangov.Definition{}, scangov.Facts{}, err
		}
		facts.TargetCount += af.Expanded
		facts.AssetTags, facts.MaxCriticality, facts.CrownJewel = af.Tags, af.MaxCriticality, af.CrownJewel
	}
	return def, facts, nil
}

func scanGroupIDs(sc *scan.Scan) []shared.ID {
	out := make([]shared.ID, 0, len(sc.AssetGroupIDs)+1)
	seen := map[shared.ID]bool{}
	for _, g := range append([]shared.ID{sc.AssetGroupID}, sc.AssetGroupIDs...) {
		if !g.IsZero() && !seen[g] {
			seen[g] = true
			out = append(out, g)
		}
	}
	return out
}

func placement(sc *scan.Scan) string {
	if sc.RunOnTenantRunner || sc.SensorPreference == scan.SensorPreferenceTenant {
		return scangov.PlacementTenant
	}
	if sc.SensorPreference == scan.SensorPreferencePlatform {
		return scangov.PlacementPlatform
	}
	return "auto"
}

// governanceTools returns the scan's tools (lower case), the workflow steps
// as "tool" or "capability" entries for the definition, and the highest
// tier they probe at (an unknown tool counts as active).
func (s *Service) governanceTools(ctx context.Context, sc *scan.Scan) ([]string, []string, int, error) {
	if sc.ScanType != scan.ScanTypeWorkflow {
		name := strings.ToLower(strings.TrimSpace(sc.ScannerName))
		if name == "" {
			return nil, nil, int(stage.TierActive), nil
		}
		return []string{name}, nil, int(stage.ProbeTier(name)), nil
	}
	if sc.ScanWorkflowID == nil || s.stepRepo == nil {
		return nil, nil, int(stage.TierActive), nil
	}
	steps, err := s.stepRepo.GetByScanWorkflowID(ctx, *sc.ScanWorkflowID)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to get scan workflow steps: %w", err)
	}
	if len(steps) == 0 {
		return nil, nil, int(stage.TierActive), nil
	}
	var tools, defs []string
	top := -1
	for _, st := range steps {
		tier := stepTier(st)
		if tier > top {
			top = tier
		}
		if t := strings.ToLower(strings.TrimSpace(st.Tool)); t != "" {
			tools = append(tools, t)
			defs = append(defs, "tool:"+t)
		}
		for _, p := range st.PreferTools {
			tools = append(tools, strings.ToLower(strings.TrimSpace(p)))
		}
		if st.Tool == "" {
			defs = append(defs, "capabilities:"+strings.Join(st.Capabilities, "+"))
		}
	}
	return tools, defs, top, nil
}

// stepTier is the tier a workflow step probes at: its pinned tool's, else
// its capability stage's, else active.
func stepTier(st *scanworkflow.Step) int {
	if st == nil {
		return int(stage.TierActive)
	}
	if st.Tool != "" {
		return int(stage.ProbeTier(st.Tool))
	}
	if sg, ok := stage.ForStep("", st.Capabilities); ok {
		return int(sg.Tier)
	}
	return int(stage.TierActive)
}

// RunApproved starts a run of the tenant's scan as userID (the requester of
// an approval that asked to run once approved, or an emergency run). The
// run passes every gate again, the approval included.
func (s *Service) RunApproved(ctx context.Context, tenantID, scanID shared.ID, userID string) error {
	_, err := s.TriggerScan(ctx, TriggerScanExecInput{
		TenantID: tenantID.String(), ScanID: scanID.String(), TriggeredBy: userID,
		TriggerType: scanworkflow.TriggerTypeManual,
	})
	return err
}
