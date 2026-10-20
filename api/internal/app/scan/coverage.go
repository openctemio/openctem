package scan

// Continuous coverage runs (docs/rfcs/RFC-093-asset-coverage.md): the
// coverage planner starts one capability on a batch of due assets. Like an
// enrichment run, one target that may not be scanned never refuses the
// batch: it is reported with the gate's code and the rest runs. The run acts
// with the coverage policy's system authority (scope entries only, no member's act scope), at the
// capability's tier; an intrusive capability is never started this way.

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
)

// CoverageTag marks continuous coverage scans.
const CoverageTag = "auto-coverage"

// maxCoverageTargets caps one coverage run.
const maxCoverageTargets = 500

// defaultCoverageChunk is the targets per command when the stage names no
// chunk size.
const defaultCoverageChunk = 25

// CoverageScanName is the scan that carries one capability's coverage runs
// for a tenant: one per capability, reused by every batch.
func CoverageScanName(capability string) string { return "Continuous coverage: " + capability }

// CoverageInput is one batch of one capability.
type CoverageInput struct {
	TenantID   shared.ID
	Capability string
	Targets    []string
}

// CoverageResult is what was started. RunID is nil when nothing was left.
type CoverageResult struct {
	RunID *shared.ID
	Tool  string
	Kept  []string
	// Refused are the targets the gate refused, with its code.
	Refused []RefusedTarget
}

// ErrCoverageBusy: the capability's previous coverage run is still active;
// the batch waits for the next pass.
var ErrCoverageBusy = errors.New("coverage run of this capability still active")

// StartCoverage starts one capability on the targets, as the system.
func (s *Service) StartCoverage(ctx context.Context, in CoverageInput) (*CoverageResult, error) {
	if in.TenantID.IsZero() || len(in.Targets) == 0 {
		return nil, fmt.Errorf("%w: tenant and targets are required", shared.ErrValidation)
	}
	if len(in.Targets) > maxCoverageTargets {
		return nil, fmt.Errorf("%w: at most %d targets per coverage run", shared.ErrValidation, maxCoverageTargets)
	}
	st, ok := stage.Lookup(stage.Key(in.Capability))
	if !ok {
		return nil, fmt.Errorf("%w: %q is not a stage", shared.ErrValidation, in.Capability)
	}
	if st.Tier >= stage.TierIntrusive {
		return nil, fmt.Errorf("%w: intrusive capabilities are never started by coverage", shared.ErrValidation)
	}
	tool := st.DefaultTool()
	if tool == "" {
		return nil, fmt.Errorf("%w: %s has no tool", shared.ErrValidation, in.Capability)
	}
	tier, intensity, passive := scopedom.TierActive, scan.IntensityActive, st.Tier == stage.TierPassive
	if passive {
		tier, intensity = scopedom.TierPassive, scan.IntensityPassive
	}
	gated, err := s.ResolveDispatchTargets(ctx, DispatchTargetsInput{
		TenantID: in.TenantID,
		Targets:  in.Targets,
		// The policy's explicit system authority: scope entries and the
		// tier, never a member's act scope (and never "no actor").
		SystemPolicy: string(scan.ManagedByCoverage),
		PassiveOnly:  passive,
		Tier:         &tier,
		// Zone routing here: a target no zone can place is refused on its
		// own (zone_none, zone_no_sensor), so the rest of the batch runs.
		MaxTargets: maxCoverageTargets,
		Path:       "auto_coverage",
	})
	if err != nil {
		return nil, fmt.Errorf("coverage targets not checked, nothing dispatched: %w", err)
	}
	res := &CoverageResult{Tool: tool, Refused: gated.Refused}
	allowed := make(map[string]bool, len(gated.Allowed))
	for _, t := range gated.Allowed {
		allowed[strings.ToLower(t)] = true
	}
	for _, t := range gated.Excluded {
		res.Refused = append(res.Refused, RefusedTarget{Target: t, Code: "excluded", Reason: "excluded"})
	}
	for _, t := range in.Targets {
		if allowed[strings.ToLower(strings.TrimSpace(t))] {
			res.Kept = append(res.Kept, strings.TrimSpace(t))
		}
	}
	if len(res.Kept) == 0 {
		return res, nil
	}

	sc, err := s.coverageScan(ctx, in.TenantID, in.Capability)
	if err != nil {
		return nil, err
	}
	sc.SetTargets(res.Kept)
	// One command per chunk of the stage's size (list tools are efficient
	// with lists), not one per target.
	perJob := st.ChunkSizeFor(tool)
	if perJob <= 0 {
		perJob = defaultCoverageChunk
	}
	if err := sc.SetSingleScanner(tool, map[string]any{"targets": res.Kept}, perJob); err != nil {
		return nil, fmt.Errorf("failed to set scanner: %w", err)
	}
	if err := s.applyIntensity(ctx, sc, string(intensity)); err != nil {
		return nil, err
	}
	if err := s.scanRepo.Update(ctx, sc); err != nil {
		return nil, fmt.Errorf("failed to update coverage scan: %w", err)
	}
	run, err := s.TriggerScan(ctx, TriggerScanExecInput{
		TenantID:      in.TenantID.String(),
		ScanID:        sc.ID.String(),
		SkipIfRunning: true,
		// The run is the coverage policy's: no person is behind it.
		TriggerType: scanworkflow.TriggerTypeSystem,
		TriggeredBy: PolicyTriggerPrefix + string(scan.ManagedByCoverage),
		Context:     map[string]any{"trigger": "auto_coverage", "capability": in.Capability, "target_count": len(res.Kept)},
	})
	if err != nil {
		if errors.Is(err, ErrScanRunInProgress) {
			return nil, ErrCoverageBusy
		}
		return nil, fmt.Errorf("failed to trigger coverage: %w", err)
	}
	res.RunID = &run.ID
	return res, nil
}

// coverageScan returns the tenant's coverage scan of a capability, creating
// it on first use. The scan is found by its managed key, never by name: a
// person's scan that carries the coverage scan's name is left alone and the
// managed scan is created under a different name. It is ad hoc (hidden from
// the configurations list).
func (s *Service) coverageScan(ctx context.Context, tenantID shared.ID, capability string) (*scan.Scan, error) {
	sc, err := s.scanRepo.GetManaged(ctx, tenantID, scan.ManagedByCoverage, capability)
	if err == nil {
		return sc, nil
	}
	if !errors.Is(err, shared.ErrNotFound) {
		return nil, fmt.Errorf("load coverage scan: %w", err)
	}
	base := CoverageScanName(capability)
	var createErr error
	for _, name := range []string{base, base + " (platform)", ""} {
		if name == "" {
			name = fmt.Sprintf("%s (%s)", base, shared.NewID().String()[:8])
		}
		sc, err = scan.NewScan(tenantID, name, shared.ID{}, scan.ScanTypeSingle)
		if err != nil {
			return nil, fmt.Errorf("failed to create scan: %w", err)
		}
		sc.AdHoc = true
		sc.ManagedBy, sc.ManagedKey = scan.ManagedByCoverage, capability
		sc.Description = "Continuous coverage of every asset that needs " + capability
		sc.SetTags([]string{CoverageTag})
		if err := sc.SetSingleScanner(stageTool(capability), map[string]any{}, 1); err != nil {
			return nil, fmt.Errorf("failed to set scanner: %w", err)
		}
		if createErr = s.scanRepo.Create(ctx, sc); createErr == nil {
			s.logAudit(ctx, AuditContext{TenantID: tenantID.String()},
				NewSuccessEvent(audit.ActionScanConfigManagedCreated, audit.ResourceTypeScanConfig, sc.ID.String()).
					WithResourceName(sc.Name).
					WithMetadata("managed_by", string(scan.ManagedByCoverage)).
					WithMetadata("managed_key", capability))
			return sc, nil
		}
		if !errors.Is(createErr, shared.ErrAlreadyExists) {
			break
		}
		// Another replica created it first, or the name is taken: look again.
		if got, gerr := s.scanRepo.GetManaged(ctx, tenantID, scan.ManagedByCoverage, capability); gerr == nil {
			return got, nil
		}
	}
	return nil, fmt.Errorf("failed to create coverage scan: %w", createErr)
}

func stageTool(capability string) string {
	st, _ := stage.Lookup(stage.Key(capability))
	return st.DefaultTool()
}
