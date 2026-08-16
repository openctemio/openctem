package validation

import (
	"context"
	"fmt"
	"strings"

	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/logger"
)

// FindingLookup is the narrow read seam over the finding repository.
type FindingLookup interface {
	GetByID(ctx context.Context, tenantID, id shared.ID) (*vulnerability.Finding, error)
}

// AssetLookup is the narrow read seam over the asset repository.
type AssetLookup interface {
	GetByID(ctx context.Context, tenantID, assetID shared.ID) (*asset.Asset, error)
}

// defaultTimeoutSeconds bounds how long an agent may spend on a single
// validation job before the platform reclaims it.
const defaultTimeoutSeconds = 120

// safeCheckTechnique is the ATT&CK technique used for the non-intrusive
// reachability re-check. It is one of the techniques DefaultSelector's
// safe-check kind is allowed to run (see kindSupportsTechnique).
const safeCheckTechnique TechniqueID = "T1046"

// ErrNotNetworkAddressable is returned when a finding's asset has no network
// address a safe-check reachability probe can dial (e.g. a code repository,
// container image, or cloud-account finding). Callers that auto-dispatch
// validation (e.g. proof-of-fix on fix_applied) treat it as an expected skip,
// not a failure.
var ErrNotNetworkAddressable = fmt.Errorf("%w: asset is not network-addressable for a safe-check re-check", shared.ErrValidation)

// ErrNoValidationAgent is returned when a validation job would be dispatched but
// no validation-capable agent is currently online for the tenant. This makes
// the dispatch capability-gated exactly like scan dispatch
// (agent.AgentSelector.CheckAgentAvailability): the platform must never enqueue
// a validate command that no agent can consume, which would sit in the queue
// forever (the "silently inert" defect) and, for a live simulation, strand its
// run in "running". Callers treat it as an expected skip: the auto-proof-of-fix
// path logs once and moves on, the live-simulation path falls back to its
// clearly-labeled synthetic result, and the manual endpoint tells the operator
// to deploy a validation agent. It wraps ErrValidation so the HTTP layer
// surfaces a 400 with the message rather than a 500. The gate is self-arming:
// the moment a tenant registers an agent advertising the "validate" capability,
// dispatch begins — no code change or redeploy.
var ErrNoValidationAgent = fmt.Errorf("%w: no validation-capable agent is online for this tenant; deploy a validation agent to run this check", shared.ErrValidation)

// AgentAvailability reports whether a validation-capable agent is currently
// online for a tenant. It is the validation-side mirror of the scan dispatch
// pre-flight capability check: a real implementation asks the agent registry
// for online, in-capacity agents advertising the "validate" capability
// (AgentCapabilityValidate); the test stub returns a fixed answer. Optional on
// RunService — a nil gate preserves the pre-gate behavior (always dispatch).
type AgentAvailability interface {
	HasValidationAgent(ctx context.Context, tenantID shared.ID) (bool, error)
}

// networkAddressableTypes is the set of asset types whose Name() is a host,
// IP, or URL a safe-check probe can reach over the network. Types outside this
// set (repository, container, cloud_account, …) cannot be reachability-probed.
var networkAddressableTypes = map[asset.AssetType]bool{
	asset.AssetTypeDomain:         true,
	asset.AssetTypeSubdomain:      true,
	asset.AssetTypeIPAddress:      true,
	asset.AssetTypeWebsite:        true,
	asset.AssetTypeWebApplication: true,
	asset.AssetTypeAPI:            true,
	asset.AssetTypeService:        true,
	asset.AssetTypeHost:           true,
}

// isNetworkAddressable reports whether a safe-check reachability probe can
// meaningfully target an asset of the given type.
func isNetworkAddressable(t asset.AssetType) bool {
	return networkAddressableTypes[t]
}

// RunService turns "validate this finding" into a dispatched validation job.
// It resolves the finding's asset into a Target, picks an executor kind via the
// Selector against the fleet's available kinds, and hands the job to the
// dispatcher. Evidence returns asynchronously through EvidenceIngestService.
type RunService struct {
	findings   FindingLookup
	assets     AssetLookup
	dispatcher JobDispatcher
	selector   Selector
	available  []ExecutorKind
	// availability, when set, capability-gates every dispatch on a live
	// per-tenant check for an online validation agent. Nil disables the gate
	// (pre-gate behavior). Installed via SetAgentAvailability at wiring time.
	availability AgentAvailability
	// nucleiAvailability, when set, gates the deeper KindNuclei rung on a live
	// per-tenant check for an online `validate:nuclei`-capable agent (RFC-011.2
	// Phase 2b). Nil means the fleet advertises no nuclei executor, so routing
	// stays safe-check-only — 2b is inert-safe until a nuclei agent is deployed.
	nucleiAvailability NucleiAvailability
	logger             *logger.Logger
}

// NewRunService wires the run service. available is the set of executor kinds
// the agent fleet supports; the MVP passes {KindSafeCheck}.
func NewRunService(
	findings FindingLookup,
	assets AssetLookup,
	dispatcher JobDispatcher,
	selector Selector,
	available []ExecutorKind,
	log *logger.Logger,
) *RunService {
	return &RunService{
		findings:   findings,
		assets:     assets,
		dispatcher: dispatcher,
		selector:   selector,
		available:  available,
		logger:     log.With("service", "validation-run"),
	}
}

// SetAgentAvailability installs the per-tenant capability gate. When set, a
// dispatch is skipped with ErrNoValidationAgent whenever no validation-capable
// agent is online for the tenant, so a validate command is only ever queued for
// an agent that can execute it. Optional: leaving it unset keeps every dispatch
// unconditional (the pre-gate behavior), which is what the unit tests exercise.
func (s *RunService) SetAgentAvailability(a AgentAvailability) {
	s.availability = a
}

// SetNucleiAvailability installs the deeper-rung nuclei capability gate. When
// set, ValidateFinding upgrades a re-verify from safe-check to KindNuclei only
// when a `validate:nuclei`-capable agent is online for the tenant AND the
// finding carries a usable, non-destructive detection signature. Leaving it
// unset keeps routing safe-check-only (Phase 2a behavior) — the inert-safe
// default: no nuclei agent, no behavior change.
func (s *RunService) SetNucleiAvailability(a NucleiAvailability) {
	s.nucleiAvailability = a
}

// nucleiAgentOnline reports whether a nuclei-capable agent is online for the
// tenant. A nil gate (no nuclei fleet) or a lookup error both resolve to "not
// online" so the caller safely falls back to safe-check rather than failing the
// whole validation — a nuclei outage must never break the base reachability
// re-check that already worked in Phase 1.
func (s *RunService) nucleiAgentOnline(ctx context.Context, tenantID shared.ID) bool {
	if s.nucleiAvailability == nil {
		return false
	}
	ok, err := s.nucleiAvailability.HasNucleiValidationAgent(ctx, tenantID)
	if err != nil {
		s.logger.Warn("nuclei validation availability check failed; falling back to safe-check",
			"tenant_id", tenantID.String(), "error", err)
		return false
	}
	return ok
}

// ensureAgentAvailable enforces the capability gate. It returns nil when the
// gate is disabled (unwired) or a validation-capable agent is online, and
// ErrNoValidationAgent when the gate is armed but no such agent exists. It does
// not log: each caller decides how to surface the skip (the manual endpoint
// returns 400, the auto and live paths log once) so a batch of findings cannot
// produce one log line per finding.
func (s *RunService) ensureAgentAvailable(ctx context.Context, tenantID shared.ID) error {
	if s.availability == nil {
		return nil
	}
	ok, err := s.availability.HasValidationAgent(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("validation agent availability check: %w", err)
	}
	if !ok {
		return ErrNoValidationAgent
	}
	return nil
}

// ValidateFinding dispatches a validation job for the given finding and returns
// the command ID it was queued under.
func (s *RunService) ValidateFinding(ctx context.Context, tenantID, findingID shared.ID) (shared.ID, error) {
	if tenantID.IsZero() || findingID.IsZero() {
		return shared.ID{}, fmt.Errorf("%w: tenant and finding ids are required", shared.ErrValidation)
	}

	f, err := s.findings.GetByID(ctx, tenantID, findingID)
	if err != nil {
		return shared.ID{}, fmt.Errorf("finding lookup: %w", err)
	}

	assetID := f.AssetID()
	if assetID.IsZero() {
		return shared.ID{}, fmt.Errorf("%w: finding has no asset to validate against", shared.ErrValidation)
	}

	a, err := s.assets.GetByID(ctx, tenantID, assetID)
	if err != nil {
		return shared.ID{}, fmt.Errorf("asset lookup: %w", err)
	}

	if !isNetworkAddressable(a.Type()) {
		return shared.ID{}, ErrNotNetworkAddressable
	}

	address := strings.TrimSpace(a.Name())
	if address == "" {
		return shared.ID{}, fmt.Errorf("%w: asset has no address to validate against", shared.ErrValidation)
	}

	// Capability gate: never queue a validate command no agent can consume.
	if err := s.ensureAgentAvailable(ctx, tenantID); err != nil {
		return shared.ID{}, err
	}

	// Rung selection (RFC-011.2 Phase 2b): re-run the finding's OWN detection
	// template (KindNuclei, "controlled non-destructive proof") when the finding
	// carries a usable signature AND a nuclei-capable agent is online; otherwise
	// stay on safe-check ("reachability only"). This is capability-gated exactly
	// like safe-check, so a nuclei job is never enqueued for a fleet that can't
	// run it, and the fallback is honest — the recorded executor_kind/technique
	// makes clear whether the re-verify proved exploitability or only reachability.
	technique := safeCheckTechnique
	available := s.available
	templateID, cveID := "", ""
	if tmpl, cve, ok := nucleiSignature(f); ok && s.nucleiAgentOnline(ctx, tenantID) {
		technique = nucleiTechnique
		templateID, cveID = tmpl, cve
		// Offer both kinds to the selector; under nucleiTechnique it deterministically
		// returns KindNuclei (safe-check does not support T1190), while leaving the
		// base kind present means a future policy change can still degrade rather
		// than error.
		available = []ExecutorKind{KindSafeCheck, KindNuclei}
	}

	kind, err := s.selector.Select(technique, nil, available)
	if err != nil {
		return shared.ID{}, fmt.Errorf("no validation executor available for finding: %w", err)
	}
	// A safe-check-only fleet (or no signature) must not carry a nuclei signature.
	if kind != KindNuclei {
		templateID, cveID = "", ""
	}

	job := ValidationJob{
		JobID:        shared.NewID(),
		TenantID:     tenantID,
		FindingID:    findingID,
		ExecutorKind: kind,
		Technique:    technique,
		Target: Target{
			AssetID: assetID,
			Type:    a.Type().String(),
			Address: address,
		},
		TimeoutSeconds: defaultTimeoutSeconds,
		TemplateID:     templateID,
		CVEID:          cveID,
	}

	cmdID, err := s.dispatcher.Dispatch(ctx, job)
	if err != nil {
		return shared.ID{}, err
	}

	s.logger.Info("finding validation requested",
		"tenant_id", tenantID.String(),
		"finding_id", findingID.String(),
		"asset_id", assetID.String(),
		"executor_kind", string(kind),
		"command_id", cmdID.String(),
	)
	return cmdID, nil
}

// DispatchSimulationCheck dispatches a real safe-check probe for an
// attack-simulation run (RFC-012 Phase 1b). Unlike ValidateFinding it is not
// finding-scoped: the job carries the simulation run id, and the completion
// hook finalizes the run from the agent's outcome. Returns
// ErrNotNetworkAddressable when the target asset cannot be reachability-probed,
// or a selector error when the technique is not safe-checkable — in both cases
// the caller falls back to the (clearly-labeled) synthetic path.
func (s *RunService) DispatchSimulationCheck(ctx context.Context, tenantID, simRunID, assetID shared.ID, technique string) (shared.ID, error) {
	if tenantID.IsZero() || simRunID.IsZero() || assetID.IsZero() {
		return shared.ID{}, fmt.Errorf("%w: tenant, run and asset ids are required", shared.ErrValidation)
	}

	a, err := s.assets.GetByID(ctx, tenantID, assetID)
	if err != nil {
		return shared.ID{}, fmt.Errorf("asset lookup: %w", err)
	}
	if !isNetworkAddressable(a.Type()) {
		return shared.ID{}, ErrNotNetworkAddressable
	}
	address := strings.TrimSpace(a.Name())
	if address == "" {
		return shared.ID{}, fmt.Errorf("%w: asset has no address to validate against", shared.ErrValidation)
	}

	// Capability gate: only dispatch a live safe-check when a validation agent
	// is online for the tenant. Otherwise the caller (tryDispatchLive) falls
	// back to the synthetic path and finalizes the run, rather than stranding it
	// in "running" behind a command nothing will ever execute.
	if err := s.ensureAgentAvailable(ctx, tenantID); err != nil {
		return shared.ID{}, err
	}

	// Only dispatch when the simulation's technique is one the safe-check
	// executor genuinely supports; otherwise let the caller fall back.
	tech := TechniqueID(technique)
	kind, err := s.selector.Select(tech, nil, s.available)
	if err != nil {
		return shared.ID{}, fmt.Errorf("no safe-check executor for technique %s: %w", technique, err)
	}

	job := ValidationJob{
		JobID:           shared.NewID(),
		TenantID:        tenantID,
		SimulationRunID: simRunID,
		ExecutorKind:    kind,
		Technique:       tech,
		Target: Target{
			AssetID: assetID,
			Type:    a.Type().String(),
			Address: address,
		},
		TimeoutSeconds: defaultTimeoutSeconds,
	}

	cmdID, err := s.dispatcher.Dispatch(ctx, job)
	if err != nil {
		return shared.ID{}, err
	}

	s.logger.Info("simulation safe-check dispatched",
		"tenant_id", tenantID.String(),
		"simulation_run_id", simRunID.String(),
		"asset_id", assetID.String(),
		"executor_kind", string(kind),
		"technique", technique,
		"command_id", cmdID.String(),
	)
	return cmdID, nil
}
