package scancoverage

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	scanapp "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// scheduler.go is the Phase 3 orchestration core of RFC-007: it ties the pure
// planner (which batch to scan next) to the dispatcher (how a batch reaches a
// runner). It walks each tenant's active Tenable coverage configuration, sizes a
// batch against the engine's license headroom, dispatches it, and records the
// dispatch so the same assets are not re-picked next cycle.
//
// It stays IO-free behind narrow interfaces so the rotation logic is unit-tested
// without a database or a live appliance. A thin controller adapter in
// internal/infra/controller wires real repositories to these interfaces.
// See docs/rfcs/RFC-007-license-aware-scan-coverage.md §3.2/§3.3.

// CoverageConfig is one tenant's active rolling-coverage configuration.
type CoverageConfig struct {
	TenantID shared.ID
	// SensorID optionally pins a specific runner (C3); nil → capability routing.
	SensorID *shared.ID
	// Engine is "nessus_pro" (unlimited) or "tenable_sc" (active-IP cap).
	Engine string
	// Policy is the license rule used to size the batch.
	Policy LicensePolicy
	// DefaultBatch is the performance/time-window batch size; for an unlimited
	// engine it is the whole headroom, for a capped engine it bounds a single
	// cycle so one tenant cannot consume the entire cap at once.
	DefaultBatch int
	// TemplateUUID optionally overrides the runner's default Nessus template.
	TemplateUUID string
}

// CoverageSource yields the work the scheduler acts on. The live implementation
// reads integrations + the asset estate; tests use a fake.
type CoverageSource interface {
	// ListActiveCoverage returns every tenant with an active Tenable coverage
	// integration configured for rolling coverage.
	ListActiveCoverage(ctx context.Context) ([]CoverageConfig, error)
	// ListCandidates returns assets eligible for the next batch for a tenant
	// (already filtered to in-scope, scannable assets). Order is irrelevant — the
	// planner re-sorts by criticality + staleness.
	ListCandidates(ctx context.Context, tenantID shared.ID, limit int) ([]Candidate, error)
	// ActiveIPs returns how many IPs the scheduler currently believes are live on
	// the engine for this tenant (active-IP-cap engines only; return 0 for
	// unlimited). This is the un-reclaimed count: it is what gates the next batch
	// — a capped engine will not get a new batch until a prior one has been aged
	// out / reclaimed by the runner and the count has dropped (RFC-007 §3.2).
	ActiveIPs(ctx context.Context, tenantID shared.ID) (int, error)
}

// BatchDispatcher dispatches one batch to a runner. *Dispatcher satisfies it.
type BatchDispatcher interface {
	DispatchTenableScan(ctx context.Context, in DispatchTenableInput) (shared.ID, string, error)
}

// DispatchRecord is what the scheduler hands back to the store after a batch has
// been dispatched, so the cursor advances and active-IP accounting updates.
type DispatchRecord struct {
	TenantID  shared.ID
	AssetIDs  []string
	SessionID string
	CommandID shared.ID
	// IPCount is the license IPs this batch consumes (for active-IP accounting).
	IPCount int
}

// CursorStore persists the effect of a dispatch: it advances LastScannedAt for
// the batch's assets (so they sort last next cycle) and, for capped engines,
// adds the batch to the active-IP set the runner will later reclaim.
type CursorStore interface {
	// ClaimBatch claims the batch's assets for this caller before anything is
	// dispatched: each asset's cursor moves from the LastScannedAt the caller
	// planned with to `at`, and only assets whose cursor still held that value
	// are returned. Every API replica runs the scheduler and plans from the same
	// view; the claim makes sure an asset is dispatched by one of them only.
	ClaimBatch(ctx context.Context, tenantID shared.ID, batch []Candidate, at time.Time) (claimed []string, err error)
	// ReleaseBatch undoes a claim whose dispatch failed, so the assets are
	// picked again next cycle instead of waiting out a whole rotation. It only
	// touches cursors that still hold the claim time `at`.
	ReleaseBatch(ctx context.Context, tenantID shared.ID, batch []Candidate, at time.Time) error
	MarkDispatched(ctx context.Context, rec DispatchRecord) error
}

// TargetGate applies a scan trigger's target checks (private-range policy,
// scope exclusions, scan zones) to a batch before it is dispatched.
// Implemented by *scan.Service.
type TargetGate interface {
	ResolveDispatchTargets(ctx context.Context, in scanapp.DispatchTargetsInput) (*scanapp.DispatchTargets, error)
}

// errNoTargetGate refuses a dispatch when no gate is wired (fail closed).
var errNoTargetGate = errors.New("coverage target gate is not configured; nothing dispatched")

// SchedulerConfig configures the Scheduler.
type SchedulerConfig struct {
	// CandidateLimit caps how many candidates are loaded per tenant per cycle.
	// Default: 5000.
	CandidateLimit int
	// Gate checks every batch before dispatch. Without it nothing is
	// dispatched.
	Gate   TargetGate
	Logger *logger.Logger
}

// Scheduler performs one rotation pass over all tenants' coverage configs.
type Scheduler struct {
	source     CoverageSource
	dispatcher BatchDispatcher
	store      CursorStore
	gate       TargetGate
	limit      int
	logger     *logger.Logger
}

const defaultCandidateLimit = 5000

// NewScheduler builds a Scheduler.
func NewScheduler(source CoverageSource, dispatcher BatchDispatcher, store CursorStore, cfg *SchedulerConfig) *Scheduler {
	if cfg == nil {
		cfg = &SchedulerConfig{}
	}
	limit := cfg.CandidateLimit
	if limit <= 0 {
		limit = defaultCandidateLimit
	}
	lg := cfg.Logger
	if lg == nil {
		lg = logger.NewNop()
	}
	return &Scheduler{
		source:     source,
		dispatcher: dispatcher,
		store:      store,
		gate:       cfg.Gate,
		limit:      limit,
		logger:     lg,
	}
}

// RunOnce performs a single rotation pass and returns the number of batches
// dispatched. A failure for one tenant is logged and skipped — it never aborts
// the pass for the other tenants (controllers must be resilient).
func (s *Scheduler) RunOnce(ctx context.Context) (dispatched int, err error) {
	configs, err := s.source.ListActiveCoverage(ctx)
	if err != nil {
		return 0, fmt.Errorf("list active coverage: %w", err)
	}

	for _, cfg := range configs {
		if ctx.Err() != nil {
			return dispatched, ctx.Err()
		}
		ok, derr := s.dispatchTenant(ctx, cfg)
		if derr != nil {
			s.logger.Error("coverage cycle failed for tenant",
				"tenant_id", cfg.TenantID.String(),
				"engine", cfg.Engine,
				"error", derr)
			continue
		}
		if ok {
			dispatched++
		}
	}
	return dispatched, nil
}

// dispatchTenant runs one tenant's rotation step. It returns ok=true only when a
// batch was actually dispatched.
func (s *Scheduler) dispatchTenant(ctx context.Context, cfg CoverageConfig) (bool, error) {
	// 1. Determine license headroom for this cycle.
	headroom := cfg.DefaultBatch
	if cfg.Policy.Mode == LicenseActiveIPCap {
		active, err := s.source.ActiveIPs(ctx, cfg.TenantID)
		if err != nil {
			return false, fmt.Errorf("active ips: %w", err)
		}
		headroom = cfg.Policy.Headroom(active, cfg.DefaultBatch)
		if headroom <= 0 {
			// Cap is full — a prior batch is still live on the engine. Wait for the
			// runner to reclaim it before releasing more (RFC-007 §3.2).
			s.logger.Info("coverage paused: license cap full, awaiting reclaim",
				"tenant_id", cfg.TenantID.String(),
				"active_ips", active,
				"cap", cfg.Policy.Cap)
			return false, nil
		}
	}
	if headroom <= 0 {
		return false, nil
	}

	// 2. Load candidates and pick the next batch.
	candidates, err := s.source.ListCandidates(ctx, cfg.TenantID, s.limit)
	if err != nil {
		return false, fmt.Errorf("list candidates: %w", err)
	}
	if len(candidates) == 0 {
		return false, nil
	}

	batch, ips := SelectBatch(candidates, headroom)
	if len(batch) == 0 {
		return false, nil
	}

	// 3. Guard the capped engine against an oversized single target. SelectBatch
	// always takes the top candidate even when it alone exceeds headroom (to
	// avoid starving the rotation); for an active-IP-cap engine dispatching it
	// would blow the license, so refuse and surface it rather than violate the
	// cap. A single target larger than the cap must be split manually.
	if cfg.Policy.Mode == LicenseActiveIPCap && ips > headroom {
		s.logger.Warn("coverage skipped: top target exceeds license headroom",
			"tenant_id", cfg.TenantID.String(),
			"target", batch[0].Target,
			"target_ips", ips,
			"headroom", headroom)
		return false, nil
	}

	// 4. Gate the batch like a scan trigger: private-range policy, scope
	// exclusions, scan zones (RFC-042 F16). A failed check dispatches and
	// claims nothing (fail closed).
	send, skipped, zoneID, err := s.gateBatch(ctx, cfg, batch)
	if err != nil {
		return false, err
	}

	// 5. Claim the batch. Another replica that planned from the same view gets
	// none (or only the rest) of these assets. Skipped assets are claimed
	// too, without a dispatch: their cursor moves, so they rotate to the back
	// instead of holding the top of every batch; they are checked again on
	// their next turn.
	toClaim := append(append(make([]Candidate, 0, len(send)+len(skipped)), send...), skipped...)
	claimAt := time.Now().UTC().Truncate(time.Microsecond)
	claimedIDs, err := s.store.ClaimBatch(ctx, cfg.TenantID, toClaim, claimAt)
	if err != nil {
		return false, fmt.Errorf("claim batch: %w", err)
	}
	won := make(map[string]bool, len(claimedIDs))
	for _, id := range claimedIDs {
		won[id] = true
	}
	kept := send[:0:0]
	ips = 0
	for _, c := range send {
		if won[c.AssetID] {
			kept = append(kept, c)
			ips += CountIPs(c.Target)
		}
	}
	if len(kept) < len(send) {
		s.logger.Debug("coverage batch partly claimed by another replica",
			"tenant_id", cfg.TenantID.String(), "planned", len(send), "claimed", len(kept))
	}
	batch = kept
	if len(batch) == 0 {
		return false, nil
	}

	// 6. Dispatch the batch to a runner.
	targets := make([]string, 0, len(batch))
	assetIDs := make([]string, 0, len(batch))
	for _, c := range batch {
		targets = append(targets, c.Target)
		assetIDs = append(assetIDs, c.AssetID)
	}

	cmdID, sessionID, err := s.dispatcher.DispatchTenableScan(ctx, DispatchTenableInput{
		TenantID:     cfg.TenantID,
		Targets:      targets,
		SensorID:     cfg.SensorID,
		Engine:       cfg.Engine,
		TemplateUUID: cfg.TemplateUUID,
		ScanZoneID:   zoneID,
	})
	if err != nil {
		if rerr := s.store.ReleaseBatch(ctx, cfg.TenantID, batch, claimAt); rerr != nil {
			s.logger.Warn("failed to release coverage claim after a failed dispatch",
				"tenant_id", cfg.TenantID.String(), "error", rerr)
		}
		return false, fmt.Errorf("dispatch: %w", err)
	}

	// 7. Record the dispatch: advance the cursor + active-IP accounting. If this
	// fails the batch is already in flight, so surface the error (the next cycle
	// could otherwise re-pick the same assets).
	if err := s.store.MarkDispatched(ctx, DispatchRecord{
		TenantID:  cfg.TenantID,
		AssetIDs:  assetIDs,
		SessionID: sessionID,
		CommandID: cmdID,
		IPCount:   ips,
	}); err != nil {
		return false, fmt.Errorf("mark dispatched (command %s already in flight): %w", cmdID, err)
	}

	s.logger.Info("dispatched coverage batch",
		"tenant_id", cfg.TenantID.String(),
		"command_id", cmdID.String(),
		"session_id", sessionID,
		"engine", cfg.Engine,
		"assets", len(assetIDs),
		"ips", ips,
		"headroom", headroom)
	return true, nil
}

// gateBatch runs the batch through the target gate and splits it into the
// candidates to dispatch now, the ones skipped this rotation (excluded or
// refused), and the zone the dispatched ones are in. A batch is one command,
// so it stays in one zone: the zone of its first allowed candidate (the
// highest priority); allowed candidates of another zone are left unclaimed
// for a later cycle.
func (s *Scheduler) gateBatch(ctx context.Context, cfg CoverageConfig, batch []Candidate) (send, skipped []Candidate, zoneID *shared.ID, err error) {
	if s.gate == nil {
		return nil, nil, nil, errNoTargetGate
	}
	targets := make([]string, 0, len(batch))
	for _, c := range batch {
		targets = append(targets, c.Target)
	}
	gated, err := s.gate.ResolveDispatchTargets(ctx, scanapp.DispatchTargetsInput{
		TenantID: cfg.TenantID,
		Targets:  targets,
		SensorID: cfg.SensorID,
	})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("target gate: %w", err)
	}

	key := func(t string) string { return strings.ToLower(strings.TrimSpace(t)) }
	allowed := make(map[string]string, len(gated.Allowed)) // key -> spelling the gate kept
	for _, t := range gated.Allowed {
		allowed[key(t)] = t
	}
	reasons := make(map[string]string, len(gated.Excluded)+len(gated.Refused))
	for _, t := range gated.Excluded {
		reasons[key(t)] = "matches an active scope exclusion"
	}
	for _, r := range gated.Refused {
		reasons[key(r.Target)] = r.Reason
	}

	zoneKey, zoneSet := "", false
	for _, c := range batch {
		t, ok := allowed[key(c.Target)]
		if !ok {
			skipped = append(skipped, c)
			s.logger.Info("coverage target skipped by the target gate",
				"tenant_id", cfg.TenantID.String(), "asset_id", c.AssetID, "reason", reasons[key(c.Target)])
			continue
		}
		z := gated.Zone(t)
		k := ""
		if z != nil {
			k = z.ID.String()
		}
		if !zoneSet {
			zoneKey, zoneSet = k, true
			if z != nil {
				id := z.ID
				zoneID = &id
			}
		}
		if k != zoneKey {
			continue // another zone: left for a later cycle
		}
		send = append(send, c)
	}
	return send, skipped, zoneID, nil
}
