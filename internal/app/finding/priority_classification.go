package finding

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/api/internal/infra/telemetry"
	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// PriorityClassificationService orchestrates finding priority classification.
// It enriches findings with EPSS/KEV data, evaluates override rules,
// and applies the default CTEM classification logic.
type PriorityClassificationService struct {
	findingRepo   vulnerability.FindingRepository
	assetRepo     asset.Repository
	epssRepo      EPSSRepository
	kevRepo       KEVRepository
	ruleRepo      PriorityRuleRepository
	auditRepo     PriorityAuditRepository
	controlLookup CompensatingControlLookup // optional, may be nil
	// businessContext resolves per-asset business-unit / business-service
	// criticality so an asset's EFFECTIVE criticality can be raised to the most
	// critical of {own, its BU, the services it powers} — CTEM's business
	// alignment. Optional — nil keeps classification on the asset's own
	// criticality (a pure floor, never a downgrade).
	businessContext BusinessContextLookup
	// reachabilityOracle feeds attack-path reachability into classification:
	// an internal asset that sits on a validated internet→KEV/crown-jewel attack
	// path is treated as reachable, so the "KEV+reachable→P0" / "critical+
	// reachable→P1" gates fire for the whole chain, not just directly-public
	// assets. Optional — nil keeps the asset-exposure-only fallback (no change).
	reachabilityOracle ReachabilityOracle
	// threatModelOracle feeds the threat-model engine's output into
	// classification: an asset sitting on an OPEN, high-score threat in the
	// tenant's latest generated threat model (attacker × chain-hop × technique)
	// is treated as reachable, so the exploitability gates fire on the whole
	// modeled chain. Optional — nil keeps classification unchanged (no threat
	// model / no oracle → no effect, never a downgrade).
	threatModelOracle ThreatModelOracle
	// F3 / optional publisher that fires a priority-changed
	// event whenever class transitions. Nil → no publishing (safe
	// default; classification still runs).
	changePublisher PriorityChangePublisher
	// optional flood guard that suppresses downstream fan-out
	// on bursts at the highest priority class. Nil → always fan out
	// (legacy behaviour, unsafe on noisy tenants). Classification
	// itself is NEVER altered by the guard — only the event emission.
	priorityFloodGuard *PriorityFloodGuard
	logger             *logger.Logger
}

// SetControlLookup wires the compensating control lookup for priority calculation.
func (s *PriorityClassificationService) SetControlLookup(lookup CompensatingControlLookup) {
	s.controlLookup = lookup
}

// SetBusinessContextLookup wires the business-unit / business-service criticality
// lookup used to raise an asset's effective criticality. Safe to call after
// construction; nil keeps classification on the asset's own criticality.
func (s *PriorityClassificationService) SetBusinessContextLookup(lookup BusinessContextLookup) {
	s.businessContext = lookup
}

// businessContextFor fetches a single asset's business context (single-finding
// path). A nil lookup, a zero asset, or any error yields the zero context —
// which can only classify upwards via effectiveCriticality, never a downgrade.
func (s *PriorityClassificationService) businessContextFor(ctx context.Context, tenantID, assetID shared.ID) AssetBusinessContext {
	if s.businessContext == nil || assetID.IsZero() {
		return AssetBusinessContext{}
	}
	m, err := s.businessContext.GetForAssets(ctx, tenantID, []shared.ID{assetID})
	if err != nil {
		s.logger.Warn("business context lookup failed",
			"tenant_id", tenantID.String(), "error", err.Error())
		return AssetBusinessContext{}
	}
	return m[assetID]
}

// ReachabilityOracle returns, for a tenant, the set of asset IDs that sit on a
// validated attack path from a public entry point to a KEV/crown-jewel target
// (entry points + hops + targets of the exposure-chain graph). Implemented over
// the attack-surface service with a short TTL cache so per-finding classification
// stays cheap.
type ReachabilityOracle interface {
	ReachableFromPublic(ctx context.Context, tenantID shared.ID) (map[string]bool, error)
}

// SetReachabilityOracle wires attack-path reachability into classification.
// Optional — nil keeps the asset-exposure-only fallback.
func (s *PriorityClassificationService) SetReachabilityOracle(o ReachabilityOracle) {
	s.reachabilityOracle = o
}

// reachableSet fetches the tenant's attack-path-reachable asset set; a nil oracle
// or any error yields an empty set (classification degrades to the exposure-only
// fallback — never blocks).
func (s *PriorityClassificationService) reachableSet(ctx context.Context, tenantID shared.ID) map[string]bool {
	if s.reachabilityOracle == nil {
		return nil
	}
	set, err := s.reachabilityOracle.ReachableFromPublic(ctx, tenantID)
	if err != nil {
		s.logger.Warn("attack-path reachability lookup failed", "tenant_id", tenantID.String(), "error", err.Error())
		return nil
	}
	return set
}

// ThreatModelOracle returns, for a tenant, the set of asset IDs that sit on an
// OPEN, high-score threat in the tenant's latest generated threat model — the
// entry points, hops, and targets of unmitigated modeled attack chains. Mirrors
// ReachabilityOracle: implemented over the threat-model store with a short TTL
// cache so per-finding classification stays cheap (one tenant-scoped, indexed
// query per cache miss — no N+1).
type ThreatModelOracle interface {
	OnOpenThreatPath(ctx context.Context, tenantID shared.ID) (map[string]bool, error)
}

// SetThreatModelOracle wires the threat-model engine's output into
// classification. Optional — nil keeps classification unchanged.
func (s *PriorityClassificationService) SetThreatModelOracle(o ThreatModelOracle) {
	s.threatModelOracle = o
}

// setControlProtection applies a single asset's effective reduction factor to a
// priority context. A 0 factor is the compensating_controls column default and
// means "no measured reduction", so it does NOT mark the asset as protected —
// otherwise a control saved without a factor would silently suppress P1.
//
// This is the one place the "protected" rule is expressed; both the per-finding
// and the batch classification paths go through it.
func setControlProtection(pctx *vulnerability.PriorityContext, reduction float64) {
	if reduction <= 0 {
		return
	}
	pctx.IsProtected = true
	pctx.ControlReductionFactor = reduction
}

// applyControlProtection marks pctx as protected when the finding's asset is
// covered by an effective compensating control.
//
// This is the ONLY thing that makes a compensating control affect priority, so
// every path that builds a PriorityContext must call it. It previously lived
// inline in the batch and explain paths but not in ClassifyFinding — which is
// the path the control-change fan-out itself drives (LinkAssets → reclassify
// sweep → Reclassifier.reclassifyAsset → ClassifyFinding), so linking an asset
// to a control enqueued a sweep through a classifier that could not see
// controls. Keep this shared rather than re-inlining it.
//
// Advisory: a nil lookup, a zero asset, or any error leaves pctx untouched,
// which can only classify upwards — never a silent downgrade.
func (s *PriorityClassificationService) applyControlProtection(
	ctx context.Context,
	tenantID shared.ID,
	assetID shared.ID,
	pctx *vulnerability.PriorityContext,
) {
	if s.controlLookup == nil || assetID.IsZero() {
		return
	}
	reductions, err := s.controlLookup.GetEffectiveForAssets(ctx, tenantID, []shared.ID{assetID})
	if err != nil {
		s.logger.Warn("compensating control lookup failed",
			"tenant_id", tenantID.String(), "error", err.Error())
		return
	}
	setControlProtection(pctx, reductions[assetID])
}

// threatenedSet fetches the tenant's open-threat-path asset set; a nil oracle or
// any error yields a nil set (classification is unaffected — the signal simply
// does not fire, never a downgrade).
func (s *PriorityClassificationService) threatenedSet(ctx context.Context, tenantID shared.ID) map[string]bool {
	if s.threatModelOracle == nil {
		return nil
	}
	set, err := s.threatModelOracle.OnOpenThreatPath(ctx, tenantID)
	if err != nil {
		s.logger.Warn("threat-model lookup failed", "tenant_id", tenantID.String(), "error", err.Error())
		return nil
	}
	return set
}

// SetChangePublisher wires the priority-change event publisher. Safe to
// call after construction; nil disables publishing.
func (s *PriorityClassificationService) SetChangePublisher(p PriorityChangePublisher) {
	s.changePublisher = p
}

// SetPriorityFloodGuard wires the anti-flap budget used to suppress
// downstream fan-out on top-class bursts from noisy scanners. Nil
// disables the guard. Safe to call after construction.
func (s *PriorityClassificationService) SetPriorityFloodGuard(g *PriorityFloodGuard) {
	s.priorityFloodGuard = g
}

// EPSSRepository provides EPSS score lookups.
type EPSSRepository interface {
	GetByCVEIDs(ctx context.Context, cveIDs []string) (map[string]EPSSData, error)
}

// KEVRepository provides KEV catalog lookups.
type KEVRepository interface {
	GetByCVEIDs(ctx context.Context, cveIDs []string) (map[string]KEVData, error)
}

// PriorityRuleRepository provides override rule lookups.
type PriorityRuleRepository interface {
	ListActiveByTenant(ctx context.Context, tenantID shared.ID) ([]*vulnerability.PriorityOverrideRule, error)
}

// PriorityAuditRepository records priority changes.
type PriorityAuditRepository interface {
	LogChange(ctx context.Context, entry PriorityAuditEntry) error
}

// PriorityChangeEvent is emitted whenever a finding's priority class
// transitions to a new value. Downstream consumers (notification
// service, assignment-rule service, dashboard live feed) subscribe via
// the outbox.
//
// (F3, B1, B2): emission is the mechanism that wires the
// reclassification sweep to the rest of the system. Without this
// event, a priority change is a silent dashboard update — an operator
// can miss that a P3 just became P0.
type PriorityChangeEvent struct {
	TenantID      shared.ID
	FindingID     shared.ID
	PreviousClass *vulnerability.PriorityClass // nil for first classification
	NewClass      vulnerability.PriorityClass
	Reason        string
	Source        string // "auto" | "rule" | "sweep" | "manual"
	RuleID        *shared.ID
	At            time.Time
}

// PriorityChangePublisher delivers priority-change events to downstream
// consumers, typically by inserting into the notification outbox.
// Optional — when nil, classification still runs but no event is fired.
type PriorityChangePublisher interface {
	Publish(ctx context.Context, event PriorityChangeEvent) error
}

// CompensatingControlLookup provides lookups for effective controls on assets/findings.
type CompensatingControlLookup interface {
	// GetEffectiveForAssets returns max reduction_factor per asset with active+effective controls.
	// Returns map[assetID]reductionFactor (0.0-1.0).
	GetEffectiveForAssets(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) (map[shared.ID]float64, error)
}

// EPSSData holds EPSS score for a CVE.
type EPSSData struct {
	Score      float64
	Percentile float64
}

// KEVData holds KEV catalog info for a CVE.
type KEVData struct {
	DueDate    *time.Time
	Ransomware string
}

// PriorityAuditEntry represents a priority change log entry.
type PriorityAuditEntry struct {
	TenantID      shared.ID
	FindingID     shared.ID
	PreviousClass *vulnerability.PriorityClass
	NewClass      vulnerability.PriorityClass
	Reason        string
	Source        string // "auto", "rule", "manual"
	RuleID        *shared.ID
	ActorID       *shared.ID
}

// NewPriorityClassificationService creates a new service.
func NewPriorityClassificationService(
	findingRepo vulnerability.FindingRepository,
	assetRepo asset.Repository,
	epssRepo EPSSRepository,
	kevRepo KEVRepository,
	ruleRepo PriorityRuleRepository,
	auditRepo PriorityAuditRepository,
	log *logger.Logger,
) *PriorityClassificationService {
	return &PriorityClassificationService{
		findingRepo: findingRepo,
		assetRepo:   assetRepo,
		epssRepo:    epssRepo,
		kevRepo:     kevRepo,
		ruleRepo:    ruleRepo,
		auditRepo:   auditRepo,
		logger:      log.With("service", "priority-classification"),
	}
}

// ClassifyFinding computes priority for a single finding.
//
// (O1 invariant): emits ctem_stage_* metrics so dashboards and
// alert rules have real numbers for the Prioritization stage. Skipped
// on manual overrides — those bypass the stage entirely.
func (s *PriorityClassificationService) ClassifyFinding(
	ctx context.Context,
	tenantID shared.ID,
	finding *vulnerability.Finding,
	assetEntity *asset.Asset,
) error {
	// Skip manual overrides
	if finding.PriorityClassOverride() {
		return nil
	}

	// O1: mark entry into the Prioritization stage. Priority label
	// uses the class BEFORE classification so the counter reflects
	// "what came in", not "what we just decided".
	stageStart := time.Now()
	prevLabel := ""
	if pc := finding.PriorityClass(); pc != nil {
		prevLabel = string(*pc)
	}
	telemetry.ObserveStageIn(telemetry.StagePrioritization, tenantID.String(), prevLabel)
	defer func() {
		telemetry.ObserveStageLatency(telemetry.StagePrioritization, tenantID.String(), time.Since(stageStart))
	}()

	// Business-aligned criticality: raise the asset to the MAX of {own, its
	// business unit, the services it powers}. Single-finding path → one direct
	// lookup (the batch path preloads a map instead). critReason is appended to
	// the classification reason below so a business-driven bump is auditable.
	var effCrit asset.Criticality
	var critReason string
	if assetEntity != nil {
		effCrit, critReason = effectiveCriticality(assetEntity.Criticality(),
			s.businessContextFor(ctx, tenantID, assetEntity.ID()))
	}

	// Build priority context (with attack-path reachability + threat-model
	// signal, if wired). Both oracle lookups are tenant-scoped and cached.
	reachable := s.reachableSet(ctx, tenantID)
	pctx := s.buildPriorityContext(finding, assetEntity, effCrit, reachable, s.threatenedSet(ctx, tenantID))

	// Compensating controls on the finding's asset suppress P1 / force P2.
	s.applyControlProtection(ctx, tenantID, finding.AssetID(), &pctx)

	// Part 2: persist the derived attacker-reachability onto the finding so the
	// is_reachable column stops lying (always-false). Fail-safe inside.
	persistReachability(finding, pctx, reachable, assetEntity)

	// Evaluate tenant override rules first
	rules, err := s.ruleRepo.ListActiveByTenant(ctx, tenantID)
	if err != nil {
		s.logger.Warn("failed to load override rules, using defaults", "error", err)
		rules = nil
	}

	var classification vulnerability.PriorityClassification
	matched := false

	for _, rule := range rules {
		if rule.Matches(pctx) {
			classification = vulnerability.PriorityClassification{
				Class:  rule.PriorityClass(),
				Reason: fmt.Sprintf("Rule: %s", rule.Name()),
				Source: "rule",
			}
			ruleID := rule.ID()
			classification.RuleID = &ruleID
			matched = true
			break
		}
	}

	if !matched {
		classification = vulnerability.ClassifyPriority(pctx)
	}

	// Explainability: record that a business unit / service raised the asset's
	// effective criticality, so the classification reason is auditable.
	classification.Reason = appendCriticalityReason(classification.Reason, critReason)

	// Apply classification
	previousClass := finding.PriorityClass()
	finding.SetPriorityClassification(classification.Class, classification.Reason)

	// Log audit entry
	entry := PriorityAuditEntry{
		TenantID:      tenantID,
		FindingID:     finding.ID(),
		PreviousClass: previousClass,
		NewClass:      classification.Class,
		Reason:        classification.Reason,
		Source:        classification.Source,
		RuleID:        classification.RuleID,
	}
	if err := s.auditRepo.LogChange(ctx, entry); err != nil {
		s.logger.Warn("failed to log priority audit", "finding_id", finding.ID(), "error", err)
	}

	// O1: mark exit from Prioritization. Transition vs no-transition
	// maps to advanced vs deferred — re-confirming the same class is
	// still "work done" but doesn't feed the downstream stages.
	outcome := telemetry.OutcomeAdvanced
	if previousClass != nil && *previousClass == classification.Class {
		outcome = telemetry.OutcomeDeferred
	}
	telemetry.ObserveStageOut(telemetry.StagePrioritization, tenantID.String(), outcome)

	// F3 / emit priority_changed event on actual transition.
	// First classification (previousClass == nil) also emits so
	// downstream services can react to "first P0 detected".
	s.publishIfChanged(ctx, tenantID, finding.ID(), previousClass, classification)

	return nil
}

// publishIfChanged fires a PriorityChangeEvent when the class actually
// transitioned (or on first classification). Safe when the publisher is
// nil. Errors are logged, not propagated — a publish failure must not
// roll back a successful classification.
// auditClassChange writes a priority_class_audit_log entry when the class
// actually moved. Independent of the change publisher and the flood guard: the
// audit trail must record the classification even when notification fan-out is
// suppressed. No-op when no audit repo is wired.
func (s *PriorityClassificationService) auditClassChange(
	ctx context.Context,
	tenantID shared.ID,
	f *vulnerability.Finding,
	previousClass *vulnerability.PriorityClass,
	c vulnerability.PriorityClassification,
) {
	if s.auditRepo == nil {
		return
	}
	if previousClass != nil && *previousClass == c.Class {
		return // no transition — don't flood on a re-confirming sweep
	}
	entry := PriorityAuditEntry{
		TenantID:      tenantID,
		FindingID:     f.ID(),
		PreviousClass: previousClass,
		NewClass:      c.Class,
		Reason:        c.Reason,
		Source:        c.Source,
		RuleID:        c.RuleID,
	}
	if err := s.auditRepo.LogChange(ctx, entry); err != nil {
		s.logger.Warn("failed to log priority audit (batch)", "finding_id", f.ID(), "error", err)
	}
}

func (s *PriorityClassificationService) publishIfChanged(
	ctx context.Context,
	tenantID, findingID shared.ID,
	previousClass *vulnerability.PriorityClass,
	c vulnerability.PriorityClassification,
) {
	if s.changePublisher == nil {
		return
	}
	if previousClass != nil && *previousClass == c.Class {
		return // no transition
	}

	// anti-flap — when the tenant has burned its rolling budget at
	// the protected class we RECORD the classification (already done
	// above) but SKIP the fan-out event, so Jira/outbox/notifications
	// don't drown in a scanner-induced flood. Classes below the
	// protected one are never throttled.
	if s.priorityFloodGuard != nil {
		shouldFanOut, err := s.priorityFloodGuard.ShouldFanOut(ctx, tenantID, c.Class)
		if err != nil {
			if errors.Is(err, ErrPriorityFloodSuppressed) {
				s.logger.Warn("priority_changed fan-out suppressed by flood guard",
					"tenant_id", tenantID.String(),
					"finding_id", findingID.String(),
					"class", string(c.Class),
					"budget_usage", s.priorityFloodGuard.CurrentUsage(tenantID),
				)
				return
			}
			// Any other error (ctx cancelled) → don't publish, but let
			// caller see via log. Classification is already recorded.
			s.logger.Warn("priority flood guard error; skipping publish",
				"finding_id", findingID, "error", err)
			return
		}
		if !shouldFanOut {
			return
		}
	}

	ev := PriorityChangeEvent{
		TenantID:      tenantID,
		FindingID:     findingID,
		PreviousClass: previousClass,
		NewClass:      c.Class,
		Reason:        c.Reason,
		Source:        c.Source,
		RuleID:        c.RuleID,
		At:            time.Now().UTC(),
	}
	if err := s.changePublisher.Publish(ctx, ev); err != nil {
		s.logger.Warn("publish priority_changed failed", "finding_id", findingID, "error", err)
		// Refund the slot so a transient publish failure doesn't
		// permanently burn budget. On retry the caller should re-run
		// classification → ShouldFanOut → Publish.
		if s.priorityFloodGuard != nil && c.Class == vulnerability.PriorityP0 {
			s.priorityFloodGuard.Refund(tenantID)
		}
	}
}

// EnrichAndClassifyBatch enriches findings with EPSS/KEV and classifies priority.
// Used after ingest to process a batch of new/updated findings.
func (s *PriorityClassificationService) EnrichAndClassifyBatch(
	ctx context.Context,
	tenantID shared.ID,
	findings []*vulnerability.Finding,
	assets map[shared.ID]*asset.Asset,
) error {
	if len(findings) == 0 {
		return nil
	}

	// Shared, batch, read-only enrichment (EPSS/KEV + compensating controls +
	// business context + attack-path reachability + open-threat-path) → one
	// PriorityContext per classifiable finding, no per-finding N+1.
	contexts := s.enrichAndContextualize(ctx, tenantID, findings, assets)

	// Load override rules once.
	rules, err := s.ruleRepo.ListActiveByTenant(ctx, tenantID)
	if err != nil {
		s.logger.Warn("failed to load override rules", "error", err)
	}

	for _, fc := range contexts {
		f := fc.finding
		classification := classifyContext(rules, fc.pctx)
		// Explainability: record a BU / service criticality bump on the reason.
		classification.Reason = appendCriticalityReason(classification.Reason, fc.critReason)

		previousClass := f.PriorityClass()
		f.SetPriorityClassification(classification.Class, classification.Reason)
		// Record the priority change in the audit trail. The batch path is the
		// MAIN classification path (ingest + the 12h reclassify sweep), yet it
		// logged nothing — priority_class_audit_log was empty despite classified
		// findings, so "why/when did this become P0" had no answer. Gated on an
		// actual class change so a re-confirming sweep does not flood the log,
		// and kept independent of publishIfChanged because the flood guard may
		// suppress the fan-out event while the classification still stands.
		s.auditClassChange(ctx, tenantID, f, previousClass, classification)
		// batch classification also emits change events so the
		// reclassification sweep reuses the same path and downstream consumers
		// see every transition.
		s.publishIfChanged(ctx, tenantID, f.ID(), previousClass, classification)
	}

	s.logger.Info("batch enrichment and classification complete",
		"findings", len(findings),
	)

	return nil
}

// findingContext pairs a finding with its fully-built PriorityContext and the
// business-criticality explanation string. Produced by enrichAndContextualize and
// consumed by both EnrichAndClassifyBatch (classify + persist) and DryRunRule
// (read-only rule evaluation) so both share exactly one enrichment path.
type findingContext struct {
	finding    *vulnerability.Finding
	pctx       vulnerability.PriorityContext
	critReason string
}

// enrichAndContextualize is the shared, batch, read-only enrichment behind both
// the classify-batch path and the rule dry-run. It batch-loads EPSS/KEV,
// compensating controls, business context, attack-path reachability and the
// open-threat-path set — each ONE tenant-scoped (cached) query, never per-finding
// — mutates every finding IN MEMORY with its EPSS/KEV enrichment, and returns
// each classifiable finding paired with its PriorityContext. It does NOT run
// rules, classify, persist, or emit events; the caller owns that. Findings with
// no loaded asset, or with a manual priority override (which bypasses rule/auto
// classification entirely), are enriched but omitted from the returned set —
// exactly the set of findings a rule can affect.
func (s *PriorityClassificationService) enrichAndContextualize(
	ctx context.Context,
	tenantID shared.ID,
	findings []*vulnerability.Finding,
	assets map[shared.ID]*asset.Asset,
) []findingContext {
	// Collect CVE IDs for batch enrichment.
	cveIDs := make([]string, 0)
	for _, f := range findings {
		if f.CVEID() != "" {
			cveIDs = append(cveIDs, f.CVEID())
		}
	}

	// Batch lookup EPSS + KEV.
	var epssMap map[string]EPSSData
	var kevMap map[string]KEVData
	if len(cveIDs) > 0 {
		var err error
		epssMap, err = s.epssRepo.GetByCVEIDs(ctx, cveIDs)
		if err != nil {
			s.logger.Warn("failed to batch lookup EPSS", "error", err)
			epssMap = make(map[string]EPSSData)
		}
		kevMap, err = s.kevRepo.GetByCVEIDs(ctx, cveIDs)
		if err != nil {
			s.logger.Warn("failed to batch lookup KEV", "error", err)
			kevMap = make(map[string]KEVData)
		}
	}

	// Batch lookup compensating controls for all asset IDs.
	controlReduction := make(map[shared.ID]float64)
	if s.controlLookup != nil && len(assets) > 0 {
		assetIDList := make([]shared.ID, 0, len(assets))
		for aid := range assets {
			assetIDList = append(assetIDList, aid)
		}
		if m, err := s.controlLookup.GetEffectiveForAssets(ctx, tenantID, assetIDList); err == nil {
			controlReduction = m
		} else {
			s.logger.Warn("failed to batch lookup compensating controls", "error", err)
		}
	}

	// Preload per-asset business context (BU + business-service criticality) for
	// the whole batch — one tenant-scoped query, mirroring the compensating-
	// control preload above, so effective-criticality never costs a per-finding
	// query. A nil lookup or an error leaves the map empty (assets keep their own
	// criticality; never a downgrade).
	businessCtx := make(map[shared.ID]AssetBusinessContext)
	if s.businessContext != nil && len(assets) > 0 {
		assetIDList := make([]shared.ID, 0, len(assets))
		for aid := range assets {
			assetIDList = append(assetIDList, aid)
		}
		if m, err := s.businessContext.GetForAssets(ctx, tenantID, assetIDList); err == nil {
			businessCtx = m
		} else {
			s.logger.Warn("failed to batch lookup business context", "error", err)
		}
	}

	// Attack-path reachability set + open-threat-path set, each computed once for
	// the whole batch (one cached, tenant-scoped query apiece — no per-finding
	// N+1).
	reachable := s.reachableSet(ctx, tenantID)
	threatened := s.threatenedSet(ctx, tenantID)

	contexts := make([]findingContext, 0, len(findings))
	for _, f := range findings {
		// Enrich with EPSS.
		if epss, ok := epssMap[f.CVEID()]; ok {
			f.SetEPSSScore(epss.Score)
			f.SetEPSSPercentile(epss.Percentile)
		}
		// Enrich with KEV.
		if kev, ok := kevMap[f.CVEID()]; ok {
			f.SetIsInKEV(true)
			if kev.DueDate != nil {
				f.SetKEVDueDate(*kev.DueDate)
			}
		}

		a := assets[f.AssetID()]
		if a == nil {
			continue
		}
		// Manual overrides bypass rule/auto classification entirely — enrich but
		// hand back no context, so neither the batch classifier nor a dry-run
		// treats them as (re)classifiable.
		if f.PriorityClassOverride() {
			continue
		}

		// Business-aligned effective criticality from the preloaded batch map.
		effCrit, critReason := effectiveCriticality(a.Criticality(), businessCtx[f.AssetID()])

		pctx := s.buildPriorityContext(f, a, effCrit, reachable, threatened)
		// Same rule as applyControlProtection, fed from the batch map above so
		// the sweep stays one query for the whole batch instead of per finding.
		setControlProtection(&pctx, controlReduction[f.AssetID()])
		// Part 2: persist derived reachability so is_reachable reflects reality.
		persistReachability(f, pctx, reachable, a)

		contexts = append(contexts, findingContext{finding: f, pctx: pctx, critReason: critReason})
	}
	return contexts
}

// classifyContext applies the tenant's active override rules (first match wins,
// by evaluation order as loaded) and falls back to the default CTEM engine when
// none match. Shared by the batch classifier; RuleID is intentionally left unset
// to preserve the batch path's historical audit shape.
func classifyContext(rules []*vulnerability.PriorityOverrideRule, pctx vulnerability.PriorityContext) vulnerability.PriorityClassification {
	for _, rule := range rules {
		if rule.Matches(pctx) {
			return vulnerability.PriorityClassification{
				Class:  rule.PriorityClass(),
				Reason: fmt.Sprintf("Rule: %s", rule.Name()),
				Source: "rule",
			}
		}
	}
	return vulnerability.ClassifyPriority(pctx)
}

// buildPriorityContext constructs PriorityContext from finding + asset.
// effCrit is the asset's EFFECTIVE (business-aligned) criticality — the MAX of
// its own and any business-unit / business-service criticality; "" falls back to
// the asset's own criticality. reachable is the tenant's attack-path-reachable
// asset set (may be nil). threatened is the tenant's open-threat-path asset set
// (may be nil).
func (s *PriorityClassificationService) buildPriorityContext(
	f *vulnerability.Finding,
	a *asset.Asset,
	effCrit asset.Criticality,
	reachable map[string]bool,
	threatened map[string]bool,
) vulnerability.PriorityContext {
	ctx := vulnerability.PriorityContext{
		Severity:             f.Severity(),
		CVEID:                f.CVEID(),
		EPSSScore:            f.EPSSScore(),
		EPSSPercentile:       f.EPSSPercentile(),
		IsInKEV:              f.IsInKEV(),
		IsReachable:          f.IsReachable(),
		ReachableFromCount:   f.ReachableFromCount(),
		IsInternetAccessible: f.IsInternetAccessible(),
		IsNetworkAccessible:  f.IsNetworkAccessible(),
		// Business impact (from CTIS finding data) — raises findings the
		// exploitability gates would bury (close-the-loop).
		HighDataExposure: f.DataExposureRisk() == vulnerability.DataExposureRiskHigh ||
			f.DataExposureRisk() == vulnerability.DataExposureRiskCritical,
		HasComplianceImpact: len(f.ComplianceImpact()) > 0,
	}

	if a != nil {
		// Effective (business-aligned) criticality: the MAX of the asset's own
		// criticality and its business-unit / business-service criticality. It is
		// a floor — it only ever raises the asset above its own value — so every
		// downstream gate (critical+reachable→P1, implicit crown jewel, …) fires
		// on the business-aligned level. "" means the caller supplied no override,
		// so fall back to the asset's own criticality.
		crit := effCrit
		if crit == "" {
			crit = a.Criticality()
		}
		ctx.AssetCriticality = string(crit)
		ctx.AssetExposure = string(a.Exposure())
		// Crown jewel: check properties (DB column exposed via properties map)
		if cj, ok := a.Properties()["is_crown_jewel"].(bool); ok && cj {
			ctx.AssetIsCrownJewel = true
		}
		// High criticality assets treated as implicit crown jewels — evaluated on
		// the EFFECTIVE criticality so an asset promoted to critical by its BU /
		// business service is treated as a crown jewel too.
		if crit == asset.CriticalityCritical {
			ctx.AssetIsCrownJewel = true
		}

		// Derive reachability from the asset's exposure level. The finding's own
		// reachability flags are not currently populated by any scanner/ingest
		// path, so without this the "KEV + reachable -> P0" and "critical +
		// reachable -> P1" gates never fire. Asset exposure is the authoritative
		// reachability signal we already have. Finding-level flags (future
		// scanner data) still win via OR.
		switch a.Exposure() {
		case asset.ExposurePublic:
			// Publicly accessible from the internet -> internet-reachable.
			ctx.IsInternetAccessible = true
			if ctx.ReachableFromCount == 0 {
				ctx.ReachableFromCount = 1
			}
		case asset.ExposureRestricted, asset.ExposurePrivate:
			// Reachable on an internal/restricted network but not from the
			// public internet. Recorded but, by design, does NOT flip the
			// external-attacker "reachable" gate (see ClassifyPriority).
			ctx.IsNetworkAccessible = true
		case asset.ExposureIsolated, asset.ExposureUnknown:
			// Air-gapped/isolated or unknown -> leave conservative (not reachable).
		}

		// Attack-path reachability (close-the-loop): an asset sitting on a
		// validated path from a public entry point to a KEV/crown-jewel target is
		// reachable even when its own exposure is private/internal. This makes the
		// exposure-chain engine actually feed prioritization instead of being
		// display-only. Additive — it can only raise reachability, never lower it.
		if reachable[a.ID().String()] {
			ctx.IsInternetAccessible = true
			if ctx.ReachableFromCount == 0 {
				ctx.ReachableFromCount = 1
			}
		}

		// Threat-model signal (close-the-loop, Part 1): an asset the threat-model
		// engine placed on an OPEN, high-score modeled attack chain is treated as
		// reachable, feeding the same "reachable" gate. Kept as its own field
		// (not folded into IsInternetAccessible) so it raises priority without
		// polluting the persisted is_reachable/attack-surface signal. Additive —
		// only raises, never lowers.
		if threatened[a.ID().String()] {
			ctx.OnOpenThreatPath = true
		}
	}

	return ctx
}

// persistReachability writes the classifier's freshly-derived attacker-
// reachability back onto the finding so the is_reachable column (API field +
// filter) reflects reality instead of always-false. It persists the effective
// internet/attack-path reachability (exposure + attack-path oracle) — NOT the
// threat-model signal, which is a distinct input. Fail-safe: called only when
// the reachability oracle was available (reachable != nil); when it is
// unavailable we leave the finding's flag untouched rather than force a
// possibly-false-negative value. The actual DB write happens via the caller's
// FindingRepository.Update / ingest upsert, both of which include is_reachable.
func persistReachability(f *vulnerability.Finding, pctx vulnerability.PriorityContext, reachable map[string]bool, a *asset.Asset) {
	if reachable == nil || a == nil {
		return
	}
	f.SetReachability(pctx.IsInternetAccessible, pctx.ReachableFromCount)
}

// Default caps for a priority-rule dry run. Evaluation is bounded to the most
// recent open findings so a large tenant can't turn a preview into an unbounded
// scan; the sample returned to the UI is bounded separately.
const (
	DefaultDryRunCap        = 1000
	DefaultDryRunSampleSize = 25
)

// DryRunResult is the outcome of evaluating a DRAFT priority rule against the
// tenant's open findings with the REAL classification engine. It is purely
// informational — nothing is mutated or persisted.
type DryRunResult struct {
	Evaluated    int            // findings actually evaluated (asset-backed, non-override)
	Matched      int            // how many the draft rule matched
	Capped       bool           // true when more open findings exist than were evaluated
	Cap          int            // the evaluation cap applied
	Sample       []DryRunSample // a bounded preview of matched findings
	Distribution map[string]int // would-be priority-class histogram (P0..P3)
}

// DryRunSample previews a single matched finding in a dry-run result.
type DryRunSample struct {
	FindingID    string
	Title        string
	Severity     string
	CurrentClass string
	WouldBeClass string
}

// DryRunRule evaluates a DRAFT (possibly unsaved) priority override rule against
// the tenant's OPEN findings (new/confirmed/in_progress/fix_applied) using the
// SAME enrichment + engine the classifier uses, and returns exact match counts,
// a would-be class distribution, and a bounded sample of matched findings.
//
// It is strictly READ-ONLY: findings are enriched in memory via
// enrichAndContextualize (never persisted) and no rule is stored. Evaluation is
// capped at the `cap` most-recent open findings (a non-positive cap falls back to
// DefaultDryRunCap); when the tenant has more open findings than the cap, the
// result's Capped flag is set. sampleSize (non-positive → DefaultDryRunSampleSize)
// bounds the returned sample.
func (s *PriorityClassificationService) DryRunRule(
	ctx context.Context,
	tenantID shared.ID,
	draft *vulnerability.PriorityOverrideRule,
	cap int,
	sampleSize int,
) (DryRunResult, error) {
	if cap <= 0 {
		cap = DefaultDryRunCap
	}
	if sampleSize <= 0 {
		sampleSize = DefaultDryRunSampleSize
	}

	// Load the tenant's OPEN findings, most-recent first, capped.
	filter := vulnerability.NewFindingFilter().WithTenantID(tenantID)
	filter.Statuses = vulnerability.ActiveFindingStatuses()
	sort := pagination.NewSortOption(vulnerability.FindingAllowedSortFields()).Parse("-created_at")
	opts := vulnerability.NewFindingListOptions().WithSort(sort)
	page := pagination.Pagination{Page: 1, PerPage: cap}

	res, err := s.findingRepo.List(ctx, filter, opts, page)
	if err != nil {
		return DryRunResult{}, fmt.Errorf("list open findings: %w", err)
	}
	findings := res.Data

	// Load the distinct assets for those findings (deduped; one GetByID per
	// asset, mirroring the reclassify sweep). A missing asset is skipped — the
	// enrichment step then drops the finding.
	assets := make(map[shared.ID]*asset.Asset, len(findings))
	for _, f := range findings {
		aid := f.AssetID()
		if aid.IsZero() {
			continue
		}
		if _, ok := assets[aid]; ok {
			continue
		}
		a, aerr := s.assetRepo.GetByID(ctx, tenantID, aid)
		if aerr != nil {
			if errors.Is(aerr, shared.ErrNotFound) {
				continue
			}
			return DryRunResult{}, fmt.Errorf("load asset %s: %w", aid.String(), aerr)
		}
		assets[aid] = a
	}

	// Reuse the SAME batch enrichment the classifier uses — no reimplementation.
	contexts := s.enrichAndContextualize(ctx, tenantID, findings, assets)

	result := DryRunResult{
		Cap:          cap,
		Capped:       res.Total > int64(len(findings)),
		Distribution: map[string]int{"P0": 0, "P1": 0, "P2": 0, "P3": 0},
	}
	draftClass := string(draft.PriorityClass())

	for _, fc := range contexts {
		f := fc.finding
		result.Evaluated++

		current := s.currentClass(f, fc.pctx)
		wouldBe := current
		matched := draft.Matches(fc.pctx)
		if matched {
			result.Matched++
			wouldBe = draftClass
		}
		result.Distribution[wouldBe]++

		if matched && len(result.Sample) < sampleSize {
			result.Sample = append(result.Sample, DryRunSample{
				FindingID:    f.ID().String(),
				Title:        f.Title(),
				Severity:     string(f.Severity()),
				CurrentClass: current,
				WouldBeClass: draftClass,
			})
		}
	}

	return result, nil
}

// currentClass reports the finding's current priority class: its persisted class
// when already classified, otherwise the default engine's verdict for its context
// (so a never-classified open finding still contributes a sensible bucket to the
// dry-run distribution).
func (s *PriorityClassificationService) currentClass(f *vulnerability.Finding, pctx vulnerability.PriorityContext) string {
	if pc := f.PriorityClass(); pc != nil {
		return string(*pc)
	}
	return string(vulnerability.ClassifyPriority(pctx).Class)
}
