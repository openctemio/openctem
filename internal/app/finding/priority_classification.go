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
	DueDate   *time.Time
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

	// Build priority context
	pctx := s.buildPriorityContext(finding, assetEntity)

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

	// Collect CVE IDs for batch enrichment
	cveIDs := make([]string, 0)
	for _, f := range findings {
		if f.CVEID() != "" {
			cveIDs = append(cveIDs, f.CVEID())
		}
	}

	// Batch lookup EPSS + KEV
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

	// Load override rules once
	rules, err := s.ruleRepo.ListActiveByTenant(ctx, tenantID)
	if err != nil {
		s.logger.Warn("failed to load override rules", "error", err)
	}

	// Batch lookup compensating controls for all asset IDs
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

	// Enrich + classify each finding
	for _, f := range findings {
		// Enrich with EPSS
		if epss, ok := epssMap[f.CVEID()]; ok {
			f.SetEPSSScore(epss.Score)
			f.SetEPSSPercentile(epss.Percentile)
		}

		// Enrich with KEV
		if kev, ok := kevMap[f.CVEID()]; ok {
			f.SetIsInKEV(true)
			if kev.DueDate != nil {
				f.SetKEVDueDate(*kev.DueDate)
			}
		}

		// Classify
		a := assets[f.AssetID()]
		if a == nil {
			continue
		}

		if f.PriorityClassOverride() {
			continue
		}

		pctx := s.buildPriorityContext(f, a)
		if reduction, ok := controlReduction[f.AssetID()]; ok && reduction > 0 {
			pctx.IsProtected = true
			pctx.ControlReductionFactor = reduction
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
				matched = true
				break
			}
		}
		if !matched {
			classification = vulnerability.ClassifyPriority(pctx)
		}

		previousClass := f.PriorityClass()
		f.SetPriorityClassification(classification.Class, classification.Reason)
		// batch classification also emits change events so the
		// reclassification sweep (a future task) reuses the same path
		// and downstream consumers see every transition.
		s.publishIfChanged(ctx, tenantID, f.ID(), previousClass, classification)
	}

	s.logger.Info("batch enrichment and classification complete",
		"findings", len(findings),
		"cves_enriched", len(cveIDs),
	)

	return nil
}

// buildPriorityContext constructs PriorityContext from finding + asset.
func (s *PriorityClassificationService) buildPriorityContext(
	f *vulnerability.Finding,
	a *asset.Asset,
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
	}

	if a != nil {
		ctx.AssetCriticality = string(a.Criticality())
		ctx.AssetExposure = string(a.Exposure())
		// Crown jewel: check properties (DB column exposed via properties map)
		if cj, ok := a.Properties()["is_crown_jewel"].(bool); ok && cj {
			ctx.AssetIsCrownJewel = true
		}
		// High criticality assets treated as implicit crown jewels
		if a.Criticality() == asset.CriticalityCritical {
			ctx.AssetIsCrownJewel = true
		}
	}

	return ctx
}
