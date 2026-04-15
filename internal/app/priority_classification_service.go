package app

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/logger"
)

// PriorityClassificationService orchestrates finding priority classification.
// It enriches findings with EPSS/KEV data, evaluates override rules,
// and applies the default CTEM classification logic.
type PriorityClassificationService struct {
	findingRepo  vulnerability.FindingRepository
	assetRepo    asset.Repository
	epssRepo     EPSSRepository
	kevRepo      KEVRepository
	ruleRepo     PriorityRuleRepository
	auditRepo    PriorityAuditRepository
	logger       *logger.Logger
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

	return nil
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

		f.SetPriorityClassification(classification.Class, classification.Reason)
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
