package ingest

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/sdk-go/pkg/shared/fingerprint"
	"github.com/openctemio/sdk-go/pkg/shared/severity"

	"github.com/openctemio/api/pkg/domain/agent"
	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/branch"
	"github.com/openctemio/api/pkg/domain/component"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/sdk-go/pkg/ctis"
)

// FindingCreatedCallback is called when findings are created during ingestion.
type FindingCreatedCallback func(ctx context.Context, tenantID shared.ID, findings []*vulnerability.Finding)

// FindingProcessor handles batch finding processing.
type FindingProcessor struct {
	repo         vulnerability.FindingRepository
	dataFlowRepo vulnerability.DataFlowRepository
	branchRepo   branch.Repository
	assetRepo    asset.Repository
	compRepo     component.Repository
	logger       *logger.Logger

	// findingCreatedCallback is called after findings are successfully created
	findingCreatedCallback FindingCreatedCallback
}

// NewFindingProcessor creates a new finding processor.
func NewFindingProcessor(repo vulnerability.FindingRepository, branchRepo branch.Repository, assetRepo asset.Repository, log *logger.Logger) *FindingProcessor {
	return &FindingProcessor{
		repo:       repo,
		branchRepo: branchRepo,
		assetRepo:  assetRepo,
		logger:     log.With("processor", "findings"),
	}
}

// SetComponentRepository sets the component repository for linking findings to components.
func (p *FindingProcessor) SetComponentRepository(repo component.Repository) {
	p.compRepo = repo
}

// SetDataFlowRepository sets the data flow repository for persisting data flow traces.
func (p *FindingProcessor) SetDataFlowRepository(repo vulnerability.DataFlowRepository) {
	p.dataFlowRepo = repo
}

// SetFindingCreatedCallback sets the callback for when findings are created.
func (p *FindingProcessor) SetFindingCreatedCallback(callback FindingCreatedCallback) {
	p.findingCreatedCallback = callback
}

// ProcessBatch processes all findings using batch operations.
//
//nolint:gocognit,nestif,cyclop // Batch ingestion inherently requires complex control flow
func (p *FindingProcessor) ProcessBatch(
	ctx context.Context,
	agt *agent.Agent,
	tenantID shared.ID,
	report *ctis.Report,
	assetMap map[string]shared.ID,
	tenantRules branch.BranchTypeRules,
	output *Output,
) error {
	if len(report.Findings) == 0 {
		return nil
	}

	// Step 0: Lookup/create branch record if branch info is available
	// This maps assetID -> branchID for setting findings.branch_id FK
	branchMap := p.resolveBranches(ctx, tenantID, report, assetMap, tenantRules)

	// Step 1: Pre-process findings to collect fingerprints
	type findingMeta struct {
		index       int
		finding     ctis.Finding
		assetID     shared.ID
		branchID    *shared.ID // FK to asset_branches
		fingerprint string
	}

	// Helper to create FailedFinding from findingMeta
	createFailedFinding := func(fm findingMeta, errMsg string) FailedFinding {
		ff := FailedFinding{
			Index:       fm.index,
			Fingerprint: fm.fingerprint,
			RuleID:      fm.finding.RuleID,
			Error:       errMsg,
		}
		if fm.finding.Location != nil {
			ff.FilePath = fm.finding.Location.Path
			ff.Line = fm.finding.Location.StartLine
		}
		return ff
	}

	validFindings := make([]findingMeta, 0, len(report.Findings))
	fingerprints := make([]string, 0, len(report.Findings))

	// Get default asset if available (single asset report)
	var defaultAssetID shared.ID
	if len(assetMap) == 1 {
		for _, id := range assetMap {
			defaultAssetID = id
			break
		}
	}

	// Debug: Log assetMap keys for diagnosis
	if len(assetMap) > 0 {
		assetMapKeys := make([]string, 0, len(assetMap))
		for k := range assetMap {
			assetMapKeys = append(assetMapKeys, k)
		}
		p.logger.Debug("asset map keys", "keys", assetMapKeys, "count", len(assetMap))
	} else {
		p.logger.Warn("asset map is empty - all findings will be skipped")
	}

	for i, ctisFinding := range report.Findings {
		// Determine target asset
		var targetAssetID shared.ID
		if ctisFinding.AssetRef != "" {
			// Try to find by asset reference
			if id, ok := assetMap[ctisFinding.AssetRef]; ok {
				targetAssetID = id
			} else {
				p.logger.Debug("finding AssetRef not found in assetMap",
					"finding_index", i,
					"asset_ref", ctisFinding.AssetRef,
				)
			}
		}

		if targetAssetID.IsZero() && !defaultAssetID.IsZero() {
			targetAssetID = defaultAssetID
		}

		if targetAssetID.IsZero() {
			p.logger.Warn("finding skipped: no target asset",
				"finding_index", i,
				"asset_ref", ctisFinding.AssetRef,
				"default_asset_available", !defaultAssetID.IsZero(),
				"asset_map_size", len(assetMap),
			)
			addError(output, fmt.Sprintf("finding %d: no target asset", i))
			output.FindingsSkipped++
			continue
		}

		// Generate fingerprint
		fp := generateFindingFingerprint(targetAssetID, &ctisFinding, report.Tool)

		// Get branch ID for this asset (if available)
		var branchID *shared.ID
		if bid, ok := branchMap[targetAssetID]; ok {
			branchID = &bid
		}

		validFindings = append(validFindings, findingMeta{
			index:       i,
			finding:     ctisFinding,
			assetID:     targetAssetID,
			branchID:    branchID,
			fingerprint: fp,
		})
		fingerprints = append(fingerprints, fp)
	}

	if len(validFindings) == 0 {
		return nil
	}

	// Step 2: Batch check existing fingerprints
	existsMap, err := p.repo.CheckFingerprintsExist(ctx, tenantID, fingerprints)
	if err != nil {
		return fmt.Errorf("failed to check fingerprints: %w", err)
	}

	p.logger.Debug("fingerprint check complete",
		"total", len(fingerprints),
		"existing", countTrue(existsMap),
	)

	// Step 3: Separate new vs existing findings
	newFindings := make([]*vulnerability.Finding, 0)
	newFindingsMeta := make([]findingMeta, 0) // Track metadata for error reporting
	existingFingerprints := make([]string, 0)
	existingSnippets := make(map[string]string) // Track snippets for existing findings

	for _, fm := range validFindings {
		if existsMap[fm.fingerprint] {
			existingFingerprints = append(existingFingerprints, fm.fingerprint)
			// Track snippet for potential update (if current DB value is invalid)
			if fm.finding.Location != nil && fm.finding.Location.Snippet != "" && fm.finding.Location.Snippet != "requires login" {
				existingSnippets[fm.fingerprint] = fm.finding.Location.Snippet
			}
		} else {
			f, err := p.buildFinding(ctx, tenantID, fm.assetID, fm.branchID, agt.ID, report, &fm.finding, fm.fingerprint)
			if err != nil {
				addError(output, fmt.Sprintf("finding %d: %v", fm.index, err))
				output.FindingsSkipped++
				// Track failed finding for audit
				output.FailedFindings = append(output.FailedFindings, createFailedFinding(fm, err.Error()))
				continue
			}
			newFindings = append(newFindings, f)
			newFindingsMeta = append(newFindingsMeta, fm)
		}
	}

	// Step 3b: Batch auto-reopen previously auto-resolved findings
	// PERFORMANCE: Single query instead of N queries per existing finding
	if len(existingFingerprints) > 0 {
		reopenedMap, err := p.repo.AutoReopenByFingerprintsBatch(ctx, tenantID, existingFingerprints)
		if err != nil {
			p.logger.Warn("failed to batch auto-reopen findings", "error", err)
		} else if len(reopenedMap) > 0 {
			output.FindingsAutoReopened = len(reopenedMap)
			p.logger.Info("batch auto-reopened findings",
				"count", len(reopenedMap),
			)
			// TODO: Create activity records for auto-reopened findings
		}
	}

	// Step 4: Batch create new findings with partial success support
	if len(newFindings) > 0 {
		result, err := p.repo.CreateBatchWithResult(ctx, newFindings)
		if err != nil {
			// Fatal error - could not process any findings
			p.logger.Error("failed to batch create findings", "error", err, "count", len(newFindings))
			addError(output, fmt.Sprintf("batch create failed: %v", err))
			// Track all findings as failed for audit
			for i, fm := range newFindingsMeta {
				output.FailedFindings = append(output.FailedFindings, createFailedFinding(fm, fmt.Sprintf("batch failed at index %d: %v", i, err)))
			}
		} else {
			output.FindingsCreated = result.Created
			output.FindingsSkipped += result.Skipped

			// Log individual errors for debugging
			if result.HasErrors() {
				p.logger.Warn("some findings failed to create",
					"created", result.Created,
					"skipped", result.Skipped,
					"error_count", len(result.Errors),
				)
				for idx, errMsg := range result.Errors {
					// Log each error with finding details for debugging
					if idx < len(newFindingsMeta) {
						fm := newFindingsMeta[idx]
						p.logger.Error("finding insert failed",
							"index", idx,
							"fingerprint", fm.fingerprint,
							"rule_id", fm.finding.RuleID,
							"asset_id", fm.assetID.String(),
							"error", errMsg,
						)
					} else {
						p.logger.Error("finding insert failed", "index", idx, "error", errMsg)
					}
					addError(output, fmt.Sprintf("finding %d: %s", idx, errMsg))
					// Track failed finding with full context for audit
					if idx < len(newFindingsMeta) {
						fm := newFindingsMeta[idx]
						output.FailedFindings = append(output.FailedFindings, createFailedFinding(fm, errMsg))
					}
				}
			}

			// Step 4b: Persist data flows for newly created findings
			if p.dataFlowRepo != nil && result.Created > 0 {
				p.persistDataFlows(ctx, newFindings)
			}

			// Step 4c: Trigger workflow events for newly created findings
			if p.findingCreatedCallback != nil && result.Created > 0 {
				// Only include successfully created findings (exclude failed ones)
				createdFindings := make([]*vulnerability.Finding, 0, result.Created)
				for i, f := range newFindings {
					// Check if this finding was created (not in error list)
					if result.Errors == nil || result.Errors[i] == "" {
						createdFindings = append(createdFindings, f)
					}
				}
				if len(createdFindings) > 0 {
					p.findingCreatedCallback(ctx, tenantID, createdFindings)
				}
			}
		}
	}

	// Step 5: Batch update existing findings
	if len(existingFingerprints) > 0 {
		scanID := report.Metadata.ID
		updated, err := p.repo.UpdateScanIDBatchByFingerprints(ctx, tenantID, existingFingerprints, scanID)
		if err != nil {
			p.logger.Warn("failed to update existing findings", "error", err)
		} else {
			output.FindingsUpdated = int(updated)
		}

		// Step 5b: Update snippets for existing findings that have invalid snippets in DB
		// This fixes the "requires login" issue when Semgrep pro features are unavailable
		if len(existingSnippets) > 0 {
			snippetUpdated, err := p.repo.UpdateSnippetBatchByFingerprints(ctx, tenantID, existingSnippets)
			if err != nil {
				p.logger.Warn("failed to update snippets for existing findings", "error", err)
			} else if snippetUpdated > 0 {
				p.logger.Info("updated snippets for existing findings",
					"count", snippetUpdated,
				)
			}
		}
	}

	return nil
}

// CheckFingerprints checks which fingerprints already exist in the database.
func (p *FindingProcessor) CheckFingerprints(
	ctx context.Context,
	tenantID shared.ID,
	fingerprints []string,
) (existing, missing []string, err error) {
	if len(fingerprints) == 0 {
		return []string{}, []string{}, nil
	}

	// Limit the number of fingerprints to check at once
	const maxFingerprints = 100
	if len(fingerprints) > maxFingerprints {
		fingerprints = fingerprints[:maxFingerprints]
	}

	existsMap, err := p.repo.CheckFingerprintsExist(ctx, tenantID, fingerprints)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to check fingerprints: %w", err)
	}

	existing = make([]string, 0)
	missing = make([]string, 0)

	for _, fp := range fingerprints {
		if existsMap[fp] {
			existing = append(existing, fp)
		} else {
			missing = append(missing, fp)
		}
	}

	return existing, missing, nil
}

// generateFindingFingerprint generates a fingerprint for a CTIS finding.
// The fingerprint includes assetID to ensure findings are unique per-asset.
// This prevents the same vulnerability on different assets from being deduplicated incorrectly.
func generateFindingFingerprint(assetID shared.ID, ctisFinding *ctis.Finding, tool *ctis.Tool) string {
	// Generate base fingerprint
	var baseFingerprint string

	if ctisFinding.Fingerprint != "" && isValidFingerprint(ctisFinding.Fingerprint) {
		// Use provided fingerprint as base (only if valid hash-like string)
		baseFingerprint = ctisFinding.Fingerprint
	} else {
		// Generate using SDK fingerprint package
		input := fingerprint.Input{
			RuleID:  ctisFinding.RuleID,
			Message: ctisFinding.Title,
		}

		// Set location if available
		if ctisFinding.Location != nil {
			input.FilePath = ctisFinding.Location.Path
			input.StartLine = ctisFinding.Location.StartLine
			input.EndLine = ctisFinding.Location.EndLine
		}

		// Add CVE for SCA findings
		if ctisFinding.Vulnerability != nil && ctisFinding.Vulnerability.CVEID != "" {
			input.VulnerabilityID = ctisFinding.Vulnerability.CVEID
		}

		baseFingerprint = fingerprint.Generate(input)
	}

	// Create composite fingerprint including assetID
	// This ensures the same vulnerability on different assets produces different fingerprints
	return createCompositeFingerprint(assetID.String(), baseFingerprint)
}

// buildFinding creates a Finding domain entity from a CTIS finding.
func (p *FindingProcessor) buildFinding(
	ctx context.Context,
	tenantID shared.ID,
	assetID shared.ID,
	branchID *shared.ID,
	agentID shared.ID,
	report *ctis.Report,
	ctisFinding *ctis.Finding,
	fp string,
) (*vulnerability.Finding, error) {
	// Map severity
	sev := vulnerability.SeverityMedium
	if ctisFinding.Severity != "" {
		parsed := severity.FromString(string(ctisFinding.Severity))
		sev = mapSDKSeverity(parsed)
	}

	// Determine source from tool
	source := vulnerability.FindingSourceSAST
	toolName := UnknownValue
	toolVersion := ""
	if report.Tool != nil {
		source = detectFindingSource(report.Tool.Name, report.Tool.Capabilities)
		toolName = report.Tool.Name
		toolVersion = report.Tool.Version
	}

	// Determine message: prefer Message field, fallback to Description, then Title
	// Message is the primary human-readable text displayed for the finding
	message := ctisFinding.Title
	if ctisFinding.Message != "" {
		message = ctisFinding.Message
	} else if ctisFinding.Description != "" {
		message = ctisFinding.Description
	}

	// Create finding with proper message
	f, err := vulnerability.NewFinding(
		tenantID,
		assetID,
		source,
		toolName,
		sev,
		message,
	)
	if err != nil {
		return nil, err
	}

	// Set core identifiers
	f.SetFingerprint(fp)
	f.SetAgentID(agentID)
	f.SetScanID(report.Metadata.ID)
	if branchID != nil {
		f.SetBranchID(*branchID)
	}
	if toolVersion != "" {
		f.SetToolVersion(toolVersion)
	}

	// Set basic fields
	p.setFindingBasicFields(f, ctisFinding)

	// Set location and branch info
	p.setFindingLocationFields(f, ctisFinding, report)

	// Set classification (CVE/CWE/OWASP/CVSS)
	p.setFindingClassification(f, ctisFinding)

	// Set tags
	if len(ctisFinding.Tags) > 0 {
		f.SetTags(ctisFinding.Tags)
	}

	// Set SARIF 2.1.0 fields
	p.setFindingSARIFFields(f, ctisFinding)

	// Set CTEM fields (exposure, remediation, business impact)
	p.setFindingCTEMFields(f, ctisFinding)

	// Set finding type and specialized fields
	p.setFindingTypeAndSpecializedFields(f, ctisFinding)

	// Link to component via PURL (for SCA findings)
	p.linkFindingToComponent(ctx, f, ctisFinding)

	return f, nil
}

// setFindingBasicFields sets basic fields like rule ID, name, description, title.
func (p *FindingProcessor) setFindingBasicFields(f *vulnerability.Finding, ctisFinding *ctis.Finding) {
	if ctisFinding.RuleID != "" {
		f.SetRuleID(ctisFinding.RuleID)
	}
	if ctisFinding.RuleName != "" {
		f.SetRuleName(ctisFinding.RuleName)
	}
	if ctisFinding.Description != "" {
		f.SetDescription(ctisFinding.Description)
	}
	if ctisFinding.Remediation != nil {
		// Set legacy fields for backward compatibility
		if ctisFinding.Remediation.Recommendation != "" {
			f.SetRecommendation(ctisFinding.Remediation.Recommendation)
		}
		// Set auto-fix code (from Semgrep native JSON)
		if ctisFinding.Remediation.FixCode != "" {
			f.SetFixCode(ctisFinding.Remediation.FixCode)
		}
		// Set fix regex pattern (from Semgrep native JSON)
		var fixRegex *vulnerability.FixRegex
		if ctisFinding.Remediation.FixRegex != nil {
			fixRegex = &vulnerability.FixRegex{
				Regex:       ctisFinding.Remediation.FixRegex.Regex,
				Replacement: ctisFinding.Remediation.FixRegex.Replacement,
				Count:       ctisFinding.Remediation.FixRegex.Count,
			}
			f.SetFixRegex(fixRegex)
		}

		// Create consolidated remediation JSONB object
		remediation := &vulnerability.FindingRemediation{
			Recommendation: ctisFinding.Remediation.Recommendation,
			FixCode:        ctisFinding.Remediation.FixCode,
			FixRegex:       fixRegex,
			Steps:          ctisFinding.Remediation.Steps,
			References:     ctisFinding.Remediation.References,
			Effort:         ctisFinding.Remediation.Effort,
			FixAvailable:   ctisFinding.Remediation.FixCode != "" || fixRegex != nil,
			AutoFixable:    ctisFinding.Remediation.FixCode != "" || fixRegex != nil,
		}
		if !remediation.IsEmpty() {
			f.SetRemediation(remediation)
		}
	}

	// Set title: prefer RuleName (short identifier) over full Title
	if ctisFinding.RuleName != "" {
		f.SetTitle(ctisFinding.RuleName)
	} else if ctisFinding.Title != "" {
		f.SetTitle(ctisFinding.Title)
	}
}

// setFindingLocationFields sets location and branch info.
func (p *FindingProcessor) setFindingLocationFields(f *vulnerability.Finding, ctisFinding *ctis.Finding, report *ctis.Report) {
	// Set location
	if ctisFinding.Location != nil && ctisFinding.Location.Path != "" {
		f.SetLocation(
			ctisFinding.Location.Path,
			ctisFinding.Location.StartLine,
			ctisFinding.Location.EndLine,
			ctisFinding.Location.StartColumn,
			ctisFinding.Location.EndColumn,
		)
		if ctisFinding.Location.Snippet != "" {
			f.SetSnippet(ctisFinding.Location.Snippet)
		}
		// Set context snippet for better code understanding
		if ctisFinding.Location.ContextSnippet != "" {
			f.SetContextSnippet(ctisFinding.Location.ContextSnippet)
			f.SetContextStartLine(ctisFinding.Location.ContextStartLine)
		}
	}

	// Set branch info from report metadata or finding location
	if report.Metadata.Branch != nil {
		f.SetBranchInfo(report.Metadata.Branch.Name, report.Metadata.Branch.CommitSHA)
	} else if ctisFinding.Location != nil && ctisFinding.Location.Branch != "" {
		f.SetFirstDetectedBranch(ctisFinding.Location.Branch)
		f.SetLastSeenBranch(ctisFinding.Location.Branch)
		if ctisFinding.Location.CommitSHA != "" {
			f.SetFirstDetectedCommit(ctisFinding.Location.CommitSHA)
			f.SetLastSeenCommit(ctisFinding.Location.CommitSHA)
		}
	}
}

// setFindingClassification sets CVE/CWE/OWASP/CVSS classification.
func (p *FindingProcessor) setFindingClassification(f *vulnerability.Finding, ctisFinding *ctis.Finding) {
	if ctisFinding.Vulnerability == nil {
		return
	}

	cveID := ctisFinding.Vulnerability.CVEID
	var cvssScore *float64
	if ctisFinding.Vulnerability.CVSSScore > 0 {
		score := ctisFinding.Vulnerability.CVSSScore
		cvssScore = &score
	}
	cvssVector := ctisFinding.Vulnerability.CVSSVector

	// Collect CWE IDs
	var cweIDs []string
	if len(ctisFinding.Vulnerability.CWEIDs) > 0 {
		cweIDs = ctisFinding.Vulnerability.CWEIDs
	} else if ctisFinding.Vulnerability.CWEID != "" {
		cweIDs = []string{ctisFinding.Vulnerability.CWEID}
	}

	// Collect OWASP IDs
	var owaspIDs []string
	if len(ctisFinding.Vulnerability.OWASPIDs) > 0 {
		owaspIDs = ctisFinding.Vulnerability.OWASPIDs
	}

	if cveID != "" || cvssScore != nil || len(cweIDs) > 0 || len(owaspIDs) > 0 {
		if err := f.SetClassification(cveID, cvssScore, cvssVector, cweIDs, owaspIDs); err != nil {
			p.logger.Warn("failed to set classification", "error", err)
		}
	}

	// Set ASVS (Application Security Verification Standard) compliance info
	if ctisFinding.Vulnerability.ASVS != nil {
		asvs := ctisFinding.Vulnerability.ASVS
		if asvs.Section != "" {
			f.SetASVSSection(asvs.Section)
		}
		if asvs.ControlID != "" {
			f.SetASVSControlID(asvs.ControlID)
		}
		if asvs.ControlURL != "" {
			f.SetASVSControlURL(asvs.ControlURL)
		}
		if asvs.Level > 0 {
			level := asvs.Level
			f.SetASVSLevel(&level)
		}
	}
}

// setFindingTypeAndSpecializedFields sets the finding type discriminator and specialized fields.
func (p *FindingProcessor) setFindingTypeAndSpecializedFields(f *vulnerability.Finding, ctisFinding *ctis.Finding) {
	// Determine finding type from CTIS type or source
	findingType := p.inferFindingType(f.Source(), ctisFinding)
	f.SetFindingType(findingType)

	// Set specialized fields based on finding type
	switch findingType {
	case vulnerability.FindingTypeSecret:
		p.setSecretFields(f, ctisFinding)
	case vulnerability.FindingTypeCompliance:
		p.setComplianceFields(f, ctisFinding)
	case vulnerability.FindingTypeWeb3:
		p.setWeb3Fields(f, ctisFinding)
	case vulnerability.FindingTypeMisconfiguration:
		p.setMisconfigFields(f, ctisFinding)
	}
}

// inferFindingType determines the FindingType based on source and CTIS finding data.
func (p *FindingProcessor) inferFindingType(source vulnerability.FindingSource, ctisFinding *ctis.Finding) vulnerability.FindingType {
	// First, check if CTIS finding has explicit type
	if ctisFinding.Type != "" {
		switch ctisFinding.Type {
		case ctis.FindingTypeVulnerability:
			return vulnerability.FindingTypeVulnerability
		case ctis.FindingTypeSecret:
			return vulnerability.FindingTypeSecret
		case ctis.FindingTypeMisconfiguration:
			return vulnerability.FindingTypeMisconfiguration
		case ctis.FindingTypeCompliance:
			return vulnerability.FindingTypeCompliance
		}
	}

	// Infer from source
	switch source {
	case vulnerability.FindingSourceSecret:
		return vulnerability.FindingTypeSecret
	case vulnerability.FindingSourceIaC:
		return vulnerability.FindingTypeMisconfiguration
	}

	// Check for compliance finding (has compliance details)
	if ctisFinding.Compliance != nil && ctisFinding.Compliance.Framework != "" {
		return vulnerability.FindingTypeCompliance
	}

	// Check for Web3 finding
	if ctisFinding.Web3 != nil && (ctisFinding.Web3.Chain != "" || ctisFinding.Web3.SWCID != "") {
		return vulnerability.FindingTypeWeb3
	}

	// Check for misconfiguration finding
	if ctisFinding.Misconfiguration != nil && ctisFinding.Misconfiguration.PolicyID != "" {
		return vulnerability.FindingTypeMisconfiguration
	}

	// Default to vulnerability
	return vulnerability.FindingTypeVulnerability
}

// setSecretFields sets secret-specific fields on a finding.
func (p *FindingProcessor) setSecretFields(f *vulnerability.Finding, ctisFinding *ctis.Finding) {
	if ctisFinding.Secret == nil {
		return
	}

	if ctisFinding.Secret.SecretType != "" {
		f.SetSecretType(ctisFinding.Secret.SecretType)
	}
	if ctisFinding.Secret.Service != "" {
		f.SetSecretService(ctisFinding.Secret.Service)
	}
	if ctisFinding.Secret.Valid != nil {
		f.SetSecretValid(ctisFinding.Secret.Valid)
	}
	if ctisFinding.Secret.Revoked {
		revoked := true
		f.SetSecretRevoked(&revoked)
	}
	if ctisFinding.Secret.Entropy > 0 {
		entropy := ctisFinding.Secret.Entropy
		f.SetSecretEntropy(&entropy)
	}
	// Extended secret fields
	if ctisFinding.Secret.ExpiresAt != nil {
		f.SetSecretExpiresAt(ctisFinding.Secret.ExpiresAt)
	}
	if ctisFinding.Secret.VerifiedAt != nil {
		f.SetSecretVerifiedAt(ctisFinding.Secret.VerifiedAt)
	}
	if ctisFinding.Secret.RotationDueAt != nil {
		f.SetSecretRotationDueAt(ctisFinding.Secret.RotationDueAt)
	}
	if ctisFinding.Secret.AgeInDays > 0 {
		f.SetSecretAgeInDays(ctisFinding.Secret.AgeInDays)
	}
	if len(ctisFinding.Secret.Scopes) > 0 {
		f.SetSecretScopes(ctisFinding.Secret.Scopes)
	}
	if ctisFinding.Secret.MaskedValue != "" {
		f.SetSecretMaskedValue(ctisFinding.Secret.MaskedValue)
	}
	if ctisFinding.Secret.InHistoryOnly {
		f.SetSecretInHistoryOnly(true)
	}
	if ctisFinding.Secret.CommitCount > 0 {
		f.SetSecretCommitCount(ctisFinding.Secret.CommitCount)
	}
}

// setComplianceFields sets compliance-specific fields on a finding.
func (p *FindingProcessor) setComplianceFields(f *vulnerability.Finding, ctisFinding *ctis.Finding) {
	if ctisFinding.Compliance == nil {
		return
	}

	if ctisFinding.Compliance.Framework != "" {
		f.SetComplianceFramework(ctisFinding.Compliance.Framework)
	}
	if ctisFinding.Compliance.FrameworkVersion != "" {
		f.SetComplianceFrameworkVersion(ctisFinding.Compliance.FrameworkVersion)
	}
	if ctisFinding.Compliance.ControlID != "" {
		f.SetComplianceControlID(ctisFinding.Compliance.ControlID)
	}
	if ctisFinding.Compliance.ControlName != "" {
		f.SetComplianceControlName(ctisFinding.Compliance.ControlName)
	}
	if ctisFinding.Compliance.ControlDescription != "" {
		f.SetComplianceControlDescription(ctisFinding.Compliance.ControlDescription)
	}
	if ctisFinding.Compliance.Result != "" {
		f.SetComplianceResult(ctisFinding.Compliance.Result)
	}
}

// setWeb3Fields sets Web3-specific fields on a finding.
func (p *FindingProcessor) setWeb3Fields(f *vulnerability.Finding, ctisFinding *ctis.Finding) {
	if ctisFinding.Web3 == nil {
		return
	}

	if ctisFinding.Web3.Chain != "" {
		f.SetWeb3Chain(ctisFinding.Web3.Chain)
	}
	if ctisFinding.Web3.ChainID > 0 {
		f.SetWeb3ChainID(ctisFinding.Web3.ChainID)
	}
	if ctisFinding.Web3.ContractAddress != "" {
		f.SetWeb3ContractAddress(ctisFinding.Web3.ContractAddress)
	}
	if ctisFinding.Web3.SWCID != "" {
		f.SetWeb3SWCID(ctisFinding.Web3.SWCID)
	}
	if ctisFinding.Web3.FunctionSignature != "" {
		f.SetWeb3FunctionSignature(ctisFinding.Web3.FunctionSignature)
	}
	if ctisFinding.Web3.FunctionSelector != "" {
		f.SetWeb3FunctionSelector(ctisFinding.Web3.FunctionSelector)
	}
	if ctisFinding.Web3.BytecodeOffset > 0 {
		f.SetWeb3BytecodeOffset(ctisFinding.Web3.BytecodeOffset)
	}
	// RelatedTxHashes available in CTIS but not mapped to domain yet
}

// setMisconfigFields sets misconfiguration-specific fields on a finding.
func (p *FindingProcessor) setMisconfigFields(f *vulnerability.Finding, ctisFinding *ctis.Finding) {
	if ctisFinding.Misconfiguration == nil {
		return
	}

	if ctisFinding.Misconfiguration.PolicyID != "" {
		f.SetMisconfigPolicyID(ctisFinding.Misconfiguration.PolicyID)
	}
	if ctisFinding.Misconfiguration.PolicyName != "" {
		f.SetMisconfigPolicyName(ctisFinding.Misconfiguration.PolicyName)
	}
	if ctisFinding.Misconfiguration.ResourceType != "" {
		f.SetMisconfigResourceType(ctisFinding.Misconfiguration.ResourceType)
	}
	if ctisFinding.Misconfiguration.ResourceName != "" {
		f.SetMisconfigResourceName(ctisFinding.Misconfiguration.ResourceName)
	}
	// ResourcePath not available in CTIS types, use Location path instead
	if ctisFinding.Location != nil && ctisFinding.Location.Path != "" {
		f.SetMisconfigResourcePath(ctisFinding.Location.Path)
	}
	if ctisFinding.Misconfiguration.Expected != "" {
		f.SetMisconfigExpected(ctisFinding.Misconfiguration.Expected)
	}
	if ctisFinding.Misconfiguration.Actual != "" {
		f.SetMisconfigActual(ctisFinding.Misconfiguration.Actual)
	}
	if ctisFinding.Misconfiguration.Cause != "" {
		f.SetMisconfigCause(ctisFinding.Misconfiguration.Cause)
	}
}

// setFindingSARIFFields sets SARIF 2.1.0 extended fields on a finding.
func (p *FindingProcessor) setFindingSARIFFields(f *vulnerability.Finding, ctisFinding *ctis.Finding) {
	// Risk assessment fields
	if ctisFinding.Confidence > 0 {
		confidence := ctisFinding.Confidence
		_ = f.SetConfidence(&confidence)
	}
	if ctisFinding.Impact != "" {
		// Normalize to lowercase (DB constraint requires lowercase: critical, high, medium, low)
		f.SetImpact(strings.ToLower(ctisFinding.Impact))
	}
	if ctisFinding.Likelihood != "" {
		// Normalize to lowercase (DB constraint requires lowercase: high, medium, low)
		f.SetLikelihood(strings.ToLower(ctisFinding.Likelihood))
	}
	if len(ctisFinding.VulnerabilityClass) > 0 {
		f.SetVulnerabilityClass(ctisFinding.VulnerabilityClass)
	}
	if len(ctisFinding.Subcategory) > 0 {
		f.SetSubcategory(ctisFinding.Subcategory)
	}

	// SARIF core fields
	if ctisFinding.BaselineState != "" {
		f.SetBaselineState(ctisFinding.BaselineState)
	}
	if ctisFinding.Kind != "" {
		f.SetKind(ctisFinding.Kind)
	}
	if ctisFinding.Rank > 0 {
		rank := ctisFinding.Rank
		_ = f.SetRank(&rank)
	}
	if ctisFinding.OccurrenceCount > 0 {
		f.SetOccurrenceCount(ctisFinding.OccurrenceCount)
	}
	if ctisFinding.CorrelationID != "" {
		f.SetCorrelationID(ctisFinding.CorrelationID)
	}

	// SARIF extended fields
	if len(ctisFinding.PartialFingerprints) > 0 {
		f.SetPartialFingerprints(ctisFinding.PartialFingerprints)
	}
	if len(ctisFinding.RelatedLocations) > 0 {
		relLocs := make([]vulnerability.FindingLocation, 0, len(ctisFinding.RelatedLocations))
		for _, loc := range ctisFinding.RelatedLocations {
			relLocs = append(relLocs, mapCTISLocationToDomain(loc))
		}
		f.SetRelatedLocations(relLocs)
	}
	if len(ctisFinding.Stacks) > 0 {
		stacks := make([]vulnerability.StackTrace, 0, len(ctisFinding.Stacks))
		for _, st := range ctisFinding.Stacks {
			stacks = append(stacks, mapCTISStackTraceToDomain(st))
		}
		f.SetStacks(stacks)
	}
	if len(ctisFinding.Attachments) > 0 {
		atts := make([]vulnerability.Attachment, 0, len(ctisFinding.Attachments))
		for _, att := range ctisFinding.Attachments {
			atts = append(atts, mapCTISAttachmentToDomain(att))
		}
		f.SetAttachments(atts)
	}
	if len(ctisFinding.WorkItemURIs) > 0 {
		f.SetWorkItemURIs(ctisFinding.WorkItemURIs)
	}
	if ctisFinding.HostedViewerURI != "" {
		f.SetHostedViewerURI(ctisFinding.HostedViewerURI)
	}

	// Data flow (taint tracking)
	if ctisFinding.DataFlow != nil {
		domainFlow := mapCTISDataFlowToDomain(ctisFinding.DataFlow)
		f.SetDataFlows([]vulnerability.DataFlow{domainFlow})
	}
}

// setFindingCTEMFields sets CTEM-related fields on a finding.
func (p *FindingProcessor) setFindingCTEMFields(f *vulnerability.Finding, ctisFinding *ctis.Finding) {
	// Exposure fields
	if ctisFinding.Exposure != nil {
		if ctisFinding.Exposure.Vector != "" {
			_ = f.SetExposureVector(vulnerability.ExposureVector(ctisFinding.Exposure.Vector))
		}
		f.SetNetworkAccessible(ctisFinding.Exposure.IsNetworkAccessible)
		f.SetInternetAccessible(ctisFinding.Exposure.IsInternetAccessible)
		if ctisFinding.Exposure.AttackPrerequisites != "" {
			f.SetAttackPrerequisites(ctisFinding.Exposure.AttackPrerequisites)
		}
	}

	// Remediation context fields
	if ctisFinding.RemediationContext != nil {
		if ctisFinding.RemediationContext.Type != "" {
			_ = f.SetRemediationType(vulnerability.RemediationType(ctisFinding.RemediationContext.Type))
		}
		if ctisFinding.RemediationContext.EstimatedMinutes > 0 {
			estTime := ctisFinding.RemediationContext.EstimatedMinutes
			f.SetEstimatedFixTime(&estTime)
		}
		if ctisFinding.RemediationContext.Complexity != "" {
			_ = f.SetFixComplexity(vulnerability.FixComplexity(ctisFinding.RemediationContext.Complexity))
		}
		f.SetRemedyAvailable(ctisFinding.RemediationContext.RemedyAvailable)
	}

	// Business impact fields
	if ctisFinding.BusinessImpact != nil {
		if ctisFinding.BusinessImpact.DataExposureRisk != "" {
			_ = f.SetDataExposureRisk(vulnerability.DataExposureRisk(ctisFinding.BusinessImpact.DataExposureRisk))
		}
		f.SetReputationalImpact(ctisFinding.BusinessImpact.ReputationalImpact)
		if len(ctisFinding.BusinessImpact.ComplianceImpact) > 0 {
			f.SetComplianceImpact(ctisFinding.BusinessImpact.ComplianceImpact)
		}
	}
}

// mapCTISLocationToDomain converts a CTIS FindingLocation to a domain FindingLocation.
func mapCTISLocationToDomain(loc *ctis.FindingLocation) vulnerability.FindingLocation {
	if loc == nil {
		return vulnerability.FindingLocation{}
	}
	result := vulnerability.FindingLocation{
		Path:           loc.Path,
		StartLine:      loc.StartLine,
		EndLine:        loc.EndLine,
		StartColumn:    loc.StartColumn,
		EndColumn:      loc.EndColumn,
		Snippet:        loc.Snippet,
		ContextSnippet: loc.ContextSnippet,
		Branch:         loc.Branch,
		CommitSHA:      loc.CommitSHA,
	}
	if loc.LogicalLocation != nil {
		result.LogicalLocation = &vulnerability.LogicalLocation{
			Name:               loc.LogicalLocation.Name,
			Kind:               loc.LogicalLocation.Kind,
			FullyQualifiedName: loc.LogicalLocation.FullyQualifiedName,
		}
	}
	return result
}

// mapCTISStackTraceToDomain converts a CTIS StackTrace to a domain StackTrace.
func mapCTISStackTraceToDomain(st *ctis.StackTrace) vulnerability.StackTrace {
	if st == nil {
		return vulnerability.StackTrace{}
	}
	result := vulnerability.StackTrace{
		Message: st.Message,
	}
	if len(st.Frames) > 0 {
		result.Frames = make([]vulnerability.StackFrame, 0, len(st.Frames))
		for _, frame := range st.Frames {
			domainFrame := vulnerability.StackFrame{
				Module:     frame.Module,
				ThreadID:   frame.ThreadID,
				Parameters: frame.Parameters,
			}
			if frame.Location != nil {
				loc := mapCTISLocationToDomain(frame.Location)
				domainFrame.Location = &loc
			}
			result.Frames = append(result.Frames, domainFrame)
		}
	}
	return result
}

// mapCTISAttachmentToDomain converts a CTIS Attachment to a domain Attachment.
func mapCTISAttachmentToDomain(att *ctis.Attachment) vulnerability.Attachment {
	if att == nil {
		return vulnerability.Attachment{}
	}
	result := vulnerability.Attachment{
		Description: att.Description,
	}
	if att.ArtifactLocation != nil {
		result.ArtifactLocation = &vulnerability.ArtifactLocation{
			URI:       att.ArtifactLocation.URI,
			URIBaseID: att.ArtifactLocation.URIBaseID,
		}
	}
	if len(att.Regions) > 0 {
		result.Regions = make([]vulnerability.FindingLocation, 0, len(att.Regions))
		for _, reg := range att.Regions {
			result.Regions = append(result.Regions, mapCTISLocationToDomain(reg))
		}
	}
	return result
}

// resolveBranches looks up or creates branch records for the repositories in the report.
// Returns a map of repositoryID -> branchID for setting findings.branch_id FK.
// If branch info is not available or branchRepo is nil, returns empty map.
// tenantRules provides per-tenant branch type detection rules (fallback chain).
// Note: Only creates branches for assets with repository type (repository, code_repo).
func (p *FindingProcessor) resolveBranches(ctx context.Context, tenantID shared.ID, report *ctis.Report, assetMap map[string]shared.ID, tenantRules branch.BranchTypeRules) map[shared.ID]shared.ID {
	branchMap := make(map[shared.ID]shared.ID)

	// Skip if no branch repo or no branch info
	if p.branchRepo == nil || report.Metadata.Branch == nil || report.Metadata.Branch.Name == "" {
		return branchMap
	}

	branchInfo := report.Metadata.Branch

	// For each asset, check if it's a repository before creating branch
	// PERFORMANCE NOTE: GetByID is called per asset, but assetMap typically has 1-2 entries
	// (auto-created assets are single). If batch processing many explicit assets becomes
	// common, consider adding GetByIDs batch method to asset.Repository.
	for _, assetID := range assetMap {
		// Load asset to check type and branch rules
		if p.assetRepo == nil {
			continue
		}

		a, err := p.assetRepo.GetByID(ctx, tenantID, assetID)
		if err != nil || a == nil {
			p.logger.Debug("failed to load asset for branch resolution",
				"asset_id", assetID.String(),
				"error", err,
			)
			continue
		}

		// Only create branches for repository-type assets
		if !a.Type().IsRepository() {
			p.logger.Debug("skipping branch creation for non-repository asset",
				"asset_id", assetID.String(),
				"asset_type", a.Type(),
			)
			continue
		}

		// Load per-asset branch type rules from asset properties
		assetRules := branch.ParseRulesFromProperties(a.Properties())

		branchID, err := p.getOrCreateBranch(ctx, assetID, branchInfo, assetRules, tenantRules)
		if err != nil {
			p.logger.Warn("failed to resolve branch for repository",
				"repository_id", assetID.String(),
				"branch_name", branchInfo.Name,
				"error", err,
			)
			continue
		}
		if branchID != nil {
			branchMap[assetID] = *branchID
		}
	}

	return branchMap
}

// getOrCreateBranch looks up a branch by name, or creates it if it doesn't exist.
// Uses a retry pattern to handle race conditions when multiple concurrent scans
// try to create the same branch simultaneously.
// assetRules and tenantRules provide the configurable branch type detection fallback chain.
func (p *FindingProcessor) getOrCreateBranch(ctx context.Context, repositoryID shared.ID, branchInfo *ctis.BranchInfo, assetRules, tenantRules branch.BranchTypeRules) (*shared.ID, error) {
	// Try to find existing branch by name
	existingBranch, err := p.branchRepo.GetByName(ctx, repositoryID, branchInfo.Name)
	if err == nil && existingBranch != nil {
		// Branch exists - batch updates into a single write
		needsUpdate := false

		if branchInfo.CommitSHA != "" && branchInfo.CommitSHA != existingBranch.LastCommitSHA() {
			existingBranch.UpdateLastCommit(branchInfo.CommitSHA, "", "", "", time.Now().UTC())
			needsUpdate = true
		}

		if branchInfo.IsDefaultBranch && !existingBranch.IsDefault() {
			existingBranch.SetDefault(true)
			needsUpdate = true
		}

		if needsUpdate {
			if err := p.branchRepo.Update(ctx, existingBranch); err != nil {
				p.logger.Warn("failed to update branch",
					"branch_id", existingBranch.ID().String(),
					"error", err,
				)
			}
		}

		id := existingBranch.ID()
		return &id, nil
	}

	// Branch doesn't exist, create it
	// Use configurable branch type detection: per-asset > per-tenant > system defaults
	branchType := branch.DetectBranchType(branchInfo.Name, assetRules, tenantRules)
	newBranch, err := branch.NewBranch(repositoryID, branchInfo.Name, branchType)
	if err != nil {
		return nil, fmt.Errorf("failed to create branch entity: %w", err)
	}

	if branchInfo.IsDefaultBranch {
		newBranch.SetDefault(true)
	}

	if branchInfo.CommitSHA != "" {
		newBranch.UpdateLastCommit(branchInfo.CommitSHA, "", "", "", time.Now().UTC())
	}

	if err := p.branchRepo.Create(ctx, newBranch); err != nil {
		// Race condition: another goroutine may have created the branch
		// between our GetByName and Create calls. Retry the lookup.
		existingBranch, retryErr := p.branchRepo.GetByName(ctx, repositoryID, branchInfo.Name)
		if retryErr == nil && existingBranch != nil {
			p.logger.Debug("branch created by concurrent request, using existing",
				"repository_id", repositoryID.String(),
				"branch_name", branchInfo.Name,
				"branch_id", existingBranch.ID().String(),
			)
			id := existingBranch.ID()
			return &id, nil
		}
		return nil, fmt.Errorf("failed to create branch: %w", err)
	}

	p.logger.Debug("created new branch record",
		"repository_id", repositoryID.String(),
		"branch_name", branchInfo.Name,
		"branch_id", newBranch.ID().String(),
		"is_default", newBranch.IsDefault(),
	)

	id := newBranch.ID()
	return &id, nil
}

// mapCTISDataFlowToDomain converts a CTIS DataFlow to a domain DataFlow value object.
// CTIS format: sources/intermediates/sinks arrays with DataFlowLocation
// Domain format: single Steps array with DataFlowStep (each step has LocationType)
func mapCTISDataFlowToDomain(df *ctis.DataFlow) vulnerability.DataFlow {
	if df == nil {
		return vulnerability.DataFlow{}
	}

	// Pre-allocate steps slice with known capacity
	totalSteps := len(df.Sources) + len(df.Intermediates) + len(df.Sinks)
	steps := make([]vulnerability.DataFlowStep, 0, totalSteps)
	stepIndex := 0

	// Add sources
	for _, loc := range df.Sources {
		steps = append(steps, mapCTISDataFlowLocationToStep(loc, vulnerability.LocationTypeSource, stepIndex))
		stepIndex++
	}

	// Add intermediates
	for _, loc := range df.Intermediates {
		steps = append(steps, mapCTISDataFlowLocationToStep(loc, vulnerability.LocationTypeIntermediate, stepIndex))
		stepIndex++
	}

	// Add sinks
	for _, loc := range df.Sinks {
		steps = append(steps, mapCTISDataFlowLocationToStep(loc, vulnerability.LocationTypeSink, stepIndex))
		stepIndex++
	}

	return vulnerability.DataFlow{
		Index:      0,
		Importance: "essential",
		Steps:      steps,
	}
}

// mapCTISDataFlowLocationToStep converts a CTIS DataFlowLocation to a domain DataFlowStep.
// Note: Uses only fields available in the SDK (Path, Line, Column, Content, Label, Index).
func mapCTISDataFlowLocationToStep(loc ctis.DataFlowLocation, locationType string, stepIndex int) vulnerability.DataFlowStep {
	return vulnerability.DataFlowStep{
		Index:        stepIndex,
		LocationType: locationType,
		Location: &vulnerability.FindingLocation{
			Path:        loc.Path,
			StartLine:   loc.Line,
			StartColumn: loc.Column,
			Snippet:     loc.Content,
		},
		Label:      loc.Label,
		Importance: "essential",
	}
}

// persistDataFlows persists data flows for newly created findings.
// The data flows are stored in the value object format on Finding entities,
// but need to be converted to normalized entity format for database storage.
//
// SECURITY: Enforces limits on number of data flows and locations per finding
// to prevent DoS attacks via excessive data.
func (p *FindingProcessor) persistDataFlows(ctx context.Context, findings []*vulnerability.Finding) {
	for _, f := range findings {
		dataFlows := f.DataFlows()
		if len(dataFlows) == 0 {
			continue
		}

		// SECURITY: Limit number of data flows per finding (DoS protection)
		if len(dataFlows) > vulnerability.MaxDataFlowsPerFinding {
			p.logger.Warn("truncating data flows due to limit exceeded",
				"finding_id", f.ID().String(),
				"count", len(dataFlows),
				"max", vulnerability.MaxDataFlowsPerFinding,
			)
			dataFlows = dataFlows[:vulnerability.MaxDataFlowsPerFinding]
		}

		for _, df := range dataFlows {
			// Create the data flow entity
			flowEntity, err := vulnerability.NewFindingDataFlow(
				f.ID(),
				df.Index,
				df.Message,
				df.Importance,
			)
			if err != nil {
				p.logger.Warn("failed to create data flow entity",
					"finding_id", f.ID().String(),
					"error", err,
				)
				continue
			}

			// Persist the data flow
			if err := p.dataFlowRepo.CreateDataFlow(ctx, flowEntity); err != nil {
				p.logger.Warn("failed to persist data flow",
					"finding_id", f.ID().String(),
					"error", err,
				)
				continue
			}

			// Create and persist flow locations
			// SECURITY: Limit number of locations per data flow (DoS protection)
			steps := df.Steps
			if len(steps) > vulnerability.MaxLocationsPerDataFlow {
				p.logger.Warn("truncating flow locations due to limit exceeded",
					"data_flow_id", flowEntity.ID().String(),
					"count", len(steps),
					"max", vulnerability.MaxLocationsPerDataFlow,
				)
				steps = steps[:vulnerability.MaxLocationsPerDataFlow]
			}

			for _, step := range steps {
				locEntity, err := vulnerability.NewFindingFlowLocation(
					flowEntity.ID(),
					step.Index,
					step.LocationType,
				)
				if err != nil {
					p.logger.Warn("failed to create flow location entity",
						"data_flow_id", flowEntity.ID().String(),
						"error", err,
					)
					continue
				}

				// Set physical location
				if step.Location != nil {
					locEntity.SetPhysicalLocation(
						step.Location.Path,
						step.Location.StartLine,
						step.Location.EndLine,
						step.Location.StartColumn,
						step.Location.EndColumn,
						step.Location.Snippet,
					)
				}

				// Set logical location
				locEntity.SetLogicalLocation(
					step.FunctionName,
					step.ClassName,
					step.FullyQualifiedName,
					step.ModuleName,
				)

				// Set context
				locEntity.SetContext(
					step.Label,
					step.Message,
					step.NestingLevel,
					step.Importance,
				)

				// Persist the flow location
				if err := p.dataFlowRepo.CreateFlowLocation(ctx, locEntity); err != nil {
					p.logger.Warn("failed to persist flow location",
						"data_flow_id", flowEntity.ID().String(),
						"error", err,
					)
				}
			}
		}
	}
}

// isValidFingerprint checks if a fingerprint is a valid hash-like string.
// Some tools (e.g., Semgrep) may return invalid values like "requires login"
// when pro features are unavailable. This function validates that the fingerprint
// looks like a hex hash (at least 16 chars, alphanumeric hex characters only).
func isValidFingerprint(fp string) bool {
	// Fingerprint should be at least 16 chars (e.g., short hash) and alphanumeric hex
	if len(fp) < 16 {
		return false
	}
	// Check if it looks like a hex hash (alphanumeric, no spaces)
	for _, c := range fp {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// linkFindingToComponent looks up a component by PURL and links it to the finding.
// This is used for SCA findings where the vulnerability is in a specific package.
func (p *FindingProcessor) linkFindingToComponent(ctx context.Context, f *vulnerability.Finding, ctisFinding *ctis.Finding) {
	// Skip if no component repository configured
	if p.compRepo == nil {
		return
	}

	// Get PURL from vulnerability details
	var purl string
	if ctisFinding.Vulnerability != nil && ctisFinding.Vulnerability.PURL != "" {
		purl = ctisFinding.Vulnerability.PURL
	}

	if purl == "" {
		return
	}

	// Lookup component by PURL
	comp, err := p.compRepo.GetByPURL(ctx, purl)
	if err != nil {
		p.logger.Debug("component not found for PURL",
			"purl", purl,
			"error", err,
		)
		return
	}

	if comp != nil {
		f.SetComponentID(comp.ID())
		p.logger.Debug("linked finding to component",
			"finding_id", f.ID().String(),
			"component_id", comp.ID().String(),
			"purl", purl,
		)
	}
}
