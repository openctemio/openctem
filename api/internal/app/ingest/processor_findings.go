package ingest

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/openctemio/ctis/fingerprint"
	"github.com/openctemio/ctis/severity"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/branch"
	"github.com/openctemio/openctem/api/pkg/domain/component"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// FindingCreatedCallback is called when findings are created during ingestion.
type FindingCreatedCallback func(ctx context.Context, tenantID shared.ID, findings []*vulnerability.Finding)

// FindingProcessor handles batch finding processing.
type FindingProcessor struct {
	// sourceResolveMode is the source-asserted resolve mode
	// (source_resolve.go); "" is dry_run.
	sourceResolveMode SourceResolveMode
	// vexMode is how a VEX not_affected statement acts (interop.go); "" is
	// dry_run.
	vexMode VEXMode

	repo         vulnerability.FindingRepository
	dataFlowRepo vulnerability.DataFlowRepository
	branchRepo   branch.Repository
	assetRepo    asset.Repository
	compRepo     component.Repository
	logger       *logger.Logger

	// findingCreatedCallback is called after findings are successfully created
	findingCreatedCallback FindingCreatedCallback

	// priorityClassifier enriches + classifies findings after creation (RFC-004)
	priorityClassifier PriorityClassifier

	// slaApplier (F3 wire): computes and sets the SLA deadline on each
	// classified finding using priority class first, severity fallback.
	// Nil-safe: when not wired, findings get NULL sla_deadline as before.
	slaApplier SLAApplier

	// assignmentApplier routes created findings to groups via assignment rules.
	// Runs POST-insert (FGA records need persisted finding IDs), unlike the
	// pre-insert priority/SLA enrichers. Nil-safe: when unwired, scanner
	// findings are not auto-routed (prior behavior).
	assignmentApplier AssignmentApplier

	// activityService records audit trail for auto-reopen events
	activityService activityRecorder
	// regressions follows up on reopened findings (fresh SLA, announcement).
	regressions RegressionHandler

	// remediationKeyApplier derives + records each created finding's remediation
	// group key (RFC-015). Runs POST-insert (needs persisted finding IDs).
	// Nil-safe: when unwired, findings simply aren't grouped.
	remediationKeyApplier RemediationKeyApplier

	// exposureBridge promotes secret-scan findings into the exposure/credential
	// store (labeled discovery_source=secret_scan). Runs POST-insert (needs the
	// persisted finding IDs to link back). Best-effort: errors are logged, never
	// fatal. Nil-safe: when unwired, secret findings are not bridged.
	exposureBridge ExposureBridge

	// suppressionChecker enforces approved suppression rules at ingest: a NEW
	// finding matching an active (approved, non-expired) rule lands
	// resolved+suppressed (out of the open backlog) rather than appearing and
	// being closed on a later pass. Active rules are loaded ONCE per batch
	// (tenant-scoped). Nil-safe: when unwired, findings are never suppressed at
	// ingest (prior behavior).
	suppressionChecker SuppressionChecker

	// suppressionModules, when wired, turns ingest suppression off for a
	// tenant whose suppressions module is disabled.
	suppressionModules ModuleGuard

	// secretFingerprinter keys the fingerprint of a reported secret with a
	// server-held secret. Nil-safe: when unwired, no fingerprint is stored.
	secretFingerprinter *vulnerability.SecretFingerprinter
}

// PriorityClassifier enriches findings with EPSS/KEV and assigns priority class.
type PriorityClassifier interface {
	EnrichAndClassifyBatch(ctx context.Context, tenantID shared.ID, findings []*vulnerability.Finding, assets map[shared.ID]*asset.Asset) error
}

// SLAApplier computes SLA deadline for each finding and writes it via
// Finding.SetSLADeadline. MUST run AFTER priority classification so
// the P0..P3 class drives the deadline (F3 invariant).
type SLAApplier interface {
	ApplyBatch(ctx context.Context, tenantID shared.ID, findings []*vulnerability.Finding) error
}

// AssignmentApplier routes persisted findings to groups by evaluating the
// tenant's assignment rules and bulk-creating finding→group records. Runs
// POST-insert (the FGA foreign key needs persisted finding IDs). Implemented by
// *assignment.BatchAssigner. Returns the number of assignments created.
type AssignmentApplier interface {
	ApplyBatch(ctx context.Context, tenantID shared.ID, findings []*vulnerability.Finding) (int, error)
}

// RegressionHandler follows up on findings a scan reopened as regressions: a
// fresh SLA deadline and an announcement (RFC-039). Implemented by
// *retest.ScanRegressions.
type RegressionHandler interface {
	HandleRegressions(ctx context.Context, tenantID shared.ID, reopened []vulnerability.ReopenedFinding, scanner string)
}

// activityRecorder is the subset of FindingActivityService needed by the processor.
type activityRecorder interface {
	RecordBatchAutoReopened(ctx context.Context, tenantID shared.ID, reopened []vulnerability.ReopenedFinding, scanner, scanID string) error
}

// RemediationKeyApplier derives and persists each finding's remediation group
// key. Runs POST-insert (needs persisted finding IDs). Implemented by
// *remediation.KeyApplier. Best-effort: errors are logged, never fatal.
type RemediationKeyApplier interface {
	ApplyBatch(ctx context.Context, tenantID shared.ID, findings []*vulnerability.Finding) error
}

// ExposureBridge promotes secret-scan findings into the exposure/credential
// store, labeled as an internal secret-scan discovery (distinct from an
// external breach import). Runs POST-insert (needs persisted finding IDs to
// link back). Implemented by *exposurebridge.Bridge. Best-effort: a failure is
// logged and never aborts ingest.
type ExposureBridge interface {
	ApplyBatch(ctx context.Context, tenantID shared.ID, findings []*vulnerability.Finding) error
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

// SetActivityService sets the activity service for recording auto-reopen audit trail.
func (p *FindingProcessor) SetActivityService(svc activityRecorder) {
	p.activityService = svc
}

// SetRegressionHandler wires the follow-up on scan regressions (RFC-039 D2).
func (p *FindingProcessor) SetRegressionHandler(h RegressionHandler) {
	p.regressions = h
}

// SetFindingCreatedCallback sets the callback for when findings are created.
func (p *FindingProcessor) SetFindingCreatedCallback(callback FindingCreatedCallback) {
	p.findingCreatedCallback = callback
}

// SetPriorityClassifier sets the priority classification service (RFC-004).
func (p *FindingProcessor) SetPriorityClassifier(classifier PriorityClassifier) {
	p.priorityClassifier = classifier
}

// SetSLAApplier wires the SLA-deadline calculator. F3: the
// applier is invoked AFTER priority classification so priority class
// drives the deadline; when the applier is nil the pipeline behaves
// as before (sla_deadline left NULL).
func (p *FindingProcessor) SetSLAApplier(applier SLAApplier) {
	p.slaApplier = applier
}

// SetAssignmentApplier wires the post-insert group-routing applier. Nil-safe:
// when unwired, scanner findings are not auto-routed to groups.
func (p *FindingProcessor) SetAssignmentApplier(applier AssignmentApplier) {
	p.assignmentApplier = applier
}

// SetRemediationKeyApplier wires remediation-group key derivation (RFC-015).
func (p *FindingProcessor) SetRemediationKeyApplier(applier RemediationKeyApplier) {
	p.remediationKeyApplier = applier
}

// SetSecretFingerprinter wires the keyed secret fingerprint (RFC-043).
func (p *FindingProcessor) SetSecretFingerprinter(fp *vulnerability.SecretFingerprinter) {
	p.secretFingerprinter = fp
}

// SetExposureBridge wires the secret-scan → exposure-store bridge. Nil-safe:
// when unwired, secret findings are not promoted into the Credentials/Exposures
// view (prior behavior).
func (p *FindingProcessor) SetExposureBridge(bridge ExposureBridge) {
	p.exposureBridge = bridge
}

// ProcessBatch processes all findings using batch operations.
func (p *FindingProcessor) ProcessBatch(
	ctx context.Context,
	agt *sensor.Sensor,
	tenantID shared.ID,
	report *ctis.Report,
	assetMap map[string]shared.ID,
	tenantRules branch.BranchTypeRules,
	output *Output,
	cveMap map[string]shared.ID,
) error {
	return p.processBatch(ctx, agt, tenantID, report, assetMap, tenantRules, output, cveMap, false, fullScope())
}

// processBatch is ProcessBatch; strictAssets (protocol v2,
// Options.RequireAssetForFindings) attaches a finding only to the asset its
// asset_ref resolves to, never to the report's single asset as a fallback.
//
//nolint:gocognit,nestif,cyclop,funlen // Batch ingestion inherently requires complex control flow
func (p *FindingProcessor) processBatch(
	ctx context.Context,
	agt *sensor.Sensor,
	tenantID shared.ID,
	report *ctis.Report,
	assetMap map[string]shared.ID,
	tenantRules branch.BranchTypeRules,
	output *Output,
	cveMap map[string]shared.ID,
	strictAssets bool,
	scope *alterScope,
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
		base        string // pre-composite base, persisted for post-merge recompute
		// v1 is the version-1 key (composite of asset and base). A finding
		// stored under it is re-keyed to identity on its next sighting.
		v1 string
		// identity is the version-2 identity (RFC-043 §4.2), nil when no
		// recipe applies and the finding keeps its version-1 key.
		identity *vulnerability.IdentityKey
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

	candidates := make([]findingMeta, 0, len(report.Findings))
	validFindings := make([]findingMeta, 0, len(report.Findings))
	fingerprints := make([]string, 0, len(report.Findings))
	seenFingerprints := make(map[string]struct{}, len(report.Findings))
	duplicatesInReport := 0

	// Get default asset if available (single asset report)
	var defaultAssetID shared.ID
	// Not when an asset of the report was skipped by a scope exclusion: its
	// findings would land on the one asset that was kept.
	if len(assetMap) == 1 && !strictAssets && len(output.ExcludedAssetRefs) == 0 && len(output.OutOfScopeAssetRefs) == 0 {
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

	for i, reported := range report.Findings {
		// A network finding that names several CVEs is one finding per CVE
		// (RFC-043 decision D3).
		for _, ctisFinding := range splitMultiCVENetworkFinding(reported) {
			if output.ExcludedAssetRefs[ctisFinding.AssetRef] {
				// Its asset matches a scope exclusion and was not added.
				output.FindingsSkipped++
				continue
			}
			if output.OutOfScopeAssetRefs[ctisFinding.AssetRef] {
				// The upload's actor may not change its asset.
				output.FindingsSkipped++
				continue
			}
			// Determine target asset
			var targetAssetID shared.ID
			if ctisFinding.AssetRef != "" {
				// Try to find by asset reference
				if id, ok := assetMap[ctisFinding.AssetRef]; ok {
					targetAssetID = id
				} else {
					p.logger.Debug("finding AssetRef not found in assetMap",
						"finding_index", i,
						"asset_ref", logValue(ctisFinding.AssetRef),
					)
				}
			}

			if targetAssetID.IsZero() && !defaultAssetID.IsZero() {
				targetAssetID = defaultAssetID
			}

			if targetAssetID.IsZero() {
				p.logger.Warn("finding skipped: no target asset",
					"finding_index", i,
					"asset_ref", logValue(ctisFinding.AssetRef),
					"default_asset_available", !defaultAssetID.IsZero(),
					"asset_map_size", len(assetMap),
				)
				addError(output, fmt.Sprintf("finding %d: no target asset", i))
				output.FindingsSkipped++
				continue
			}

			// Generate fingerprint (+ the base, persisted so the composite can be
			// recomputed for a new asset_id after an asset merge).
			fp, base := generateFindingFingerprint(targetAssetID, &ctisFinding, report.Tool)

			// Get branch ID for this asset (if available)
			var branchID *shared.ID
			if bid, ok := branchMap[targetAssetID]; ok {
				branchID = &bid
			}

			candidates = append(candidates, findingMeta{
				index:       i,
				finding:     ctisFinding,
				assetID:     targetAssetID,
				branchID:    branchID,
				fingerprint: fp,
				base:        base,
				v1:          fp,
			})
		}
	}

	if len(candidates) == 0 {
		return nil
	}

	// Step 1a: the version-2 identity, computed on the server (RFC-043 §4.2).
	applyIdentityV2Of(p, tenantID, report.Tool, candidates, func(fm *findingMeta) (shared.ID, *ctis.Finding) { return fm.assetID, &fm.finding },
		func(fm *findingMeta, k vulnerability.IdentityKey) {
			fm.identity = &k
			fm.fingerprint = k.Fingerprint()
			fm.base = ""
		})

	// Step 1b: a network finding without a CVE used to be keyed without its
	// port (RFC-043 P0). Hand a row stored under that old key to the first port
	// in this batch that reports it, so its triage carries over before the
	// existence check below sees the new key.
	p.adoptLegacyPortlessFingerprints(ctx, tenantID, validFindingsLegacy(candidates, func(fm findingMeta) (string, string, string) {
		legacy := legacyPortlessFingerprint(fm.assetID, &fm.finding)
		_, base := generateFindingFingerprint(fm.assetID, &fm.finding, report.Tool)
		return legacy, fm.v1, base
	}))

	// Step 1b': a finding still keyed by its version-1 key takes its
	// version-2 key on this sighting; the old key stays its alias (RFC-043 §6).
	adoptV1KeysOf(ctx, p, tenantID, candidates, func(fm findingMeta) (string, *vulnerability.IdentityKey) { return fm.v1, fm.identity })

	// Step 1c: a key a finding gave up (an asset merge, a duplicate folded
	// into another finding, an older recipe) is an alias of the finding that
	// carries it now (RFC-043 §6). Look the keys up so the re-sighting lands
	// on that finding instead of creating a new one.
	aliases := resolveFingerprintAliasesOf(ctx, p, tenantID, candidates, func(fm findingMeta) string { return fm.fingerprint })

	var mitigations []vulnerability.SourceMitigation
	mitigatedNow := time.Now()
	for _, fm := range candidates {
		if current, ok := aliases[fm.fingerprint]; ok {
			fm.fingerprint = current
		}
		// The source says it is mitigated (RFC-047 §7.6): not a sighting.
		if isSourceMitigated(report, &fm.finding) {
			mitigations = append(mitigations, vulnerability.SourceMitigation{
				Fingerprint: fm.fingerprint,
				AssetID:     fm.assetID,
				MitigatedAt: mitigatedAt(&fm.finding, mitigatedNow),
			})
			continue
		}
		// One report naming the same finding twice (the same package in two
		// lockfiles, a template matching twice, two keys of one finding) is
		// one observation. Keep the first; the rest would otherwise reach the
		// multi-row upsert twice, fail it, and be counted as two created
		// findings (RFC-043 B2).
		if _, dup := seenFingerprints[fm.fingerprint]; dup {
			duplicatesInReport++
			continue
		}
		seenFingerprints[fm.fingerprint] = struct{}{}
		validFindings = append(validFindings, fm)
		fingerprints = append(fingerprints, fm.fingerprint)
	}

	if duplicatesInReport > 0 {
		p.logger.Debug("folded repeated findings within one report", "count", duplicatesInReport)
	}

	p.applySourceMitigations(ctx, tenantID, report, mitigations, scope, output)
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
	existingNewData := make([]*vulnerability.Finding, 0) // Built findings for enrichment
	unenrichedFingerprints := make([]string, 0)          // Fingerprints where buildFinding failed
	existingSnippets := make(map[string]string)          // Track snippets for existing findings

	// Fingerprints on assets the report may not change (RFC-040 §5.3): a
	// finding a person resolved there stays resolved.
	var guardedFingerprints []string
	for _, fm := range validFindings {
		if existsMap[fm.fingerprint] {
			existingFingerprints = append(existingFingerprints, fm.fingerprint)
			if !scope.allowedAsset(fm.assetID) {
				guardedFingerprints = append(guardedFingerprints, fm.fingerprint)
			}
			// Track snippet for potential update (if current DB value is invalid)
			if fm.finding.Location != nil && fm.finding.Location.Snippet != "" && fm.finding.Location.Snippet != "requires login" {
				existingSnippets[fm.fingerprint] = fm.finding.Location.Snippet
			}
			// Build Finding from scan data for enrichment
			newData, err := p.buildFinding(ctx, tenantID, fm.assetID, fm.branchID, agt.ID, report, &fm.finding, fm.fingerprint, fm.base, cveMap)
			if err == nil {
				applyIdentityToFinding(newData, fm.identity, &fm.finding)
				existingNewData = append(existingNewData, newData)
			} else {
				// buildFinding failed — fall back to scan-id-only update for this fingerprint
				unenrichedFingerprints = append(unenrichedFingerprints, fm.fingerprint)
			}
		} else {
			f, err := p.buildFinding(ctx, tenantID, fm.assetID, fm.branchID, agt.ID, report, &fm.finding, fm.fingerprint, fm.base, cveMap)
			if err == nil {
				applyIdentityToFinding(f, fm.identity, &fm.finding)
			}
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

	// Step 3b: Batch-reopen re-detected findings that were closed as fixed or
	// downgraded by validation (regressions).
	// PERFORMANCE: Single query instead of N queries per existing finding
	existingFingerprints = p.withoutHumanResolved(ctx, tenantID, existingFingerprints, guardedFingerprints, output)
	if len(existingFingerprints) > 0 {
		reopenedMap, err := p.repo.AutoReopenByFingerprintsBatch(ctx, tenantID, existingFingerprints)
		if err != nil {
			p.logger.Warn("failed to batch auto-reopen findings", "error", err)
		} else if len(reopenedMap) > 0 {
			output.FindingsAutoReopened = len(reopenedMap)
			p.logger.Info("batch auto-reopened findings",
				"count", len(reopenedMap),
			)
			reopened := make([]vulnerability.ReopenedFinding, 0, len(reopenedMap))
			for _, rf := range reopenedMap {
				reopened = append(reopened, rf)
			}
			scanner := ""
			if report.Tool != nil {
				scanner = report.Tool.Name
			}
			// Record the regression on each finding, with who had resolved it.
			if p.activityService != nil {
				if err := p.activityService.RecordBatchAutoReopened(ctx, tenantID, reopened, scanner, report.Metadata.ID); err != nil {
					p.logger.Warn("failed to record auto-reopen activities", "error", err)
				}
			}
			// Fresh SLA + ticket comment + notification (RFC-039 D2, §7.4-7.5).
			if p.regressions != nil {
				p.regressions.HandleRegressions(ctx, tenantID, reopened, scanner)
			}
		}
	}

	// Step 3c: Enforce approved suppression rules. A NEW finding matching an
	// active (approved, non-expired) rule is stamped resolved+suppressed BEFORE
	// persist, so it lands out of the open backlog rather than appearing then
	// being closed on a later pass. Rules are loaded ONCE per batch
	// (tenant-scoped). The returned map (index → rule id) is recorded for audit
	// AFTER insert, once the findings have persisted IDs. Nil-safe.
	suppressionDecisions := p.applySuppressions(ctx, tenantID, newFindings)

	// Step 4: Batch create new findings with partial success support
	if len(newFindings) > 0 {
		// Enrich BEFORE inserting so EPSS/KEV/priority/SLA are written by the
		// initial INSERT. Previously this ran after the batch insert and then
		// issued one UPDATE per finding to persist the enriched fields — N
		// extra round-trips on the hottest ingest path. Enrichment is pure
		// in-memory computation (catalog/rule lookups), so it does not depend
		// on the findings being persisted first.
		p.enrichAndClassify(ctx, tenantID, newFindings)

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
			// A row that met an existing finding (a concurrent ingest created it
			// between the fingerprint check and this insert) is a re-sighting,
			// not a new finding.
			output.FindingsUpdated += result.Updated
			output.FindingsSkipped += result.Skipped

			// Only rows this insert created get the new-finding treatment.
			// The others already exist under another id (re-pointed by the
			// repository) and their side effects ran when they were created.
			createdFindings := make([]*vulnerability.Finding, 0, result.Created)
			createdIndex := make(map[int]struct{}, result.Created)
			for i, f := range newFindings {
				if result.WasInserted(i) {
					createdFindings = append(createdFindings, f)
					createdIndex[i] = struct{}{}
				}
			}

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

			if len(createdFindings) > 0 {
				p.afterCreate(ctx, tenantID, output, newFindings, createdFindings, createdIndex, suppressionDecisions)
			}
		}
	}

	// Step 5: Enrich existing findings with new scan data
	if len(existingFingerprints) > 0 {
		scanID := report.Metadata.ID

		// Step 5a: Enrich findings where buildFinding succeeded
		if len(existingNewData) > 0 {
			enriched, err := p.repo.EnrichBatchByFingerprints(ctx, tenantID, existingNewData, scanID)
			if err != nil {
				// Graceful fallback: if enrichment fails, fall back to scan-id-only update
				p.logger.Warn("enrichment failed, falling back to scan-id-only update",
					"error", err,
					"count", len(existingNewData),
				)
				// Collect fingerprints from failed enrichment for fallback
				fallbackFPs := make([]string, 0, len(existingNewData))
				for _, f := range existingNewData {
					fallbackFPs = append(fallbackFPs, f.Fingerprint())
				}
				unenrichedFingerprints = append(unenrichedFingerprints, fallbackFPs...)
			} else {
				output.FindingsUpdated = int(enriched)
				if enriched > 0 {
					p.logger.Info("enriched existing findings",
						"count", enriched,
					)
				}
			}
		}

		// Step 5b: Fallback scan-id-only update for findings where buildFinding or enrichment failed
		if len(unenrichedFingerprints) > 0 {
			sightingTool := ""
			if report.Tool != nil {
				sightingTool = report.Tool.Name
			}
			updated, err := p.repo.UpdateScanIDBatchByFingerprints(ctx, tenantID, unenrichedFingerprints, scanID, sightingTool)
			if err != nil {
				p.logger.Warn("failed to update existing findings (fallback)", "error", err)
			} else {
				output.FindingsUpdated += int(updated)
			}

			// Update snippets only for unenriched findings (enrichment already handles snippet via LastWins)
			// This fixes the "requires login" issue when Semgrep pro features are unavailable
			unenrichedSnippets := make(map[string]string, len(unenrichedFingerprints))
			for _, fp := range unenrichedFingerprints {
				if s, ok := existingSnippets[fp]; ok {
					unenrichedSnippets[fp] = s
				}
			}
			if len(unenrichedSnippets) > 0 {
				snippetUpdated, err := p.repo.UpdateSnippetBatchByFingerprints(ctx, tenantID, unenrichedSnippets)
				if err != nil {
					p.logger.Warn("failed to update snippets for existing findings", "error", err)
				} else if snippetUpdated > 0 {
					p.logger.Info("updated snippets for unenriched findings",
						"count", snippetUpdated,
					)
				}
			}
		}
	}

	// Step 6: Branch-aware occurrence model. Record, per branch, where each
	// finding was observed in this scan. Matched by fingerprint so it covers
	// both newly-created and enriched findings, and is additive to the finding
	// row (which keeps its branch-independent identity). Best-effort: a failure
	// here must not fail the ingest.
	reportCommit := ""
	if report.Metadata.Branch != nil {
		reportCommit = report.Metadata.Branch.CommitSHA
	}
	occurrences := make([]vulnerability.BranchOccurrenceUpsert, 0, len(validFindings))
	for _, fm := range validFindings {
		if fm.branchID == nil {
			continue
		}
		commit := reportCommit
		if commit == "" && fm.finding.Location != nil {
			commit = fm.finding.Location.CommitSHA
		}
		occurrences = append(occurrences, vulnerability.BranchOccurrenceUpsert{
			Fingerprint: fm.fingerprint,
			BranchID:    *fm.branchID,
			ScanID:      report.Metadata.ID,
			CommitSHA:   commit,
		})
	}
	if len(occurrences) > 0 {
		// Give existing findings the branch this scan saw them on. A finding
		// first ingested without branch info (or first seen on a feature
		// branch) otherwise never sits on the default branch, and
		// default-branch auto-resolve can never close it.
		if n, err := p.repo.BackfillFindingBranches(ctx, tenantID, occurrences); err != nil {
			p.logger.Warn("failed to backfill finding branches", "error", err, "count", len(occurrences))
		} else if n > 0 {
			p.logger.Info("backfilled finding branches", "count", n)
		}
		if err := p.repo.UpsertBranchOccurrences(ctx, tenantID, occurrences); err != nil {
			p.logger.Warn("failed to record branch occurrences", "error", err, "count", len(occurrences))
		}
	}

	// Step 7: Scanner output and CVSS vectors (research 24 P0-2), matched by
	// fingerprint like step 6, so new and re-sighted findings both get the
	// latest output. Best-effort: a failure here must not fail the ingest.
	evidence := make([]vulnerability.ScannerEvidenceUpdate, 0, len(validFindings))
	for i := range validFindings {
		if u := scannerEvidenceUpdate(validFindings[i].fingerprint, &validFindings[i].finding); !u.IsEmpty() {
			evidence = append(evidence, u)
		}
	}
	p.storeScannerEvidence(ctx, tenantID, evidence)

	// Step 7b: source interoperability data (CTIS 1.4: native identity,
	// scores, vulnerability ids, source lifecycle, solution, VEX, source
	// extras, location key), matched by fingerprint like step 7, then the
	// VEX not_affected statements. Best-effort.
	interop := make([]vulnerability.InteropUpdate, 0, len(validFindings))
	vexSightings := make([]vexSighting, 0)
	for i := range validFindings {
		fm := &validFindings[i]
		if u := interopUpdate(fm.fingerprint, &fm.finding); !u.Data.IsEmpty() {
			interop = append(interop, u)
		}
		if fm.finding.VEX != nil {
			vexSightings = append(vexSightings, vexSighting{fingerprint: fm.fingerprint, assetID: fm.assetID, finding: &fm.finding})
		}
	}
	p.storeInterop(ctx, tenantID, interop)
	p.applyVEX(ctx, tenantID, vexNotAffectedItems(vexSightings), scope, output)

	// Step 8: the template content each finding was matched with
	// (research/18 O6): its new baseline for retests and later scans. A
	// record of the sighting, like the enrichment above; it never changes a
	// finding's status, and a baseline only narrows what later proves a fix.
	sightings := make([]vulnerability.TemplateSighting, 0, len(validFindings))
	for _, fm := range validFindings {
		if prov := findingTemplateProvenance(&fm.finding, report.Tool); !prov.Empty() {
			sightings = append(sightings, vulnerability.TemplateSighting{Fingerprint: fm.fingerprint, Provenance: prov})
		}
	}
	p.recordTemplateSightings(ctx, tenantID, sightings)

	return nil
}

// storeScannerEvidence writes each sighting's scanner output and vectors.
func (p *FindingProcessor) storeScannerEvidence(ctx context.Context, tenantID shared.ID, updates []vulnerability.ScannerEvidenceUpdate) {
	w, ok := p.repo.(scannerEvidenceWriter)
	if !ok || len(updates) == 0 {
		return
	}
	if _, err := w.UpdateScannerEvidenceBatch(ctx, tenantID, updates); err != nil {
		p.logger.Warn("failed to store scanner output", "error", err, "count", len(updates))
	}
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

	existing = make([]string, 0, len(fingerprints))
	missing = make([]string, 0, len(fingerprints))

	// Check in batches so a single query stays bounded, but check ALL
	// fingerprints — the previous code truncated to the first 100, so a caller
	// that sent >100 and used `missing` to decide what to upload silently lost
	// visibility of fingerprints 101+. The request body size is already capped
	// upstream, so the batch count is bounded.
	const batchSize = 100
	for start := 0; start < len(fingerprints); start += batchSize {
		end := start + batchSize
		if end > len(fingerprints) {
			end = len(fingerprints)
		}
		batch := fingerprints[start:end]

		existsMap, err := p.repo.CheckFingerprintsExist(ctx, tenantID, batch)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to check fingerprints: %w", err)
		}
		// A former key of a finding (RFC-043 §6) is known too.
		var unknown []string
		for _, fp := range batch {
			if !existsMap[fp] {
				unknown = append(unknown, fp)
			}
		}
		for alias := range resolveFingerprintAliasesOf(ctx, p, tenantID, unknown, func(fp string) string { return fp }) {
			existsMap[alias] = true
		}
		for _, fp := range batch {
			if existsMap[fp] {
				existing = append(existing, fp)
			} else {
				missing = append(missing, fp)
			}
		}
	}

	return existing, missing, nil
}

// generateFindingFingerprint generates a fingerprint for a CTIS finding.
// The fingerprint includes assetID to ensure findings are unique per-asset.
// This prevents the same vulnerability on different assets from being deduplicated incorrectly.
// It returns both the composite fingerprint (stored on the finding) and the
// pre-composite base, so the base can be persisted (see FingerprintBaseKey) and
// the composite recomputed for a new asset_id after an asset merge.
func generateFindingFingerprint(assetID shared.ID, ctisFinding *ctis.Finding, tool *ctis.Tool) (composite, base string) {
	// Generate base fingerprint
	var baseFingerprint string

	if ctisFinding.Fingerprint != "" && isValidFingerprint(ctisFinding.Fingerprint) {
		// Use provided fingerprint as base (only if valid hash-like string)
		baseFingerprint = ctisFinding.Fingerprint
	} else if cve, port, ok := networkVACVEKey(ctisFinding); ok {
		// Network/host vulnerability (Nessus/Qualys/Tenable): a CVE observed on a
		// host with no package and no code location. Left to fingerprint.DetectType
		// this falls to TypeGeneric (rule id + file + message) — or, if TargetHost
		// were set, to TypeDAST (rule id + host + path) — both of which key on the
		// scanner's plugin id/message. The SAME CVE on the SAME host reported by two
		// scanners then produced two findings. Key the base on CVE(+port) alone; the
		// host/asset is already bound via the composite asset id below, so this dedups
		// the finding across scanners independent of rule id and message.
		baseFingerprint = fingerprint.Hash("netva:" + port + ":" + cve)
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
			input.StartColumn = ctisFinding.Location.StartColumn
			input.EndColumn = ctisFinding.Location.EndColumn
		}

		// Populate type-specific fields so fingerprint.Generate selects the
		// correct type-aware algorithm (see fingerprint.DetectType). Without
		// these, every finding fell back to the generic algorithm, which both
		// false-merged distinct SCA/secret findings and churned fingerprints
		// across scans when incidental fields (line numbers, messages) shifted.
		if v := ctisFinding.Vulnerability; v != nil {
			input.PackageName = v.Package
			input.PackageVersion = v.AffectedVersion
			if v.CVEID != "" {
				input.VulnerabilityID = v.CVEID
			}
		}
		if s := ctisFinding.Secret; s != nil {
			// MaskedValue is stable per-secret and carries no plaintext.
			input.SecretValue = s.MaskedValue
		}
		if m := ctisFinding.Misconfiguration; m != nil {
			input.ResourceType = m.ResourceType
			input.ResourceName = m.ResourceName
		}
		if w := ctisFinding.Web3; w != nil {
			input.ContractAddress = w.ContractAddress
			input.ChainID = int(w.ChainID)
			input.SWCID = w.SWCID
			input.FunctionSignature = w.FunctionSignature
		}

		// GenerateAuto detects the type from the populated fields above and
		// applies the matching type-aware algorithm (plain Generate would key
		// everything by the generic location-based scheme).
		baseFingerprint = fingerprint.GenerateAuto(input)

		// The generic recipe has no port: one scanner plugin without a CVE on
		// ports 443 and 8443 of a host was a single finding (RFC-043 P0). Key a
		// port-specific generic finding on its port and transport as well.
		if pp := genericNetworkPort(ctisFinding, input); pp != "" {
			baseFingerprint = fingerprint.Hash("netport:" + pp + ":" + baseFingerprint)
		}
	}

	// Create composite fingerprint including assetID
	// This ensures the same vulnerability on different assets produces different fingerprints
	return createCompositeFingerprint(assetID.String(), baseFingerprint), baseFingerprint
}

// networkVACVEKey reports whether a CTIS finding is a network/host vulnerability
// (a CVE observed on a host by a scanner like Nessus/Qualys/Tenable) and, if so,
// returns its scanner-independent dedup key parts: the CVE id and the port.
//
// It deliberately excludes findings that already dedup correctly under a
// type-aware algorithm: SCA/container (have a package), SAST/secret (have a code
// file location). Only a CVE-bearing finding with neither is treated as a network
// VA. port is "" for a host-level finding (no specific port). When multiple CVEs
// are grouped on one plugin, the lexically smallest id is used so two scanners
// reporting the same CVE agree regardless of field placement (CVEID vs CVEIDs).
func networkVACVEKey(f *ctis.Finding) (cve, port string, ok bool) {
	v := f.Vulnerability
	if v == nil {
		return "", "", false
	}
	if strings.TrimSpace(v.Package) != "" {
		return "", "", false // SCA / container — keyed by package elsewhere
	}
	if f.Location != nil && strings.TrimSpace(f.Location.Path) != "" {
		return "", "", false // SAST / secret — keyed by file location elsewhere
	}

	cves := make([]string, 0, len(v.CVEIDs)+1)
	if c := strings.ToLower(strings.TrimSpace(v.CVEID)); c != "" {
		cves = append(cves, c)
	}
	for _, c := range v.CVEIDs {
		if c := strings.ToLower(strings.TrimSpace(c)); c != "" {
			cves = append(cves, c)
		}
	}
	if len(cves) == 0 {
		return "", "", false // no CVE — not a network VA finding
	}
	sort.Strings(cves)
	cve = cves[0]

	if f.Network != nil && f.Network.Port > 0 {
		port = strconv.Itoa(f.Network.Port)
	}
	return cve, port, true
}

// buildFinding creates a Finding domain entity from a CTIS finding.
func (p *FindingProcessor) buildFinding(
	ctx context.Context,
	tenantID shared.ID,
	assetID shared.ID,
	branchID *shared.ID,
	sensorID shared.ID,
	report *ctis.Report,
	ctisFinding *ctis.Finding,
	fp string,
	base string,
	cveMap map[string]shared.ID,
) (*vulnerability.Finding, error) {
	// Map severity
	sev := vulnerability.SeverityMedium
	if ctisFinding.Severity != "" {
		parsed := severity.FromString(string(ctisFinding.Severity))
		sev = mapSDKSeverity(parsed)
	}

	// Determine source from tool.
	//
	// The initial value is External, not SAST. A report with no Tool block is
	// valid — report.json requires only version and metadata, and ValidateReport
	// checks counts — so this branch is reachable, and it used to file every
	// such finding as static code analysis. Same defect as detectFindingSource's
	// old default, one level up, and fixing only the inner one left it live.
	source := vulnerability.FindingSourceExternal
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
	f.SetSensorID(sensorID)
	f.SetScanID(report.Metadata.ID)

	// Provenance. ctis.ReportMetadata.SourceType has always carried this — the
	// Nessus converter sets "integration", the sensor's reports say "scanner" —
	// and the processor read it and threw it away. An unrecognized value leaves
	// the column NULL rather than guessing, so "unrecorded" stays honest.
	if channel, ok := vulnerability.IngestChannelFromCTIS(report.Metadata.SourceType); ok {
		f.SetIngestChannel(channel)
	}
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
	setFindingScannerDetails(f, ctisFinding)

	// Set tags
	if len(ctisFinding.Tags) > 0 {
		f.SetTags(ctisFinding.Tags)
	}

	// Set SARIF 2.1.0 fields
	p.setFindingSARIFFields(f, ctisFinding)

	// Persist the pre-composite base so the composite fingerprint can be
	// recomputed for a new asset_id after an asset merge (the stored fingerprint
	// embeds the old asset_id and would otherwise never dedupe post-merge).
	// MUST run AFTER setFindingSARIFFields — that call REPLACES the whole
	// partial_fingerprints map (SARIF partialFingerprints), which would wipe the
	// base if it were stored earlier.
	if base != "" {
		f.AddPartialFingerprint(vulnerability.FingerprintBaseKey, base)
	}

	// Set CTEM fields (exposure, remediation, business impact)
	p.setFindingCTEMFields(f, ctisFinding)

	// Set finding type and specialized fields
	p.setFindingTypeAndSpecializedFields(f, ctisFinding)

	// Link to component via PURL (for SCA findings)
	p.linkFindingToComponent(ctx, f, ctisFinding)

	// Stamp VulnerabilityID from cveMap if the finding references a known CVE
	if ctisFinding.Vulnerability != nil {
		if id, ok := cveMap[vulnerability.NormalizeCVEID(ctisFinding.Vulnerability.CVEID)]; ok && !id.IsZero() {
			f.SetVulnerabilityID(id)
		}
	}

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

	// Network location (port, transport, service). Stored for display and
	// service-level queries only; generateFindingFingerprint reads the port from the
	// CTIS finding itself, so storing it changes no fingerprint.
	if n := ctisFinding.Network; n != nil {
		f.SetNetwork(vulnerability.NetworkLocation{Port: n.Port, Transport: n.Protocol, Service: n.Service})
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

	// The scanner's exploit verdict is this tenant's observation: it is kept
	// on the finding, never written to the shared CVE catalog, and the
	// tenant's CVE views read it from here (global-catalog-trust.md).
	if ctisFinding.Vulnerability.ExploitAvailable {
		f.SetMetadata(vulnerability.FindingMetaScannerExploitAvailable, true)
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
		// SECURITY: for a secret finding the raw code snippet / context is the
		// leaked credential's source line. Never persist it in cleartext —
		// replace it with the masked value (or a generic placeholder) so the DB
		// and any snippet rendering cannot expose the secret. The scanner is
		// expected to pre-mask, but we redact server-side as defense in depth.
		p.redactSecretSnippet(f)
	case vulnerability.FindingTypeCompliance:
		p.setComplianceFields(f, ctisFinding)
	case vulnerability.FindingTypeWeb3:
		p.setWeb3Fields(f, ctisFinding)
	case vulnerability.FindingTypeMisconfiguration:
		p.setMisconfigFields(f, ctisFinding)
	}
}

// redactSecretSnippet strips the raw code snippet/context from a secret finding
// so the live credential is never persisted in cleartext. The masked value is
// kept as the only snippet representation; if none is available a generic
// placeholder is used.
func (p *FindingProcessor) redactSecretSnippet(f *vulnerability.Finding) {
	if masked := f.SecretMaskedValue(); masked != "" {
		f.SetSnippet(masked)
	} else {
		f.SetSnippet("[redacted secret]")
	}
	f.SetContextSnippet("")
}

// inferFindingType determines the FindingType based on source and CTIS finding data.
func (p *FindingProcessor) inferFindingType(source vulnerability.FindingSource, ctisFinding *ctis.Finding) vulnerability.FindingType {
	// A finding of the secret technique is a secret. The source comes from the
	// tool (betterleaks, gitleaks, trufflehog), and a secret scanner reports
	// nothing else. Its CTIS type cannot override that with "vulnerability":
	// converters write that generic value when they do not recognize the tool
	// (ctis FromSARIF does so for betterleaks), and the finding would then skip
	// the secret handling below, snippet redaction included.
	if source == vulnerability.FindingSourceSecret &&
		(ctisFinding.Type == "" || ctisFinding.Type == ctis.FindingTypeVulnerability) {
		return vulnerability.FindingTypeSecret
	}

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
		f.SetSecretFingerprint(p.secretFingerprinter.Fingerprint(f.TenantID(), ctisFinding.Secret.MaskedValue))
	}
	if ctisFinding.Secret.InHistoryOnly {
		f.SetSecretInHistoryOnly(true)
	}
	if ctisFinding.Secret.CommitCount > 0 {
		f.SetSecretCommitCount(ctisFinding.Secret.CommitCount)
	}
	// Previously unmapped fields - store in metadata to prevent data loss
	if ctisFinding.Secret.RevokedAt != nil {
		f.SetMetadata("secret_revoked_at", ctisFinding.Secret.RevokedAt.Format(time.RFC3339))
	}
	if ctisFinding.Secret.Length > 0 {
		f.SetMetadata("secret_length", ctisFinding.Secret.Length)
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
	if v := normalizeEnumToken(ctisFinding.Compliance.Result); v != "" && vulnerability.ComplianceResult(v).IsValid() {
		f.SetComplianceResult(v)
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
	// Previously unmapped fields - store in metadata to prevent data loss
	if len(ctisFinding.Web3.RelatedTxHashes) > 0 {
		f.SetMetadata("web3_related_tx_hashes", ctisFinding.Web3.RelatedTxHashes)
	}
	if ctisFinding.Web3.VulnerablePattern != "" {
		f.SetMetadata("web3_vulnerable_pattern", ctisFinding.Web3.VulnerablePattern)
	}
	if ctisFinding.Web3.ExploitableOnMainnet {
		f.SetMetadata("web3_exploitable_on_mainnet", true)
	}
	if ctisFinding.Web3.EstimatedImpactUSD > 0 {
		f.SetMetadata("web3_estimated_impact_usd", ctisFinding.Web3.EstimatedImpactUSD)
	}
	if ctisFinding.Web3.AffectedValueUSD > 0 {
		f.SetMetadata("web3_affected_value_usd", ctisFinding.Web3.AffectedValueUSD)
	}
	if ctisFinding.Web3.AttackVector != "" {
		f.SetMetadata("web3_attack_vector", ctisFinding.Web3.AttackVector)
	}
	if len(ctisFinding.Web3.AttackerAddresses) > 0 {
		f.SetMetadata("web3_attacker_addresses", ctisFinding.Web3.AttackerAddresses)
	}
	if ctisFinding.Web3.DetectionTool != "" {
		f.SetMetadata("web3_detection_tool", ctisFinding.Web3.DetectionTool)
	}
	if ctisFinding.Web3.DetectionConfidence != "" {
		f.SetMetadata("web3_detection_confidence", ctisFinding.Web3.DetectionConfidence)
	}
	if ctisFinding.Web3.GasIssue != nil {
		if data, err := json.Marshal(ctisFinding.Web3.GasIssue); err == nil {
			f.SetMetadata("web3_gas_issue", json.RawMessage(data))
		}
	}
	if ctisFinding.Web3.AccessControl != nil {
		if data, err := json.Marshal(ctisFinding.Web3.AccessControl); err == nil {
			f.SetMetadata("web3_access_control", json.RawMessage(data))
		}
	}
	if ctisFinding.Web3.Reentrancy != nil {
		if data, err := json.Marshal(ctisFinding.Web3.Reentrancy); err == nil {
			f.SetMetadata("web3_reentrancy", json.RawMessage(data))
		}
	}
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
	// impact, likelihood, baseline_state, kind and compliance_result are
	// CHECK-constrained columns. A value outside the vocabulary fails the INSERT
	// and drops the whole finding, so each is normalized (case, SARIF camelCase)
	// and anything still unrecognized is left unset rather than stored.
	if v := normalizeEnumToken(ctisFinding.Impact); v != "" && vulnerability.ImpactLevel(v).IsValid() {
		f.SetImpact(v)
	}
	if v := normalizeEnumToken(ctisFinding.Likelihood); v != "" && vulnerability.LikelihoodLevel(v).IsValid() {
		f.SetLikelihood(v)
	}
	if len(ctisFinding.VulnerabilityClass) > 0 {
		f.SetVulnerabilityClass(ctisFinding.VulnerabilityClass)
	}
	if len(ctisFinding.Subcategory) > 0 {
		f.SetSubcategory(ctisFinding.Subcategory)
	}

	// SARIF core fields
	if v := normalizeEnumToken(ctisFinding.BaselineState); v != "" && vulnerability.BaselineState(v).IsValid() {
		f.SetBaselineState(v)
	}
	// SARIF spells this "notApplicable"; the column holds "not_applicable".
	if v := normalizeEnumToken(ctisFinding.Kind); v != "" && vulnerability.FindingKind(v).IsValid() {
		f.SetKind(v)
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
		if branchInfo.CommitSHA != "" && branchInfo.CommitSHA != existingBranch.LastCommitSHA() {
			existingBranch.UpdateLastCommit(branchInfo.CommitSHA, "", "", "", time.Now().UTC())
			if err := p.branchRepo.Update(ctx, existingBranch); err != nil {
				p.logger.Warn("failed to update branch",
					"branch_id", existingBranch.ID().String(),
					"error", err,
				)
			}
		}

		// Default-branch designation is applied atomically (single-default
		// invariant) and only when the repo has no default yet — see
		// maybeSetDefaultBranch.
		if branchInfo.IsDefaultBranch && !existingBranch.IsDefault() {
			p.maybeSetDefaultBranch(ctx, repositoryID, existingBranch.ID())
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

	if branchInfo.CommitSHA != "" {
		newBranch.UpdateLastCommit(branchInfo.CommitSHA, "", "", "", time.Now().UTC())
	}

	// is_default is intentionally NOT set here; it is applied atomically after
	// creation via maybeSetDefaultBranch (single-default invariant + no
	// hijacking an existing default from an untrusted scan report).
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

	if branchInfo.IsDefaultBranch {
		p.maybeSetDefaultBranch(ctx, repositoryID, newBranch.ID())
	}

	p.logger.Debug("created new branch record",
		"repository_id", repositoryID.String(),
		"branch_name", branchInfo.Name,
		"branch_id", newBranch.ID().String(),
	)

	id := newBranch.ID()
	return &id, nil
}

// maybeSetDefaultBranch designates branchID as the repository's default branch,
// but ONLY when the repo has no default yet. It uses the atomic SetDefaultBranch
// (which unsets any sibling default) to preserve the single-default invariant.
//
// It deliberately does NOT flip an existing default: the default-branch flag in
// a scan report is attacker-influenceable, and silently re-pointing the default
// would re-scope default-branch auto-resolve and could be abused to mass-resolve
// a repo's real findings. Changing the default is an explicit API operation.
func (p *FindingProcessor) maybeSetDefaultBranch(ctx context.Context, repositoryID, branchID shared.ID) {
	if current, err := p.branchRepo.GetDefaultBranch(ctx, repositoryID); err == nil && current != nil {
		if current.ID() != branchID {
			p.logger.Debug("ingest reported a default branch but repository already has one; not changing",
				"repository_id", repositoryID.String(),
				"reported_branch_id", branchID.String(),
				"current_default_branch_id", current.ID().String(),
			)
		}
		return
	}
	if err := p.branchRepo.SetDefaultBranch(ctx, repositoryID, branchID); err != nil {
		p.logger.Warn("failed to set default branch on ingest",
			"repository_id", repositoryID.String(),
			"branch_id", branchID.String(),
			"error", err,
		)
	}
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
// enrichAndClassify enriches findings in-memory with EPSS/KEV, classifies
// their priority (RFC-004), and applies SLA deadlines, so the values are
// written by the subsequent batch INSERT instead of a per-finding UPDATE pass.
// All steps are best-effort: on failure the findings persist without the
// enriched fields (matching the previous graceful-degradation behaviour).
func (p *FindingProcessor) enrichAndClassify(ctx context.Context, tenantID shared.ID, findings []*vulnerability.Finding) {
	if p.priorityClassifier == nil || len(findings) == 0 {
		return
	}

	// Build asset map for classification context — each unique asset fetched
	// once. Typical batch has 1-5 unique assets.
	assetMap := make(map[shared.ID]*asset.Asset)
	for _, f := range findings {
		if _, ok := assetMap[f.AssetID()]; !ok {
			if a, err := p.assetRepo.GetByID(ctx, tenantID, f.AssetID()); err == nil {
				assetMap[f.AssetID()] = a
			}
		}
	}

	if err := p.priorityClassifier.EnrichAndClassifyBatch(ctx, tenantID, findings, assetMap); err != nil {
		p.logger.Warn("priority classification failed", "error", err)
		return
	}

	// Apply SLA deadline now that priority class is set. Non-fatal — findings
	// persist without a deadline and the SLA escalation controller surfaces
	// them as NULL.
	if p.slaApplier != nil {
		if err := p.slaApplier.ApplyBatch(ctx, tenantID, findings); err != nil {
			p.logger.Warn("sla deadline apply failed", "error", err)
		}
	}
}

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

// normalizeEnumToken maps a producer-supplied enum label onto the stored
// vocabulary's spelling: trimmed, lower snake_case. SARIF uses camelCase
// ("notApplicable"), CTIS producers vary in case ("High"), and the database
// stores lower snake_case ("not_applicable", "high"). The caller still
// validates the result; this only fixes spelling.
func normalizeEnumToken(s string) string {
	s = strings.TrimSpace(s)
	var b strings.Builder
	for i, r := range s {
		if r >= 'A' && r <= 'Z' {
			if i > 0 && s[i-1] >= 'a' && s[i-1] <= 'z' {
				b.WriteByte('_')
			}
			r += 'a' - 'A'
		}
		if r == '-' || r == ' ' {
			r = '_'
		}
		b.WriteRune(r)
	}
	return b.String()
}

// humanResolvedLookup finds which fingerprints belong to findings a person
// closed (resolved or verified by any method but scan_verified).
// Implemented by *postgres.FindingRepository.
type humanResolvedLookup interface {
	HumanResolvedFingerprints(ctx context.Context, tenantID shared.ID, fingerprints []string) (map[string]bool, error)
}

// withoutHumanResolved drops from fingerprints the guarded ones whose finding
// a person resolved: the report may not reopen them (RFC-040 §5.3). Findings
// the scanner itself auto-resolved still reopen when they are seen again.
// Fails closed: when the lookup is unavailable or fails, no guarded
// fingerprint is reopened.
func (p *FindingProcessor) withoutHumanResolved(ctx context.Context, tenantID shared.ID, fingerprints, guarded []string, output *Output) []string {
	if len(guarded) == 0 {
		return fingerprints
	}
	var human map[string]bool
	if lookup, ok := p.repo.(humanResolvedLookup); ok {
		h, err := lookup.HumanResolvedFingerprints(ctx, tenantID, guarded)
		if err != nil {
			p.logger.Warn("could not tell human-resolved findings apart; none of the guarded findings is reopened", "error", err)
		} else {
			human = h
		}
	}
	if human == nil {
		human = make(map[string]bool, len(guarded))
		for _, fp := range guarded {
			human[fp] = true
		}
	}
	kept := make([]string, 0, len(fingerprints))
	for _, fp := range fingerprints {
		if human[fp] {
			output.ReopensWithheld++
			continue
		}
		kept = append(kept, fp)
	}
	return kept
}

// genericNetworkPort returns "port/transport" when a finding is keyed by the
// generic fingerprint recipe (no CVE, package, secret, resource, contract or
// file location) and names a port; "" otherwise. Only those findings take the
// port into their key: every other recipe already decides what identifies it.
func genericNetworkPort(f *ctis.Finding, input fingerprint.Input) string {
	if f.Network == nil || f.Network.Port <= 0 {
		return ""
	}
	if fingerprint.DetectType(input) != fingerprint.TypeGeneric {
		return ""
	}
	proto := strings.ToLower(strings.TrimSpace(f.Network.Protocol))
	if proto == "" {
		proto = "tcp"
	}
	return strconv.Itoa(f.Network.Port) + "/" + proto
}

// legacyPortlessFingerprint returns the composite fingerprint a port-specific
// generic network finding had before the port joined its key, or "" when the
// finding's key did not change.
func legacyPortlessFingerprint(assetID shared.ID, f *ctis.Finding) string {
	if f.Network == nil || f.Network.Port <= 0 {
		return ""
	}
	// Only the generic recipe changed. A sensor-supplied fingerprint and the
	// network-VA (CVE) key were port-aware already; removing the port there
	// would point at a different, legitimate finding.
	if f.Fingerprint != "" && isValidFingerprint(f.Fingerprint) {
		return ""
	}
	if _, _, ok := networkVACVEKey(f); ok {
		return ""
	}
	portless := *f
	portless.Network = nil
	composite, _ := generateFindingFingerprint(assetID, &portless, nil)
	current, _ := generateFindingFingerprint(assetID, f, nil)
	if composite == current {
		return ""
	}
	return composite
}

// fingerprintAliasResolver is implemented by the postgres finding repository.
// Optional: a repository without it (tests, mocks) resolves nothing.
type fingerprintAliasResolver interface {
	ResolveFingerprintAliases(ctx context.Context, tenantID shared.ID, fingerprints []string) (map[string]string, error)
}

// resolveFingerprintAliases maps the keys of items that are former keys of a
// finding of the tenant to that finding's current key. A failed lookup is
// logged and resolves nothing: the report is still ingested, and a former key
// at worst creates a finding the next merge folds back.
func resolveFingerprintAliasesOf[T any](ctx context.Context, p *FindingProcessor, tenantID shared.ID, items []T, key func(T) string) map[string]string {
	resolver, ok := p.repo.(fingerprintAliasResolver)
	if !ok || len(items) == 0 {
		return nil
	}
	keys := make([]string, 0, len(items))
	for _, it := range items {
		if k := key(it); k != "" {
			keys = append(keys, k)
		}
	}
	aliases, err := resolver.ResolveFingerprintAliases(ctx, tenantID, keys)
	if err != nil {
		p.logger.Warn("failed to resolve finding fingerprint aliases", "error", err)
		return nil
	}
	if len(aliases) > 0 {
		p.logger.Debug("resolved former finding keys", "count", len(aliases))
	}
	return aliases
}

// legacyKey pairs an old fingerprint with the one that replaces it.
type legacyKey struct {
	legacy, current, base string
}

// validFindingsLegacy returns, for each legacy fingerprint, the FIRST finding
// of the batch that maps to it: only one port may take over an old row.
func validFindingsLegacy[T any](items []T, keys func(T) (legacy, current, base string)) []legacyKey {
	seen := map[string]bool{}
	out := make([]legacyKey, 0, len(items))
	for _, it := range items {
		legacy, current, base := keys(it)
		if legacy == "" || seen[legacy] {
			continue
		}
		seen[legacy] = true
		out = append(out, legacyKey{legacy: legacy, current: current, base: base})
	}
	return out
}

// legacyFingerprintAdopter is implemented by the postgres finding repository.
// Optional: a repository without it (tests, mocks) skips the re-key.
type legacyFingerprintAdopter interface {
	AdoptLegacyFingerprint(ctx context.Context, tenantID shared.ID, legacy, current, base string) (bool, error)
}

func (p *FindingProcessor) adoptLegacyPortlessFingerprints(ctx context.Context, tenantID shared.ID, keys []legacyKey) {
	if len(keys) == 0 {
		return
	}
	adopter, ok := p.repo.(legacyFingerprintAdopter)
	if !ok {
		return
	}
	adopted := 0
	for _, k := range keys {
		moved, err := adopter.AdoptLegacyFingerprint(ctx, tenantID, k.legacy, k.current, k.base)
		if err != nil {
			p.logger.Warn("failed to re-key a port-less network finding", "error", err)
			continue
		}
		if moved {
			adopted++
		}
	}
	if adopted > 0 {
		p.logger.Info("re-keyed port-less network findings onto their port", "count", adopted)
	}
}

// afterCreate runs the post-insert steps for the findings this batch newly
// inserted: data flows, the ingest suppression audit link, remediation keys,
// the created callback (workflows, notifications), assignment rules and the
// secret-to-exposure bridge. created holds only inserted findings with their
// persisted ids; createdIndex maps the same set back to newFindings indexes
// for the index-keyed suppression decisions. A row that met an existing
// finding never gets here, so its side effects do not run twice and never run
// with an id that does not exist (RFC-043 B2).
func (p *FindingProcessor) afterCreate(
	ctx context.Context,
	tenantID shared.ID,
	output *Output,
	newFindings, created []*vulnerability.Finding,
	createdIndex map[int]struct{},
	suppressionDecisions map[int]shared.ID,
) {
	// Persist data flows for newly created findings.
	if p.dataFlowRepo != nil {
		p.persistDataFlows(ctx, created)
	}

	// Record which approved rule suppressed each newly-created finding
	// (finding_suppressions) so the ingest suppression is traceable and can be
	// un-suppressed if the rule is later removed. The disposition
	// (resolved+suppressed) was already applied pre-insert; this only records
	// the audit link. Best-effort.
	if len(suppressionDecisions) > 0 {
		decisions := make(map[int]shared.ID, len(suppressionDecisions))
		for idx, ruleID := range suppressionDecisions {
			if _, ok := createdIndex[idx]; ok {
				decisions[idx] = ruleID
			}
		}
		if n := p.recordSuppressions(ctx, newFindings, decisions, nil); n > 0 {
			output.FindingsSuppressed += n
			p.logger.Info("suppressed findings at ingest via approved rules", "count", n)
		}
	}

	// Derive remediation-group keys (RFC-015). Best-effort; grouping is a
	// convenience layer, never blocks ingest.
	if p.remediationKeyApplier != nil {
		if err := p.remediationKeyApplier.ApplyBatch(ctx, tenantID, created); err != nil {
			p.logger.Warn("failed to derive remediation keys", "error", err)
		}
	}

	// Enrichment (EPSS/KEV/priority/SLA) is applied before the insert, so the
	// created rows already carry those fields.

	// Trigger workflow events for newly created findings.
	if p.findingCreatedCallback != nil {
		p.findingCreatedCallback(ctx, tenantID, created)
	}

	// Route newly-created findings to groups via assignment rules
	// (post-insert: FGA records need persisted finding IDs). Best-effort.
	if p.assignmentApplier != nil {
		if assigned, err := p.assignmentApplier.ApplyBatch(ctx, tenantID, created); err != nil {
			p.logger.Warn("failed to auto-route findings to groups", "error", err, "count", len(created))
		} else if assigned > 0 {
			p.logger.Info("auto-routed findings to groups", "assignments", assigned)
		}
	}

	// Promote secret-scan findings into the exposure/credential store so
	// hardcoded secrets show up in the Credentials/Exposures view
	// (discovery_source=secret_scan). Best-effort.
	if p.exposureBridge != nil {
		if err := p.exposureBridge.ApplyBatch(ctx, tenantID, created); err != nil {
			p.logger.Warn("failed to bridge secret findings into exposure store", "error", err, "count", len(created))
		}
	}
}
