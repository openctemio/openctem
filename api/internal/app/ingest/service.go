package ingest

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/internal/app/activity"
	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/branch"
	"github.com/openctemio/openctem/api/pkg/domain/component"
	"github.com/openctemio/openctem/api/pkg/domain/ingestreport"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/sensorresult"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	tooldom "github.com/openctemio/openctem/api/pkg/domain/tool"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

const (
	// DiscoverySourceSensor is the discovery source of an asset a sensor
	// reported without naming one.
	DiscoverySourceSensor = "sensor"
	// CodeNoTenantContext refuses ingest from a sensor without a tenant
	// (a platform sensor outside a job).
	CodeNoTenantContext = "NO_TENANT_CONTEXT"

	// ctisDefaultDiscoverySource is how the ctis recon converter labels a
	// discovery by default. Sensors embed that converter and still send it
	// (over protocol v2 too), so it is stored as DiscoverySourceSensor.
	ctisDefaultDiscoverySource = "agent"
)

// normalizeDiscoverySource maps the ctis converter's default label onto the
// stored value; any other value passes through unchanged.
func normalizeDiscoverySource(s string) string {
	if s == ctisDefaultDiscoverySource {
		return DiscoverySourceSensor
	}
	return s
}

// Service handles ingestion of assets and findings from various formats.
// This is the unified service that uses CTIS as the internal format.
// Supported input formats: CTIS (native), SARIF (via SDK converter), Recon (via SDK converter).
type Service struct {
	assetProcessor     *AssetProcessor
	findingProcessor   *FindingProcessor
	componentProcessor *ComponentProcessor
	cveProcessor       *CVEProcessor
	validator          *Validator

	assetRepo   asset.Repository
	findingRepo vulnerability.FindingRepository
	vulnRepo    vulnerability.VulnerabilityRepository
	compRepo    component.Repository
	sensorRepo  sensor.Repository
	branchRepo  branch.Repository
	tenantRepo  tenant.Repository
	auditRepo   audit.Repository

	// auditSvc is the SHARED application audit service. Ingest audit
	// events are tenant-scoped, so they must go through it rather than
	// writing audit_logs directly: LogEvent also extends the per-tenant
	// tamper-evident hash chain (audit_log_chain). Writing via auditRepo
	// alone persists the log but leaves it unchained, which the hourly
	// chain verifier cannot distinguish from a deleted entry.
	//
	// It must be the same *AuditService instance the rest of the process
	// uses — its chainMu is what serializes chain extension, and a second
	// instance would have its own mutex and could interleave appends.
	auditSvc *auditapp.AuditService

	activityService *activity.FindingActivityService

	// assetExposureProjector promotes recon-discovered assets (open ports,
	// exposed services, TLS certificates) into the Exposure Register. Runs
	// post-asset-insert, best-effort. Nil-safe: when unwired, recon assets are
	// not projected (prior behavior).
	assetExposureProjector AssetExposureProjector

	// scanAttribution stamps tenant_scanned attribution evidence on the
	// assets of command-bound reports (RFC-036 O8). Nil-safe.
	scanAttribution ScanAttributionStamper

	// takeoverConfirmer raises subdomain_takeover from nuclei takeover
	// findings of command-bound reports (RFC-036 P1). Nil-safe.
	takeoverConfirmer TakeoverConfirmer

	// stepOutputs records what command-bound reports of pipeline steps
	// wrote, for chained stages; commandIngested is told when a v2 report
	// of a command finished (step_outputs.go). Nil-safe.
	stepOutputs     StepOutputRecorder
	commandIngested CommandIngestedHook

	// coverageMode and coverageGuard drive coverage-scoped auto-resolve of
	// non-repository findings (coverage_autoresolve.go). The zero mode is
	// dry_run.
	coverageMode  CoverageAutoResolveMode
	coverageGuard BlindingGuard

	// commands binds reports to the commands they name; results holds the
	// tenant policy for unsolicited reports and their quarantine (RFC-040
	// §5.3). Without results every tenant behaves as in "warn" mode.
	commands     commandReader
	results      sensorresult.Repository
	resultLimits sensorresult.Limits
	// contracts reads the submitting sensor's manifest, where a ported
	// tool declares what it produces (output_binding.go). Nil-safe.
	contracts ToolContractSource

	logger *logger.Logger

	// statsUpdateMu protects concurrent stats updates
	statsUpdateMu sync.Mutex
}

// AssetExposureProjector projects recon-discovered assets into the exposure
// store. Implemented by *exposurebridge.AssetBridge. Best-effort: a failure is
// logged and never aborts ingest.
type AssetExposureProjector interface {
	ProjectAssets(ctx context.Context, tenantID shared.ID, assets []*asset.Asset) error
}

// NewService creates a new unified ingest service.
func NewService(
	assetRepo asset.Repository,
	findingRepo vulnerability.FindingRepository,
	vulnRepo vulnerability.VulnerabilityRepository,
	compRepo component.Repository,
	sensorRepo sensor.Repository,
	branchRepo branch.Repository,
	tenantRepo tenant.Repository,
	auditRepo audit.Repository,
	log *logger.Logger,
) *Service {
	l := log.With("service", "ingest")

	return &Service{
		assetProcessor:     NewAssetProcessor(assetRepo, l),
		findingProcessor:   NewFindingProcessor(findingRepo, branchRepo, assetRepo, l),
		componentProcessor: NewComponentProcessor(compRepo, slog.New(l.Handler())),
		cveProcessor:       NewCVEProcessor(vulnRepo, l),
		validator:          NewValidator(),

		assetRepo:   assetRepo,
		findingRepo: findingRepo,
		vulnRepo:    vulnRepo,
		compRepo:    compRepo,
		sensorRepo:  sensorRepo,
		branchRepo:  branchRepo,
		tenantRepo:  tenantRepo,
		auditRepo:   auditRepo,

		coverageGuard: DefaultBlindingGuard(),

		logger: l,
	}
}

// SetAuditService wires the shared audit application service so ingest
// audit events (ingest.completed / ingest.partial_success / ingest.failed)
// are appended to the tenant's tamper-evident hash chain like every other
// tenant-scoped event.
//
// Pass the SAME instance used elsewhere in the process — see the auditSvc
// field comment for why a second instance is unsafe.
func (s *Service) SetAuditService(svc *auditapp.AuditService) {
	s.auditSvc = svc
}

// SetDataFlowRepository sets the data flow repository for persisting taint tracking traces.
func (s *Service) SetDataFlowRepository(repo vulnerability.DataFlowRepository) {
	s.findingProcessor.SetDataFlowRepository(repo)
}

// SetComponentRepository sets the component repository for linking findings to components.
func (s *Service) SetComponentRepository(repo component.Repository) {
	s.findingProcessor.SetComponentRepository(repo)
}

// SetRepositoryExtensionRepository sets the repository extension repository for auto-creating
// repository extensions with web_url during asset ingestion.
func (s *Service) SetRepositoryExtensionRepository(repo asset.RepositoryExtensionRepository) {
	s.assetProcessor.SetRepositoryExtensionRepository(repo)
}

// SetRelationshipRepository sets the asset relationship repository for creating
// subdomain-to-domain relationships during asset ingestion.
func (s *Service) SetRelationshipRepository(repo asset.RelationshipRepository) {
	s.assetProcessor.SetRelationshipRepository(repo)
}

// SetPortReconciler wires port-closed detection for port-scan reports
// (research/22 P0-6). Optional: unwired, ports are only ever added.
func (s *Service) SetPortReconciler(r PortReconciler) {
	s.assetProcessor.SetPortReconciler(r)
}

// SetAssetStateHistoryRepository wires the asset state-history store so the
// discovery pipeline records appeared/recovered events. Optional.
func (s *Service) SetAssetStateHistoryRepository(repo asset.StateHistoryRepository) {
	s.assetProcessor.SetStateHistoryRepository(repo)
}

// SetCorrelator sets the asset correlator for IP-based deduplication (RFC-001).
func (s *Service) SetCorrelator(c *AssetCorrelator) {
	s.assetProcessor.SetCorrelator(c)
}

// SetDedupEnqueuer wires the duplicate-review enqueuer used when correlation
// detects multiple existing assets sharing identity (RFC-001).
func (s *Service) SetDedupEnqueuer(e DedupReviewEnqueuer) {
	s.assetProcessor.SetDedupEnqueuer(e)
}

// SetIdentityStore enables identifier-based asset matching (asset identity
// model); conflicts are raised as duplicate reviews through reviewer.
func (s *Service) SetIdentityStore(store IdentityStore, reviewer IdentityReviewer) {
	s.assetProcessor.SetIdentityStore(store, reviewer)
}

// SetActivityService sets the finding activity service for audit trail during ingestion.
func (s *Service) SetActivityService(activityService *activity.FindingActivityService) {
	s.activityService = activityService
	s.findingProcessor.SetActivityService(activityService)
}

// SetFindingCreatedCallback sets the callback for when findings are created.
// This is used to trigger workflows when new findings are ingested.
func (s *Service) SetFindingCreatedCallback(callback FindingCreatedCallback) {
	s.findingProcessor.SetFindingCreatedCallback(callback)
}

// SetAssetsDiscoveredCallback sets the callback for assets an ingest newly
// created (not merged, not manually created). It drives the asset_discovered
// workflow trigger and the new-internet-facing-asset notification.
func (s *Service) SetAssetsDiscoveredCallback(callback AssetsDiscoveredCallback) {
	s.assetProcessor.SetAssetsDiscoveredCallback(callback)
}

// SetAssetsExposedCallback sets the callback for existing assets a re-scan
// turned internet-facing. It drives the newly-exposed notification.
func (s *Service) SetAssetsExposedCallback(callback AssetsDiscoveredCallback) {
	s.assetProcessor.SetAssetsExposedCallback(callback)
}

// SetPriorityClassifier sets the priority classification service (RFC-004).
func (s *Service) SetPriorityClassifier(classifier PriorityClassifier) {
	s.findingProcessor.SetPriorityClassifier(classifier)
}

// SetRegressionHandler wires the follow-up on findings a scan reopened as
// regressions: a fresh SLA deadline and a ticket comment + notification
// (RFC-039 D2).
func (s *Service) SetRegressionHandler(h RegressionHandler) {
	s.findingProcessor.SetRegressionHandler(h)
}

// SetSLAApplier wires the SLA-deadline calculator used after priority
// classification (F3 wire). Nil-safe: when not wired, findings persist
// with NULL sla_deadline, matching pre-F3 behavior.
func (s *Service) SetSLAApplier(applier SLAApplier) {
	s.findingProcessor.SetSLAApplier(applier)
}

// SetAssignmentApplier wires the post-insert group-routing applier so
// scanner-ingested findings are auto-routed to groups via assignment rules.
// Nil-safe: when not wired, findings are not auto-routed (prior behavior).
func (s *Service) SetAssignmentApplier(applier AssignmentApplier) {
	s.findingProcessor.SetAssignmentApplier(applier)
}

// SetRemediationKeyApplier wires post-insert remediation-group key derivation
// (RFC-015). Nil-safe: when not wired, findings are not grouped.
func (s *Service) SetRemediationKeyApplier(applier RemediationKeyApplier) {
	s.findingProcessor.SetRemediationKeyApplier(applier)
}

// SetExposureBridge wires the post-insert secret-scan → exposure-store bridge
// so hardcoded secrets surface in the Credentials/Exposures view. Nil-safe:
// when not wired, secret findings are not bridged (prior behavior).
func (s *Service) SetExposureBridge(bridge ExposureBridge) {
	s.findingProcessor.SetExposureBridge(bridge)
}

// SetSecretFingerprinter wires the keyed fingerprint stored for secret
// findings. Without it, secret findings carry no fingerprint.
func (s *Service) SetSecretFingerprinter(fp *vulnerability.SecretFingerprinter) {
	s.findingProcessor.SetSecretFingerprinter(fp)
}

// SetSuppressionChecker wires approved suppression-rule enforcement into the
// ingest finding path: a new finding matching an active (approved, non-expired)
// rule lands resolved+suppressed. Nil-safe: when not wired, findings are never
// suppressed at ingest (prior behavior).
func (s *Service) SetSuppressionChecker(checker SuppressionChecker) {
	s.findingProcessor.SetSuppressionChecker(checker)
}

// SetSuppressionModuleGuard makes ingest suppression honor the tenant's
// suppressions module toggle (off = findings land as reported).
func (s *Service) SetSuppressionModuleGuard(guard ModuleGuard) {
	s.findingProcessor.SetSuppressionModuleGuard(guard)
}

// SetAssetExposureProjector wires the post-insert recon-asset → exposure-store
// projector so open ports, exposed services and weak/expiring TLS certificates
// surface continuously in the Exposure Register (CTEM Discovery). Nil-safe:
// when not wired, recon assets are not projected into exposures (prior behavior).
func (s *Service) SetAssetExposureProjector(p AssetExposureProjector) {
	s.assetExposureProjector = p
}

// =============================================================================
// Main Ingestion Methods
// =============================================================================

// Ingest processes a CTIS report from a sensor.
// This is the main entry point for all ingestion.
//
//nolint:cyclop,gocognit // Ingestion dispatches to multiple processors with validation
func (s *Service) Ingest(ctx context.Context, agt *sensor.Sensor, input Input) (*Output, error) {
	// Validate sensor context
	if err := s.validateSensor(agt); err != nil {
		return nil, err
	}
	tenantID := *agt.TenantID

	report := input.Report
	if report == nil {
		return nil, shared.NewDomainError("INVALID_INPUT", "report is required", nil)
	}
	// One name per tool from here on: a sensor released before a tool was
	// replaced still reports the old name (gitleaks -> betterleaks).
	if report.Tool != nil {
		report.Tool.Name = tooldom.CanonicalName(report.Tool.Name)
	}

	// Validate report limits
	if err := s.validator.ValidateReport(report); err != nil {
		return nil, err
	}
	// Cap sensor-supplied text before anything is stored or fingerprinted:
	// an oversized value is cut with a marker, the finding still lands
	// (RFC-040 §5.4).
	if n := capReportText(report); n > 0 {
		s.logger.Warn("ingest: capped oversized finding text",
			"sensor_id", agt.ID.String(), "tenant_id", tenantID.String(),
			"report_id", sanitizeIngestLogField(report.Metadata.ID), "values_capped", n)
	}

	// Result binding (RFC-040 §5.3). A server-side ingest (synthetic sensor,
	// zero id) is trusted. A sensor report without a command passes the
	// unsolicited gate unless the accept side ran it already: quarantined
	// (stored, not applied) or applied with the unsolicited limits.
	opts := input.Options
	if opts.Actor != nil {
		// An upload's findings land only on the assets its rows name, never
		// on an asset made up from the metadata or on "the only asset".
		opts.RequireAssetForFindings = true
	}
	binding := opts.Binding
	// A server-side ingest (synthetic sensor, zero id) is trusted, except a
	// CI run's report: it has no sensor row either, and keeps its binding.
	if agt.ID.IsZero() && binding.Kind != BindingCIRun {
		binding = TrustedBinding()
	}
	if binding.Kind == BindingCommand && binding.Tool != "" &&
		(report.Tool == nil || !tooldom.SameTool(binding.Tool, report.Tool.Name)) {
		return nil, ErrToolNotPermitted
	}
	unsolicitedWarned := false
	if binding.Kind == BindingUnsolicited && !opts.Admitted {
		warned, err := s.admitUnsolicited(ctx, agt, tenantID, unsolicitedSubmission{
			Protocol: sensorresult.ProtocolV1, Route: opts.Route, ReportID: report.Metadata.ID, Report: report,
		})
		if err != nil {
			return nil, err
		}
		unsolicitedWarned = warned
	}
	// An unsolicited report never auto-resolves in a tenant whose mode is
	// quarantine (owner decision Q6 (a)); in warn mode it keeps the previous
	// behavior until the tenant switches.
	unsolicitedMayResolve := binding.Kind != BindingUnsolicited ||
		s.ResultPolicy(ctx, tenantID).Mode == sensorresult.ModeWarn
	// Output-type binding (research/27 G12): a command-bound report may
	// carry only the asset types its tool produces or takes.
	report = s.bindOutputTypes(ctx, agt, tenantID, binding, report, opts)
	scope := newAlterScope(binding).withActor(ctx, opts.Actor)

	// report.Metadata.ID and SourceType come from the CTIS payload
	// submitted by the sensor. A compromised/malicious sensor can
	// embed CR/LF in those fields to forge log lines downstream
	// (CodeQL go/log-injection). Strip control chars before logging.
	s.logger.Info("ingesting report",
		"sensor_id", agt.ID.String(),
		"tenant_id", tenantID.String(),
		"report_id", sanitizeIngestLogField(report.Metadata.ID),
		"source_type", sanitizeIngestLogField(report.Metadata.SourceType),
		"assets_count", len(report.Assets),
		"findings_count", len(report.Findings),
	)

	output := &Output{
		ReportID:          report.Metadata.ID,
		Binding:           binding.String(),
		UnsolicitedWarned: unsolicitedWarned,
	}

	// Load tenant settings once for both asset processing and finding processing
	var tenantRules branch.BranchTypeRules
	var assetIdentityCfg *CorrelationConfig
	if s.tenantRepo != nil {
		if t, err := s.tenantRepo.GetByID(ctx, tenantID); err == nil && t != nil {
			settings := t.TypedSettings()
			tenantRules = settings.Branch.TypeRules
			// Per-tenant asset identity config (RFC-001)
			aiSettings := settings.AssetIdentity
			cfg := s.assetProcessor.defaultCorrelationConfig().WithTenantOverrides(
				aiSettings.StaleAssetDays, aiSettings.MaxIPsPerAsset,
			)
			assetIdentityCfg = &cfg
		}
	}

	// Step 1: Process assets using batch operations
	assetMap, err := s.assetProcessor.processBatch(ctx, tenantID, report, output, assetIdentityCfg, opts.RequireAssetForFindings, scope)
	if err != nil {
		s.logger.Error("failed to process assets batch", "error", logger.SanitizeError(err))
		// Continue with partial results, but say so: the asset upsert is one
		// transaction, so a failure here drops every asset in the report and
		// the findings on new ones. It was logged only, and the sensor got a
		// clean response.
		addError(output, fmt.Sprintf("assets: %v", err))
	}

	// A restricted upload creates no asset, so every asset it maps must be
	// one its actor may change; drop any other (an id a concurrent create
	// race remapped to an existing row) with its findings.
	if scope.actorRestricted() {
		for ref, id := range assetMap {
			if scope.actorDenies(id) {
				delete(assetMap, ref)
				skipOutOfScope(output, ref)
			}
		}
	}

	output.AssetMap = assetMap

	s.logger.Debug("asset processing complete",
		"assets_created", output.AssetsCreated,
		"assets_updated", output.AssetsUpdated,
		"asset_map_size", len(assetMap),
	)

	// Step 1a: attribution of what a sensor report wrote (RFC-036 §6.4,
	// research/22 E7): command-bound and unsolicited sensor reports.
	// Best-effort.
	if binding.Kind == BindingCommand || binding.Kind == BindingUnsolicited {
		toolName := ""
		if report.Tool != nil {
			toolName = report.Tool.Name
		}
		s.stampScanAttribution(ctx, agt, tenantID, binding, scope, toolName, report.Metadata.ID, assetMap)
	}
	// What a pipeline step's report wrote, for the stages chained after it.
	s.recordStepOutputs(ctx, tenantID, binding, scope)

	// Step 1b: Project recon-discovered assets (open ports, exposed services,
	// TLS certificates) into the Exposure Register. Best-effort — a failure here
	// must never abort ingest. Only the relevant CTIS asset types are re-loaded
	// (by their AUTHORITATIVE persisted id, so the exposure→asset FK is valid),
	// keeping non-recon scans (which create no such assets) free of extra work.
	if s.assetExposureProjector != nil {
		s.projectAssetExposures(ctx, tenantID, report, assetMap)
	}

	// Step 2: Process dependencies/components (SBOM)
	if s.compRepo != nil && s.componentProcessor != nil && len(report.Dependencies) > 0 {
		if err := s.componentProcessor.ProcessBatch(ctx, tenantID, report, assetMap, output); err != nil {
			s.logger.Error("failed to process components batch", "error", err)
			// Continue with partial results
		}
	}

	// Step 2b: Upsert CVE catalog entries from findings. Protocol v2 only
	// reads the catalog: a sensor never writes the global vulnerability
	// catalog (RFC-026 §5.3); it is written by trusted feeds.
	var (
		cveMap map[string]shared.ID
		cveErr error
	)
	if opts.NoCatalogWrites {
		cveMap, cveErr = s.cveProcessor.LookupBatch(ctx, report)
	} else {
		cveMap, cveErr = s.cveProcessor.ProcessBatch(ctx, report, output)
	}
	if cveErr != nil {
		s.logger.Warn("CVE upsert failed; findings will not be linked to vulnerability catalog",
			"error", cveErr)
		cveMap = map[string]shared.ID{}
		// Record the failure so the audit log reflects partial/failed rather than
		// completed: every finding here persists with a nil VulnerabilityID, and
		// createIngestAuditLog derives run status from len(output.Errors). Without
		// this the degraded run was silently audited as a success.
		addError(output, fmt.Sprintf("cve upsert failed: %v", cveErr))
	}

	// Step 2c: Process findings using batch operations (if findingRepo is available)
	if s.findingRepo != nil && len(report.Findings) > 0 {
		if err := s.findingProcessor.processBatch(ctx, agt, tenantID, report, assetMap, tenantRules, output, cveMap, opts.RequireAssetForFindings, scope); err != nil {
			s.logger.Error("failed to process findings batch", "error", err)
			// Continue with partial results
		}
		if report.Tool != nil {
			s.auditSourceResolve(ctx, tenantID, binding, report.Tool.Name, output)
		}
	}

	// Step 2d: takeover-template findings confirm open dangling CNAMEs
	// (RFC-036 P1); command-bound reports only. Best-effort.
	s.confirmTakeovers(ctx, agt, tenantID, binding, scope, report, assetMap)

	// Step 3: a protocol v1 report never closes findings (research 18 F3). A
	// scan closes default-branch findings only through the per-command
	// evaluation of a protocol v2 run (evaluateRepoCoverage): the command
	// completed with exit 0, nothing was rejected, the same tool and scan
	// profile, behind the blinding guard. A v1 report proves none of that,
	// and an unbound report or a tenant upload never closes (owner decision
	// O11). The per-branch occurrence sweep below is unchanged.
	if !opts.DeferAutoResolve && s.findingRepo != nil && report.Tool != nil && input.ShouldAutoResolve() {
		s.logger.Info("auto-resolve skipped: only a protocol v2 run bound to a command closes findings",
			"tool_name", sanitizeIngestLogField(report.Tool.Name), "binding", binding.String())
	}

	// Step 3b: Per-branch occurrence auto-resolve (branch-aware occurrence model).
	// Unlike the finding-level auto-resolve above (default branch only), this runs
	// for ANY full-coverage scan and marks occurrences on the SCANNED branch that
	// the scan no longer reports as auto_fixed — so per-branch state reflects what
	// is actually present on that branch. Additive: it only touches occurrence
	// rows, never the finding's headline status. Best-effort.
	if !opts.DeferAutoResolve && unsolicitedMayResolve && !scope.actorRestricted() && input.IsFullCoverage() && s.findingRepo != nil && s.branchRepo != nil &&
		report.Tool != nil && report.Metadata.ID != "" &&
		report.Metadata.Branch != nil && report.Metadata.Branch.Name != "" {
		toolName := report.Tool.Name
		scanID := report.Metadata.ID
		branchName := report.Metadata.Branch.Name
		for _, assetID := range assetMap {
			if (binding.Kind == BindingCommand || binding.Kind == BindingCIRun) && !scope.allowedAsset(assetID) {
				continue
			}
			br, err := s.branchRepo.GetByName(ctx, assetID, branchName)
			if err != nil || br == nil {
				continue // not a repository asset / branch not tracked — skip
			}
			n, err := s.findingRepo.AutoResolveStaleBranchOccurrences(ctx, tenantID, br.ID(), toolName, scanID)
			if err != nil {
				s.logger.Warn("failed to auto-resolve stale branch occurrences",
					"asset_id", assetID.String(), "branch", branchName, "error", err)
			} else if n > 0 {
				s.logger.Info("auto-resolved stale branch occurrences",
					"asset_id", assetID.String(), "branch", branchName, "count", n)
			}
		}
	}

	// Step 4: Update asset finding counts
	if len(assetMap) > 0 {
		assetIDs := make([]shared.ID, 0, len(assetMap))
		for _, id := range assetMap {
			assetIDs = append(assetIDs, id)
		}
		if err := s.assetProcessor.UpdateFindingCounts(ctx, tenantID, assetIDs); err != nil {
			s.logger.Warn("failed to update finding counts", "error", err)
		}
	}

	// Step 5: Update sensor statistics (with proper error handling). A v2
	// report counts once, when it completes (recordV2ReportStats).
	if !opts.DeferSensorStats {
		s.updateSensorStatsAsync(agt.ID, output)
	}

	s.logger.Info("ingestion complete",
		"report_id", output.ReportID,
		"assets_created", output.AssetsCreated,
		"assets_updated", output.AssetsUpdated,
		"findings_created", output.FindingsCreated,
		"findings_updated", output.FindingsUpdated,
		"findings_auto_resolved", output.FindingsAutoResolved,
		"findings_auto_reopened", output.FindingsAutoReopened,
		"components_created", output.ComponentsCreated,
		"dependencies_linked", output.DependenciesLinked,
		"errors", len(output.Errors),
	)

	recordWithheld(output)

	// Step 6: Create audit log for ingestion
	s.createIngestAuditLog(ctx, agt, tenantID, report, output)

	return output, nil
}

// projectAssetExposures re-loads the recon-discovered assets (open ports,
// exposed services, TLS certificates) by their AUTHORITATIVE persisted ids and
// hands them to the exposure projector. Loading by persisted id (from assetMap,
// already reconciled to the ids the DB actually wrote) keeps the exposure→asset
// FK valid. Best-effort: any error is logged and never aborts ingest.
func (s *Service) projectAssetExposures(ctx context.Context, tenantID shared.ID, report *ctis.Report, assetMap map[string]shared.ID) {
	if s.assetRepo == nil || len(assetMap) == 0 {
		return
	}

	// Select the persisted ids of the exposure-relevant asset types only, so a
	// non-recon scan (which produces none) does no extra work.
	seen := make(map[shared.ID]bool)
	ids := make([]shared.ID, 0)
	for i := range report.Assets {
		switch report.Assets[i].Type {
		case ctis.AssetTypeOpenPort, ctis.AssetTypeService, ctis.AssetTypeHTTPService, ctis.AssetTypeCertificate:
			id, ok := assetMap[report.Assets[i].ID]
			if !ok || id.IsZero() || seen[id] {
				continue
			}
			seen[id] = true
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return
	}

	assets := make([]*asset.Asset, 0, len(ids))
	for _, id := range ids {
		a, err := s.assetRepo.GetByID(ctx, tenantID, id)
		if err != nil {
			s.logger.Warn("failed to load asset for exposure projection",
				"asset_id", id.String(), "error", err)
			continue
		}
		assets = append(assets, a)
	}
	if len(assets) == 0 {
		return
	}

	if err := s.assetExposureProjector.ProjectAssets(ctx, tenantID, assets); err != nil {
		s.logger.Warn("asset exposure projection failed", "error", err)
	}
}

// CheckFingerprints checks which fingerprints already exist in the database.
func (s *Service) CheckFingerprints(ctx context.Context, agt *sensor.Sensor, input CheckFingerprintsInput) (*CheckFingerprintsOutput, error) {
	// Platform sensors must have tenant context from job assignment
	if agt.TenantID == nil {
		return nil, fmt.Errorf("sensor has no tenant context: platform sensors require job assignment")
	}
	tenantID := *agt.TenantID

	existing, missing, err := s.findingProcessor.CheckFingerprints(ctx, tenantID, input.Fingerprints)
	if err != nil {
		return nil, err
	}

	return &CheckFingerprintsOutput{
		Existing: existing,
		Missing:  missing,
	}, nil
}

// NewVsBase computes which of the given fingerprints are new relative to a PR's
// base/target branch (RFC-008 Phase 3). A finding already open on the base
// branch is pre-existing tech debt — not introduced by the PR — so a PR gate /
// inline comments should focus on the genuinely-new set. Tenant-scoped via the
// authenticated sensor. If the repository or base branch is unknown (no history),
// every fingerprint is treated as new.
func (s *Service) BaselineDiff(ctx context.Context, agt *sensor.Sensor, input BaselineDiffInput) (*BaselineDiffOutput, error) {
	if agt == nil || agt.TenantID == nil {
		return nil, fmt.Errorf("sensor has no tenant context: platform sensors require job assignment")
	}
	tenantID := *agt.TenantID

	allNew := func() *BaselineDiffOutput {
		return &BaselineDiffOutput{New: append([]string{}, input.Fingerprints...), BaseBranchKnown: false}
	}

	if len(input.Fingerprints) == 0 {
		return &BaselineDiffOutput{New: []string{}, BaseBranchKnown: false}, nil
	}
	if input.Repository == "" || input.BaseBranch == "" || s.assetRepo == nil || s.branchRepo == nil || s.findingRepo == nil {
		return allNew(), nil
	}

	repoAsset, err := s.assetRepo.GetByName(ctx, tenantID, input.Repository)
	if err != nil || repoAsset == nil {
		return allNew(), nil // unknown repo → no base history
	}
	baseBranch, err := s.branchRepo.GetByName(ctx, repoAsset.ID(), input.BaseBranch)
	if err != nil || baseBranch == nil {
		return allNew(), nil // base branch never scanned → all new
	}

	openOnBase, err := s.findingRepo.FingerprintsOpenOnBranch(ctx, tenantID, baseBranch.ID(), input.Fingerprints)
	if err != nil {
		return nil, fmt.Errorf("query fingerprints open on base branch: %w", err)
	}

	newFps, preFps := partitionByBaseline(input.Fingerprints, openOnBase)
	return &BaselineDiffOutput{New: newFps, PreExisting: preFps, BaseBranchKnown: true}, nil
}

// partitionByBaseline splits fingerprints into those NOT already open on the
// base branch (new — introduced by the PR) and those that are (pre-existing).
func partitionByBaseline(fingerprints, openOnBase []string) (newFps, preExisting []string) {
	pre := make(map[string]bool, len(openOnBase))
	for _, fp := range openOnBase {
		pre[fp] = true
	}
	newFps = make([]string, 0, len(fingerprints))
	preExisting = make([]string, 0, len(openOnBase))
	for _, fp := range fingerprints {
		if pre[fp] {
			preExisting = append(preExisting, fp)
		} else {
			newFps = append(newFps, fp)
		}
	}
	return newFps, preExisting
}

// =============================================================================
// Validation Methods
// =============================================================================

// reservedAutoResolveTools are tool names stamped on findings that do NOT come
// from a sensor-run scanner (platform imports, pentest / manual entry). An
// sensor-pushed report claiming one of these names must never drive
// auto-resolve: the "not seen in this scan" sweep would close another source's
// findings. Compared case-insensitively.
var reservedAutoResolveTools = map[string]struct{}{
	"defectdojo":     {}, // DefectDojo platform import
	"pentest":        {},
	"pentest-manual": {}, // pentest campaign findings
	"manual":         {},
	"burp_suite":     {}, // Burp XML import (pentest)
	"csv_import":     {}, // CSV finding import (pentest)
}

// validateSensor checks if the sensor is valid for ingestion.
func (s *Service) validateSensor(agt *sensor.Sensor) error {
	if agt == nil {
		return shared.NewDomainError("UNAUTHORIZED", "sensor authentication required", shared.ErrUnauthorized)
	}

	if agt.TenantID == nil {
		return shared.NewDomainError(CodeNoTenantContext, "sensor has no tenant context: platform sensors require job assignment", nil)
	}

	// Check sensor status
	if !agt.Status.CanAuthenticate() {
		return shared.NewDomainError("FORBIDDEN", "sensor is not active", shared.ErrForbidden)
	}

	return nil
}

// =============================================================================
// Helper Methods
// =============================================================================

// updateSensorStatsAsync updates sensor statistics asynchronously with proper error handling.
func (s *Service) updateSensorStatsAsync(sensorID shared.ID, output *Output) {
	// Skip for synthetic ingests with no real sensor (e.g. tenant-initiated
	// .nessus upload via the synthetic-sensor path) — there is no sensor row to
	// update, and a zero ID would just produce a no-op write + a noisy warning.
	if sensorID.IsZero() {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		s.statsUpdateMu.Lock()
		defer s.statsUpdateMu.Unlock()

		if err := s.sensorRepo.IncrementStats(
			ctx,
			sensorID,
			int64(output.FindingsCreated),
			1, // scans
			int64(len(output.Errors)),
		); err != nil {
			s.logger.Warn("failed to update sensor stats", "sensor_id", sensorID.String(), "error", err)
		}
	}()
}

// recordV2ReportStats adds a completed protocol v2 report to its sensor's
// totals, as a v1 ingest does: one scan, the findings it accepted and its item
// errors. Finalization runs once per report, so a report counts once however
// many segments or retries it took. A failed update is logged, not returned:
// the report is already complete.
func (s *Service) recordV2ReportStats(ctx context.Context, rep *ingestreport.Report) {
	if s.sensorRepo == nil || rep == nil || rep.SensorID.IsZero() {
		return
	}
	var findings, errs int64
	for _, o := range rep.Outcomes {
		findings += int64(o.AcceptedFindings)
		errs += int64(len(o.Errors))
	}
	if err := s.sensorRepo.IncrementStats(ctx, rep.SensorID, findings, 1, errs); err != nil {
		s.logger.Warn("failed to update sensor stats", "sensor_id", rep.SensorID.String(), "error", err)
	}
}

// createIngestAuditLog creates an audit log entry for the ingestion result.
// This provides visibility for debugging when ingestion has issues.
func (s *Service) createIngestAuditLog(ctx context.Context, agt *sensor.Sensor, tenantID shared.ID, report *ctis.Report, output *Output) {
	if s.auditSvc == nil && s.auditRepo == nil {
		return
	}

	// Determine action based on result
	action := audit.ActionIngestCompleted
	result := audit.ResultSuccess
	if len(output.Errors) > 0 {
		if output.FindingsCreated > 0 || output.FindingsUpdated > 0 {
			action = audit.ActionIngestPartialSuccess
		} else {
			action = audit.ActionIngestFailed
			result = audit.ResultFailure
		}
	}

	// Create resource ID from report metadata
	resourceID := output.ReportID
	if resourceID == "" {
		resourceID = UnknownValue
	}

	// Build tool name for display
	toolName := UnknownValue
	if report.Tool != nil && report.Tool.Name != "" {
		toolName = report.Tool.Name
	}

	// Build message
	var message string
	switch action {
	case audit.ActionIngestCompleted:
		message = fmt.Sprintf("Ingestion completed: %d findings created, %d updated", output.FindingsCreated, output.FindingsUpdated)
	case audit.ActionIngestPartialSuccess:
		message = fmt.Sprintf("Ingestion partial success: %d findings created, %d updated, %d errors", output.FindingsCreated, output.FindingsUpdated, len(output.Errors))
	case audit.ActionIngestFailed:
		message = fmt.Sprintf("Ingestion failed: %d errors", len(output.Errors))
	}

	metadata := map[string]any{
		"sensor_id":              agt.ID.String(),
		"sensor_name":            agt.Name,
		"report_id":              output.ReportID,
		"source_type":            report.Metadata.SourceType,
		"findings_count":         len(report.Findings),
		"findings_created":       output.FindingsCreated,
		"findings_updated":       output.FindingsUpdated,
		"findings_skipped":       output.FindingsSkipped,
		"findings_auto_resolved": output.FindingsAutoResolved,
		"findings_auto_reopened": output.FindingsAutoReopened,
		"assets_created":         output.AssetsCreated,
		"assets_updated":         output.AssetsUpdated,
		"error_count":            len(output.Errors),
		"binding":                output.Binding,
	}
	if output.AssetsLimited > 0 {
		metadata["assets_limited"] = output.AssetsLimited
	}
	if output.ReopensWithheld > 0 {
		metadata["reopens_withheld"] = output.ReopensWithheld
	}
	if output.UnsolicitedWarned {
		// Tenant mode warn: quarantine mode would have held this report.
		metadata["unsolicited_warned"] = true
	}

	// Include first few errors for debugging (limit to 5 to avoid huge audit logs)
	if len(output.Errors) > 0 {
		errorsToInclude := output.Errors
		if len(errorsToInclude) > 5 {
			errorsToInclude = errorsToInclude[:5]
		}
		metadata["errors"] = errorsToInclude
	}

	// Include detailed info about failed findings (limit to 10 for audit log size)
	if len(output.FailedFindings) > 0 {
		failedToInclude := output.FailedFindings
		if len(failedToInclude) > 10 {
			failedToInclude = failedToInclude[:10]
		}
		// Convert to map slice for JSON serialization
		failedDetails := make([]map[string]any, len(failedToInclude))
		for i, ff := range failedToInclude {
			failedDetails[i] = map[string]any{
				"index":       ff.Index,
				"fingerprint": ff.Fingerprint,
				"rule_id":     ff.RuleID,
				"file_path":   ff.FilePath,
				"line":        ff.Line,
				"error":       ff.Error,
			}
		}
		metadata["failed_findings"] = failedDetails
		metadata["failed_findings_total"] = len(output.FailedFindings)
	}

	// Include branch info if available
	if report.Metadata.Branch != nil {
		metadata["branch_name"] = report.Metadata.Branch.Name
		metadata["is_default_branch"] = report.Metadata.Branch.IsDefaultBranch
		if report.Metadata.Branch.CommitSHA != "" {
			metadata["commit_sha"] = report.Metadata.Branch.CommitSHA
		}
	}

	actx := auditapp.AuditContext{TenantID: tenantID.String()}
	event := auditapp.AuditEvent{
		Action:       action,
		ResourceType: audit.ResourceTypeIngest,
		ResourceID:   resourceID,
		ResourceName: toolName,
		Result:       result,
		Message:      message,
		Metadata:     metadata,
	}

	// Persist asynchronously so ingest does not block on the audit write.
	//
	// Concurrency: LogEvent takes the shared AuditService.chainMu before
	// reading prev_hash and appending, so concurrent ingests for the same
	// tenant are serialized exactly like synchronous request-path audit
	// events. Detached from the request context — the audit must outlive
	// the request — but capped so a stalled DB cannot pin the goroutine.
	go func() {
		auditCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := s.writeIngestAuditLog(auditCtx, actx, event); err != nil {
			s.logger.Warn("failed to persist ingest audit log",
				"error", err,
				"action", action,
				"report_id", logger.SanitizeValue(resourceID),
			)
		}
	}()
}

// writeIngestAuditLog persists one ingest audit event.
//
// Preferred path is the shared audit service, which persists the log AND
// extends the tenant's tamper-evident hash chain. The direct-repository
// path is a degraded fallback for callers that never wired the service; it
// leaves the row unchained, so it warns loudly rather than failing silently
// (an unchained tenant-scoped row is indistinguishable from a deleted one
// when the hourly verifier walks the chain).
func (s *Service) writeIngestAuditLog(ctx context.Context, actx auditapp.AuditContext, event auditapp.AuditEvent) error {
	if s.auditSvc != nil {
		return s.auditSvc.LogEvent(ctx, actx, event)
	}

	s.logger.Warn("ingest audit service not wired; audit log will bypass the tamper-evident hash chain",
		"action", event.Action.String(),
		"tenant_id", actx.TenantID,
		"alert", "audit_chain_bypassed",
	)

	auditLog, err := audit.NewAuditLog(event.Action, event.ResourceType, event.ResourceID, event.Result)
	if err != nil {
		return fmt.Errorf("build ingest audit log: %w", err)
	}
	if tenantID, err := shared.IDFromString(actx.TenantID); err == nil {
		auditLog.WithTenantID(tenantID)
	}
	auditLog.WithResourceName(event.ResourceName).WithMessage(event.Message)
	for k, v := range event.Metadata {
		auditLog.WithMetadata(k, v)
	}
	return s.auditRepo.Create(ctx, auditLog)
}

// =============================================================================
// Utility Functions
// =============================================================================

// UnmarshalReport parses a CTIS report from JSON bytes.
func UnmarshalReport(data []byte) (*ctis.Report, error) {
	var report ctis.Report
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("failed to unmarshal CTIS report: %w", err)
	}
	return &report, nil
}
