package ingest

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/pkg/domain/agent"
	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/audit"
	"github.com/openctemio/api/pkg/domain/branch"
	"github.com/openctemio/api/pkg/domain/component"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/tenant"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/sdk-go/pkg/ctis"
)

// Service handles ingestion of assets and findings from various formats.
// This is the unified service that uses CTIS as the internal format.
// Supported input formats: CTIS (native), SARIF (via SDK converter), Recon (via SDK converter).
type Service struct {
	assetProcessor     *AssetProcessor
	findingProcessor   *FindingProcessor
	componentProcessor *ComponentProcessor
	validator          *Validator

	assetRepo   asset.Repository
	findingRepo vulnerability.FindingRepository
	compRepo    component.Repository
	agentRepo   agent.Repository
	branchRepo  branch.Repository
	tenantRepo  tenant.Repository
	auditRepo   audit.Repository

	logger *logger.Logger

	// statsUpdateMu protects concurrent stats updates
	statsUpdateMu sync.Mutex
}

// NewService creates a new unified ingest service.
func NewService(
	assetRepo asset.Repository,
	findingRepo vulnerability.FindingRepository,
	compRepo component.Repository,
	agentRepo agent.Repository,
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
		validator:          NewValidator(),

		assetRepo:   assetRepo,
		findingRepo: findingRepo,
		compRepo:    compRepo,
		agentRepo:   agentRepo,
		branchRepo:  branchRepo,
		tenantRepo:  tenantRepo,
		auditRepo:   auditRepo,

		logger: l,
	}
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

// SetFindingCreatedCallback sets the callback for when findings are created.
// This is used to trigger workflows when new findings are ingested.
func (s *Service) SetFindingCreatedCallback(callback FindingCreatedCallback) {
	s.findingProcessor.SetFindingCreatedCallback(callback)
}

// =============================================================================
// Main Ingestion Methods
// =============================================================================

// Ingest processes a CTIS report from an agent.
// This is the main entry point for all ingestion.
//
//nolint:cyclop // Ingestion dispatches to multiple processors with validation
func (s *Service) Ingest(ctx context.Context, agt *agent.Agent, input Input) (*Output, error) {
	// Validate agent context
	if err := s.validateAgent(agt); err != nil {
		return nil, err
	}
	tenantID := *agt.TenantID

	report := input.Report
	if report == nil {
		return nil, shared.NewDomainError("INVALID_INPUT", "report is required", nil)
	}

	fmt.Printf("%+v\n", report)

	// Validate report limits
	if err := s.validator.ValidateReport(report); err != nil {
		return nil, err
	}

	s.logger.Info("ingesting report",
		"agent_id", agt.ID.String(),
		"tenant_id", tenantID.String(),
		"report_id", report.Metadata.ID,
		"source_type", report.Metadata.SourceType,
		"assets_count", len(report.Assets),
		"findings_count", len(report.Findings),
	)

	output := &Output{
		ReportID: report.Metadata.ID,
	}

	// Step 1: Process assets using batch operations
	assetMap, err := s.assetProcessor.ProcessBatch(ctx, tenantID, report, output)
	if err != nil {
		s.logger.Error("failed to process assets batch", "error", err)
		// Continue with partial results
	}

	s.logger.Debug("asset processing complete",
		"assets_created", output.AssetsCreated,
		"assets_updated", output.AssetsUpdated,
		"asset_map_size", len(assetMap),
	)

	// Load tenant branch type rules for configurable branch detection
	var tenantRules branch.BranchTypeRules
	if s.tenantRepo != nil {
		if t, err := s.tenantRepo.GetByID(ctx, tenantID); err == nil && t != nil {
			tenantRules = t.TypedSettings().Branch.TypeRules
		}
	}

	// Step 2: Process findings using batch operations (if findingRepo is available)
	if s.findingRepo != nil && len(report.Findings) > 0 {
		if err := s.findingProcessor.ProcessBatch(ctx, agt, tenantID, report, assetMap, tenantRules, output); err != nil {
			s.logger.Error("failed to process findings batch", "error", err)
			// Continue with partial results
		}
	}

	// Step 2b: Process dependencies/components (SBOM)
	if s.compRepo != nil && s.componentProcessor != nil && len(report.Dependencies) > 0 {
		if err := s.componentProcessor.ProcessBatch(ctx, tenantID, report, assetMap, output); err != nil {
			s.logger.Error("failed to process components batch", "error", err)
			// Continue with partial results
		}
	}

	// Step 3: Auto-resolve stale findings (only for full coverage scans on default branch)
	// This marks findings as 'resolved' if they were not seen in this scan.
	// Protected statuses (false_positive, accepted) are never auto-resolved.
	//
	// Auto-resolve conditions (all must be true):
	// 1. CoverageType = full (not incremental or partial)
	// 2. Scan is on default branch (main/master) - feature branch scans never auto-resolve
	// 3. Tool name available for scoping
	//
	// This follows GitHub/GitLab best practices where default branch is source of truth.
	if input.ShouldAutoResolve() && s.findingRepo != nil && report.Tool != nil {
		toolName := report.Tool.Name
		scanID := report.Metadata.ID

		s.logger.Info("auto-resolve enabled for default branch full scan",
			"tool_name", toolName,
			"scan_id", scanID,
			"branch", input.GetBranchInfo().Name,
		)

		for _, assetID := range assetMap {
			// Pass nil for branchID to auto-resolve findings on any default branch.
			// In the future, we can look up the specific branch and pass its ID.
			resolvedIDs, err := s.findingRepo.AutoResolveStale(ctx, tenantID, assetID, toolName, scanID, nil)
			if err != nil {
				s.logger.Warn("failed to auto-resolve stale findings",
					"asset_id", assetID.String(),
					"tool_name", toolName,
					"error", err,
				)
			} else if len(resolvedIDs) > 0 {
				output.FindingsAutoResolved += len(resolvedIDs)
				app.FindingsAutoResolved.WithLabelValues(tenantID.String()).Add(float64(len(resolvedIDs)))
				s.logger.Info("auto-resolved stale findings",
					"asset_id", assetID.String(),
					"tool_name", toolName,
					"count", len(resolvedIDs),
				)
				// TODO: Create activity records for auto-resolved findings
			}
		}
	} else if s.findingRepo != nil && report.Tool != nil {
		// Log why auto-resolve was skipped
		branchInfo := input.GetBranchInfo()
		switch {
		case branchInfo == nil:
			s.logger.Debug("auto-resolve skipped: no branch info provided")
		case !branchInfo.IsDefaultBranch:
			s.logger.Debug("auto-resolve skipped: not default branch",
				"branch", branchInfo.Name,
			)
		default:
			coverageType := input.CoverageType
			if coverageType == "" && report.Metadata.CoverageType != "" {
				coverageType = CoverageType(report.Metadata.CoverageType)
			}
			s.logger.Debug("auto-resolve skipped: coverage type not full",
				"coverage_type", coverageType,
			)
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

	// Step 5: Update agent statistics (with proper error handling)
	s.updateAgentStatsAsync(agt.ID, output)

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

	// Step 6: Create audit log for ingestion
	s.createIngestAuditLog(ctx, agt, tenantID, report, output)

	return output, nil
}

// IngestSARIF processes a SARIF log and ingests it as findings.
func (s *Service) IngestSARIF(ctx context.Context, agt *agent.Agent, sarifData []byte) (*Output, error) {
	s.logger.Info("ingesting SARIF data",
		"agent_id", agt.ID.String(),
	)

	// Convert SARIF to CTIS using SDK
	report, err := ctis.FromSARIF(sarifData, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SARIF: %w", err)
	}

	// Use the unified ingestion pipeline
	return s.Ingest(ctx, agt, Input{Report: report})
}

// IngestRecon processes recon data and ingests it.
func (s *Service) IngestRecon(ctx context.Context, agt *agent.Agent, reconInput *ctis.ReconToCTISInput) (*Output, error) {
	s.logger.Info("ingesting recon data",
		"agent_id", agt.ID.String(),
	)

	// Convert Recon to CTIS using SDK
	opts := ctis.DefaultReconConverterOptions()
	opts.DiscoverySource = "agent"
	report, err := ctis.ConvertReconToCTIS(reconInput, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to convert recon data: %w", err)
	}

	// Use the unified ingestion pipeline
	return s.Ingest(ctx, agt, Input{Report: report})
}

// CheckFingerprints checks which fingerprints already exist in the database.
func (s *Service) CheckFingerprints(ctx context.Context, agt *agent.Agent, input CheckFingerprintsInput) (*CheckFingerprintsOutput, error) {
	// Platform agents must have tenant context from job assignment
	if agt.TenantID == nil {
		return nil, fmt.Errorf("agent has no tenant context: platform agents require job assignment")
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

// =============================================================================
// Validation Methods
// =============================================================================

// validateAgent checks if the agent is valid for ingestion.
func (s *Service) validateAgent(agt *agent.Agent) error {
	if agt == nil {
		return shared.NewDomainError("UNAUTHORIZED", "agent authentication required", shared.ErrUnauthorized)
	}

	if agt.TenantID == nil {
		return shared.NewDomainError("INVALID_AGENT", "agent has no tenant context: platform agents require job assignment", nil)
	}

	// Check agent status
	if !agt.Status.CanAuthenticate() {
		return shared.NewDomainError("FORBIDDEN", "agent is not active", shared.ErrForbidden)
	}

	return nil
}

// =============================================================================
// Helper Methods
// =============================================================================

// updateAgentStatsAsync updates agent statistics asynchronously with proper error handling.
func (s *Service) updateAgentStatsAsync(agentID shared.ID, output *Output) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		s.statsUpdateMu.Lock()
		defer s.statsUpdateMu.Unlock()

		if err := s.agentRepo.IncrementStats(
			ctx,
			agentID,
			int64(output.FindingsCreated),
			1, // scans
			int64(len(output.Errors)),
		); err != nil {
			s.logger.Warn("failed to update agent stats", "agent_id", agentID.String(), "error", err)
		}
	}()
}

// createIngestAuditLog creates an audit log entry for the ingestion result.
// This provides visibility for debugging when ingestion has issues.
func (s *Service) createIngestAuditLog(ctx context.Context, agt *agent.Agent, tenantID shared.ID, report *ctis.Report, output *Output) {
	if s.auditRepo == nil {
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

	// Create audit log entry
	auditLog, err := audit.NewAuditLog(action, audit.ResourceTypeIngest, resourceID, result)
	if err != nil {
		s.logger.Warn("failed to create ingest audit log", "error", err)
		return
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

	// Set audit log fields
	auditLog.WithTenantID(tenantID).
		WithResourceName(toolName).
		WithMessage(message).
		WithMetadata("agent_id", agt.ID.String()).
		WithMetadata("agent_name", agt.Name).
		WithMetadata("report_id", output.ReportID).
		WithMetadata("source_type", report.Metadata.SourceType).
		WithMetadata("findings_count", len(report.Findings)).
		WithMetadata("findings_created", output.FindingsCreated).
		WithMetadata("findings_updated", output.FindingsUpdated).
		WithMetadata("findings_skipped", output.FindingsSkipped).
		WithMetadata("findings_auto_resolved", output.FindingsAutoResolved).
		WithMetadata("findings_auto_reopened", output.FindingsAutoReopened).
		WithMetadata("assets_created", output.AssetsCreated).
		WithMetadata("assets_updated", output.AssetsUpdated).
		WithMetadata("error_count", len(output.Errors))

	// Include first few errors for debugging (limit to 5 to avoid huge audit logs)
	if len(output.Errors) > 0 {
		errorsToInclude := output.Errors
		if len(errorsToInclude) > 5 {
			errorsToInclude = errorsToInclude[:5]
		}
		auditLog.WithMetadata("errors", errorsToInclude)
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
		auditLog.WithMetadata("failed_findings", failedDetails)
		auditLog.WithMetadata("failed_findings_total", len(output.FailedFindings))
	}

	// Include branch info if available
	if report.Metadata.Branch != nil {
		auditLog.WithMetadata("branch_name", report.Metadata.Branch.Name)
		auditLog.WithMetadata("is_default_branch", report.Metadata.Branch.IsDefaultBranch)
		if report.Metadata.Branch.CommitSHA != "" {
			auditLog.WithMetadata("commit_sha", report.Metadata.Branch.CommitSHA)
		}
	}

	// Create audit log asynchronously to not block the response
	go func() {
		auditCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := s.auditRepo.Create(auditCtx, auditLog); err != nil {
			s.logger.Warn("failed to persist ingest audit log",
				"error", err,
				"action", action,
				"report_id", resourceID,
			)
		}
	}()
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
