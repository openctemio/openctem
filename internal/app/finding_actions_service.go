package app

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"

	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/domain/accesscontrol"
	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/group"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/pagination"
)

// VerificationScanTrigger is the interface for triggering targeted verification scans.
// Implemented by the scan.Service; kept as interface to avoid import cycles.
type VerificationScanTrigger interface {
	// TriggerVerificationScan launches a quick scan on the given targets.
	// targets is a list of asset identifiers (names / hostnames / URLs).
	// Returns the pipeline run ID and scan ID on success.
	TriggerVerificationScan(ctx context.Context, tenantID, createdBy, scannerName, workflowID string, targets []string) (pipelineRunID, scanID string, err error)
}

// FindingActionsService handles the closed-loop finding lifecycle:
// in_progress → fix_applied → resolved (verified by scan or security).
type FindingActionsService struct {
	findingRepo     vulnerability.FindingRepository
	accessCtrlRepo  accesscontrol.Repository
	groupRepo       group.Repository
	assetRepo       asset.Repository
	activityService *FindingActivityService
	scanTrigger     VerificationScanTrigger // optional; set via SetVerificationScanTrigger
	db              *sql.DB
	logger          *logger.Logger
}

// NewFindingActionsService creates a new FindingActionsService.
func NewFindingActionsService(
	findingRepo vulnerability.FindingRepository,
	accessCtrlRepo accesscontrol.Repository,
	groupRepo group.Repository,
	assetRepo asset.Repository,
	activityService *FindingActivityService,
	db *sql.DB,
	logger *logger.Logger,
) *FindingActionsService {
	return &FindingActionsService{
		findingRepo:     findingRepo,
		accessCtrlRepo:  accessCtrlRepo,
		groupRepo:       groupRepo,
		assetRepo:       assetRepo,
		activityService: activityService,
		db:              db,
		logger:          logger,
	}
}

// loadVerificationChecklist loads the structured closure checklist for a
// finding. Returns (nil, nil) when the row is absent — the caller passes
// that through to TransitionStatusWithChecklist, which will reject the
// transition with ErrValidation if a checklist was required.
//
// F4 (Q2/WS-E): gates FixApplied → Resolved / Resolved → Verified on the
// tenant's verification checklist. Checklist rows are owned by the HTTP
// handler (raw SQL on finding_verification_checklists); this loader is
// the read-only backdoor the service layer uses to enforce the gate
// without introducing a new domain repository.
func (s *FindingActionsService) loadVerificationChecklist(
	ctx context.Context,
	tenantID, findingID shared.ID,
) (*vulnerability.VerificationChecklist, error) {
	const q = `
		SELECT id, tenant_id, finding_id, exposure_cleared, evidence_attached,
		       register_updated, monitoring_added, regression_scheduled,
		       COALESCE(notes, ''), completed_by, completed_at,
		       created_at, updated_at
		FROM finding_verification_checklists
		WHERE tenant_id = $1 AND finding_id = $2
	`
	var (
		data                vulnerability.VerificationChecklistData
		monitoringAdded     sql.NullBool
		regressionScheduled sql.NullBool
		completedBy         sql.NullString
		completedAt         sql.NullTime
		idStr, tidStr, fidStr string
	)
	err := s.db.QueryRowContext(ctx, q, tenantID.String(), findingID.String()).Scan(
		&idStr, &tidStr, &fidStr,
		&data.ExposureCleared, &data.EvidenceAttached, &data.RegisterUpdated,
		&monitoringAdded, &regressionScheduled,
		&data.Notes, &completedBy, &completedAt,
		&data.CreatedAt, &data.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows { //nolint:errorlint
			return nil, nil
		}
		return nil, fmt.Errorf("load verification checklist: %w", err)
	}
	data.ID, _ = shared.IDFromString(idStr)
	data.TenantID, _ = shared.IDFromString(tidStr)
	data.FindingID, _ = shared.IDFromString(fidStr)
	if monitoringAdded.Valid {
		v := monitoringAdded.Bool
		data.MonitoringAdded = &v
	}
	if regressionScheduled.Valid {
		v := regressionScheduled.Bool
		data.RegressionScheduled = &v
	}
	if completedBy.Valid {
		if id, err := shared.IDFromString(completedBy.String); err == nil {
			data.CompletedBy = &id
		}
	}
	if completedAt.Valid {
		t := completedAt.Time
		data.CompletedAt = &t
	}
	return vulnerability.ReconstituteVerificationChecklist(data), nil
}

// SetVerificationScanTrigger wires the scan trigger (called after both services are initialized).
func (s *FindingActionsService) SetVerificationScanTrigger(trigger VerificationScanTrigger) {
	s.scanTrigger = trigger
}

// --- Group View ---

// ListFindingGroups returns findings grouped by a dimension.
func (s *FindingActionsService) ListFindingGroups(
	ctx context.Context, tenantID string, groupBy string, filter vulnerability.FindingFilter, page pagination.Pagination,
) (pagination.Result[*vulnerability.FindingGroup], error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return pagination.Result[*vulnerability.FindingGroup]{}, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	validDimensions := map[string]bool{
		"cve_id": true, "asset_id": true, "owner_id": true,
		"component_id": true, "severity": true, "source": true, "finding_type": true,
	}
	if !validDimensions[groupBy] {
		return pagination.Result[*vulnerability.FindingGroup]{}, fmt.Errorf("%w: invalid group_by: %s", shared.ErrValidation, groupBy)
	}

	filter.TenantID = &tid
	return s.findingRepo.ListFindingGroups(ctx, tid, groupBy, filter, page)
}

// --- Related CVEs ---

// GetRelatedCVEs finds CVEs that share the same component as the given CVE.
func (s *FindingActionsService) GetRelatedCVEs(
	ctx context.Context, tenantID string, cveID string, filter vulnerability.FindingFilter,
) ([]vulnerability.RelatedCVE, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	if err := validateCVEID(cveID); err != nil {
		return nil, err
	}

	return s.findingRepo.FindRelatedCVEs(ctx, tid, cveID, filter)
}

// --- Bulk Fix Applied ---

// BulkFixAppliedInput is the input for bulk fix-applied operation.
type BulkFixAppliedInput struct {
	Filter            vulnerability.FindingFilter
	IncludeRelatedCVEs bool
	Note              string // REQUIRED
	Reference         string // optional (commit hash, patch ID)
}

// BulkFixAppliedResult is the result of bulk fix-applied operation.
type BulkFixAppliedResult struct {
	Updated        int            `json:"updated"`
	Skipped        int            `json:"skipped"`
	ByCVE          map[string]int `json:"by_cve,omitempty"`
	AssetsAffected int            `json:"assets_affected"`
}

// BulkFixApplied marks findings as fix_applied.
// Authorization: user must be assignee, group member, or asset owner for each finding.
func (s *FindingActionsService) BulkFixApplied(
	ctx context.Context, tenantID string, userID string, input BulkFixAppliedInput,
) (*BulkFixAppliedResult, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	uid, err := shared.IDFromString(userID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid user id", shared.ErrValidation)
	}

	// Validate note required
	if input.Note == "" {
		return nil, fmt.Errorf("%w: note is required when marking fix applied", shared.ErrValidation)
	}

	// Validate CVE IDs format
	for _, cve := range input.Filter.CVEIDs {
		if err := validateCVEID(cve); err != nil {
			return nil, err
		}
	}

	// Include related CVEs if requested
	if input.IncludeRelatedCVEs && len(input.Filter.CVEIDs) > 0 {
		relatedCVEs, err := s.findingRepo.FindRelatedCVEs(ctx, tid, input.Filter.CVEIDs[0], input.Filter)
		if err != nil {
			s.logger.Warn("failed to find related CVEs", "error", err)
		} else {
			for _, rc := range relatedCVEs {
				input.Filter.CVEIDs = append(input.Filter.CVEIDs, rc.CVEID)
			}
		}
	}

	// Ensure we only target in_progress findings
	input.Filter.Statuses = []vulnerability.FindingStatus{vulnerability.FindingStatusInProgress}
	input.Filter.TenantID = &tid

	// Count preview — cap at 1000
	count, err := s.findingRepo.Count(ctx, input.Filter)
	if err != nil {
		return nil, fmt.Errorf("failed to count findings: %w", err)
	}
	if count > 1000 {
		return nil, fmt.Errorf("%w: too many findings (%d), max 1000. Use a narrower filter", shared.ErrValidation, count)
	}
	if count == 0 {
		return &BulkFixAppliedResult{}, nil
	}

	// Preload user's group IDs (1 query — avoid N+1)
	userGroupIDs, err := s.groupRepo.ListGroupIDsByUser(ctx, tid, uid)
	if err != nil {
		s.logger.Warn("failed to load user groups", "error", err)
		userGroupIDs = nil
	}
	groupIDSet := make(map[shared.ID]bool, len(userGroupIDs))
	for _, gid := range userGroupIDs {
		groupIDSet[gid] = true
	}

	// Fetch all findings first to preload related data
	result := &BulkFixAppliedResult{ByCVE: make(map[string]int)}
	assetSet := make(map[shared.ID]bool)

	// Collect all findings (cap already checked at 1000)
	allFindings := make([]*vulnerability.Finding, 0, int(count))
	const batchSize = 100
	for offset := int64(0); offset < count; offset += batchSize {
		page := pagination.New(int(batchSize), int(offset))
		findings, err := s.findingRepo.List(ctx, input.Filter, vulnerability.NewFindingListOptions(), page)
		if err != nil {
			return nil, fmt.Errorf("failed to list findings: %w", err)
		}
		allFindings = append(allFindings, findings.Data...)
	}

	// Preload finding→group assignments (1 batch query, not N+1)
	findingIDs := make([]shared.ID, len(allFindings))
	for i, f := range allFindings {
		findingIDs[i] = f.ID()
	}
	findingGroupMap, err := s.accessCtrlRepo.BatchListFindingGroupIDs(ctx, tid, findingIDs)
	if err != nil {
		s.logger.Warn("failed to batch load finding groups", "error", err)
		findingGroupMap = make(map[shared.ID][]shared.ID)
	}

	// Preload asset→owner (deduplicated by asset ID)
	assetOwnerMap := make(map[shared.ID]*shared.ID)
	seenAssets := make(map[shared.ID]bool)
	for _, f := range allFindings {
		if seenAssets[f.AssetID()] {
			continue
		}
		seenAssets[f.AssetID()] = true
		assetEntity, err := s.assetRepo.GetByID(ctx, tid, f.AssetID())
		if err == nil {
			ownerID := assetEntity.OwnerID()
			assetOwnerMap[f.AssetID()] = ownerID
		}
	}

	// Process findings with preloaded data (all auth checks in-memory)
	for _, f := range allFindings {
		if !s.canMarkFixApplied(uid, groupIDSet, findingGroupMap, assetOwnerMap, f) {
			result.Skipped++
			continue
		}

		// Transition status
		if err := f.TransitionStatus(vulnerability.FindingStatusFixApplied, input.Note, &uid); err != nil {
			result.Skipped++
			continue
		}

		if err := s.findingRepo.Update(ctx, f); err != nil {
			s.logger.Warn("failed to update finding", "finding_id", f.ID(), "error", err)
			result.Skipped++
			continue
		}

		result.Updated++
		result.ByCVE[f.CVEID()]++
		assetSet[f.AssetID()] = true
	}

	result.AssetsAffected = len(assetSet)
	return result, nil
}

// canMarkFixApplied checks if a user can mark a finding as fix_applied.
// User must be: direct assignee, member of assigned group, or asset owner.
// findingGroupMap and assetOwnerMap are preloaded to avoid N+1 queries.
func (s *FindingActionsService) canMarkFixApplied(
	userID shared.ID,
	userGroupIDs map[shared.ID]bool,
	findingGroupMap map[shared.ID][]shared.ID, // finding ID → assigned group IDs
	assetOwnerMap map[shared.ID]*shared.ID, // asset ID → owner ID
	finding *vulnerability.Finding,
) bool {
	// 1. Direct assignee
	if finding.AssignedTo() != nil && *finding.AssignedTo() == userID {
		return true
	}

	// 2. Member of assigned group (in-memory via preloaded map)
	if groupIDs, ok := findingGroupMap[finding.ID()]; ok {
		for _, gid := range groupIDs {
			if userGroupIDs[gid] {
				return true
			}
		}
	}

	// 3. Asset owner (in-memory via preloaded map)
	if ownerID, ok := assetOwnerMap[finding.AssetID()]; ok && ownerID != nil && *ownerID == userID {
		return true
	}

	return false
}

// --- Bulk Verify ---

// BulkVerify resolves fix_applied findings (manual security review).
func (s *FindingActionsService) BulkVerify(
	ctx context.Context, tenantID string, userID string, findingIDs []string, note string,
) (*BulkUpdateResult, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	result := &BulkUpdateResult{}

	for _, idStr := range findingIDs {
		fid, err := shared.IDFromString(idStr)
		if err != nil {
			result.Failed++
			result.Errors = append(result.Errors, fmt.Sprintf("%s: invalid id", idStr))
			continue
		}

		f, err := s.findingRepo.GetByID(ctx, tid, fid)
		if err != nil {
			result.Failed++
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", idStr, err))
			continue
		}

		if f.Status() != vulnerability.FindingStatusFixApplied {
			result.Failed++
			result.Errors = append(result.Errors, fmt.Sprintf("%s: not in fix_applied status", idStr))
			continue
		}

		resolution := "Verified by security review"
		if note != "" {
			resolution = note
		}

		uid, uidErr := shared.IDFromString(userID)
		if uidErr != nil {
			return nil, fmt.Errorf("%w: invalid user id", shared.ErrValidation)
		}
		// F4: FixApplied → Resolved goes through the checklist gate. A
		// missing/incomplete checklist is returned to the operator so
		// they can fill it before retrying — the domain layer owns
		// the rejection message.
		checklist, err := s.loadVerificationChecklist(ctx, tid, fid)
		if err != nil {
			result.Failed++
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", idStr, err))
			continue
		}
		if err := f.TransitionStatusWithChecklist(vulnerability.FindingStatusResolved, resolution, &uid, checklist); err != nil {
			result.Failed++
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", idStr, err))
			continue
		}
		if err := f.SetResolutionMethod(string(vulnerability.ResolutionMethodSecurityReviewed)); err != nil {
			result.Failed++
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", idStr, err))
			continue
		}

		if err := s.findingRepo.Update(ctx, f); err != nil {
			result.Failed++
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", idStr, err))
			continue
		}

		result.Updated++
	}

	return result, nil
}

// --- Bulk Reject Fix ---

// BulkRejectFix reopens fix_applied findings (fix was incorrect).
func (s *FindingActionsService) BulkRejectFix(
	ctx context.Context, tenantID string, userID string, findingIDs []string, reason string,
) (*BulkUpdateResult, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	if reason == "" {
		return nil, fmt.Errorf("%w: reason is required when rejecting fix", shared.ErrValidation)
	}

	result := &BulkUpdateResult{}

	uid, uidErr := shared.IDFromString(userID)
	if uidErr != nil {
		return nil, fmt.Errorf("%w: invalid user id", shared.ErrValidation)
	}

	for _, idStr := range findingIDs {
		fid, err := shared.IDFromString(idStr)
		if err != nil {
			result.Failed++
			result.Errors = append(result.Errors, fmt.Sprintf("%s: invalid id", idStr))
			continue
		}

		f, err := s.findingRepo.GetByID(ctx, tid, fid)
		if err != nil {
			result.Failed++
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", idStr, err))
			continue
		}

		if f.Status() != vulnerability.FindingStatusFixApplied {
			result.Failed++
			result.Errors = append(result.Errors, fmt.Sprintf("%s: not in fix_applied status (current: %s)", idStr, f.Status()))
			continue
		}

		if err := f.TransitionStatus(vulnerability.FindingStatusInProgress, reason, &uid); err != nil {
			result.Failed++
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", idStr, err))
			continue
		}

		if err := s.findingRepo.Update(ctx, f); err != nil {
			result.Failed++
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", idStr, err))
			continue
		}

		result.Updated++
	}

	return result, nil
}

// --- Verify/Reject by Filter (for Pending Review tab) ---

// VerifyByFilterInput is the input for bulk verify by filter.
type VerifyByFilterInput struct {
	Filter vulnerability.FindingFilter
	Note   string
}

// BulkVerifyByFilter resolves all fix_applied findings matching a filter.
// Used by Pending Review tab to approve entire groups at once.
func (s *FindingActionsService) BulkVerifyByFilter(
	ctx context.Context, tenantID string, userID string, input VerifyByFilterInput,
) (int64, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return 0, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	uid, err := shared.IDFromString(userID)
	if err != nil {
		return 0, fmt.Errorf("%w: invalid user id", shared.ErrValidation)
	}

	// Force filter to only fix_applied findings + apply data scope
	input.Filter.Statuses = []vulnerability.FindingStatus{vulnerability.FindingStatusFixApplied}
	input.Filter.TenantID = &tid
	input.Filter.DataScopeUserID = &uid // SEC-01: enforce data scope

	resolution := "Verified by security review"
	if input.Note != "" {
		resolution = input.Note
	}

	count, err := s.findingRepo.BulkUpdateStatusByFilter(ctx, tid, input.Filter,
		vulnerability.FindingStatusResolved, resolution, &uid)
	if err != nil {
		return 0, fmt.Errorf("failed to verify findings: %w", err)
	}

	return count, nil
}

// RejectByFilterInput is the input for bulk reject by filter.
type RejectByFilterInput struct {
	Filter vulnerability.FindingFilter
	Reason string
}

// BulkRejectByFilter reopens all fix_applied findings matching a filter.
func (s *FindingActionsService) BulkRejectByFilter(
	ctx context.Context, tenantID string, userID string, input RejectByFilterInput,
) (int64, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return 0, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	uid, err := shared.IDFromString(userID)
	if err != nil {
		return 0, fmt.Errorf("%w: invalid user id", shared.ErrValidation)
	}

	if input.Reason == "" {
		return 0, fmt.Errorf("%w: reason is required when rejecting fix", shared.ErrValidation)
	}

	input.Filter.Statuses = []vulnerability.FindingStatus{vulnerability.FindingStatusFixApplied}
	input.Filter.TenantID = &tid
	input.Filter.DataScopeUserID = &uid // SEC-01: enforce data scope

	count, err := s.findingRepo.BulkUpdateStatusByFilter(ctx, tid, input.Filter,
		vulnerability.FindingStatusInProgress, input.Reason, &uid)
	if err != nil {
		return 0, fmt.Errorf("failed to reject findings: %w", err)
	}

	return count, nil
}

// --- Auto-Assign to Owners ---

// AutoAssignToOwnersResult is the result of auto-assign operation.
type AutoAssignToOwnersResult struct {
	Assigned   int            `json:"assigned"`
	ByOwner    map[string]int `json:"by_owner"`
	Unassigned int            `json:"unassigned"`
}

// AutoAssignToOwners assigns findings to their asset owners.
// Only assigns findings that don't already have an assignee.
func (s *FindingActionsService) AutoAssignToOwners(
	ctx context.Context, tenantID string, assignerID string, filter vulnerability.FindingFilter,
) (*AutoAssignToOwnersResult, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	aid, err := shared.IDFromString(assignerID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid assigner id", shared.ErrValidation)
	}

	filter.TenantID = &tid
	result := &AutoAssignToOwnersResult{ByOwner: make(map[string]int)}

	const batchSize = 100
	for offset := 0; ; offset += batchSize {
		page := pagination.New(batchSize, offset)
		findings, err := s.findingRepo.List(ctx, filter, vulnerability.NewFindingListOptions(), page)
		if err != nil {
			return nil, fmt.Errorf("failed to list findings: %w", err)
		}
		if len(findings.Data) == 0 {
			break
		}

		for _, f := range findings.Data {
			// Skip already assigned
			if f.AssignedTo() != nil {
				continue
			}

			// Get asset owner
			assetEntity, err := s.assetRepo.GetByID(ctx, f.TenantID(), f.AssetID())
			if err != nil {
				continue
			}

			ownerID := assetEntity.OwnerID()
			if ownerID == nil {
				result.Unassigned++
				continue
			}

			if err := f.Assign(*ownerID, aid); err != nil {
				continue
			}

			// Auto-transition to in_progress if still new/confirmed
			if f.Status() == vulnerability.FindingStatusNew || f.Status() == vulnerability.FindingStatusConfirmed {
				_ = f.TransitionStatus(vulnerability.FindingStatusInProgress, "", nil)
			}

			if err := s.findingRepo.Update(ctx, f); err != nil {
				s.logger.Warn("failed to assign finding", "finding_id", f.ID(), "error", err)
				continue
			}

			result.Assigned++
			result.ByOwner[assetEntity.Name()]++
		}
	}

	_ = aid // suppress unused
	return result, nil
}

// --- Verification Scan ---

// RequestVerificationScanInput is the input for requesting a verification scan.
type RequestVerificationScanInput struct {
	FindingID   string
	ScannerName string // required if WorkflowID is empty
	WorkflowID  string // required if ScannerName is empty
}

// RequestVerificationScanResult is the result of requesting a verification scan.
type RequestVerificationScanResult struct {
	FindingID     string `json:"finding_id"`
	AssetID       string `json:"asset_id"`
	AssetName     string `json:"asset_name"`
	PipelineRunID string `json:"pipeline_run_id"`
	ScanID        string `json:"scan_id"`
}

// RequestVerificationScan triggers a targeted quick scan on the asset associated with a finding.
// The finding must be in fix_applied status (dev has marked it as fixed; awaiting scan verification).
// The scan result is expected to either confirm the fix (→ resolved) or reveal the vuln still exists
// (→ back to in_progress) via the normal ingest pipeline.
func (s *FindingActionsService) RequestVerificationScan(
	ctx context.Context, tenantID, userID string, input RequestVerificationScanInput,
) (*RequestVerificationScanResult, error) {
	if s.scanTrigger == nil {
		return nil, fmt.Errorf("%w: verification scan trigger not configured", shared.ErrInternal)
	}

	if input.ScannerName == "" && input.WorkflowID == "" {
		return nil, fmt.Errorf("%w: scanner_name or workflow_id is required", shared.ErrValidation)
	}

	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant_id", shared.ErrValidation)
	}

	fid, err := shared.IDFromString(input.FindingID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid finding_id", shared.ErrValidation)
	}

	f, err := s.findingRepo.GetByID(ctx, tid, fid)
	if err != nil {
		return nil, fmt.Errorf("finding not found: %w", err)
	}

	if f.Status() != vulnerability.FindingStatusFixApplied {
		return nil, fmt.Errorf(
			"%w: finding must be in fix_applied status to request verification scan (current: %s)",
			shared.ErrValidation, f.Status(),
		)
	}

	assetEntity, err := s.assetRepo.GetByID(ctx, tid, f.AssetID())
	if err != nil {
		return nil, fmt.Errorf("asset not found for finding: %w", err)
	}

	targets := []string{assetEntity.Name()}

	runID, scanID, err := s.scanTrigger.TriggerVerificationScan(
		ctx, tenantID, userID, input.ScannerName, input.WorkflowID, targets,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to trigger verification scan: %w", err)
	}

	s.logger.Info("verification scan triggered",
		"finding_id", f.ID(),
		"asset_id", f.AssetID(),
		"asset_name", assetEntity.Name(),
		"pipeline_run_id", runID,
		"scan_id", scanID,
	)

	return &RequestVerificationScanResult{
		FindingID:     f.ID().String(),
		AssetID:       f.AssetID().String(),
		AssetName:     assetEntity.Name(),
		PipelineRunID: runID,
		ScanID:        scanID,
	}, nil
}

// --- Validation helpers ---

var cveIDRegex = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

func validateCVEID(cveID string) error {
	if !cveIDRegex.MatchString(cveID) {
		return fmt.Errorf("%w: invalid CVE ID format: %s (expected CVE-YYYY-NNNNN)", shared.ErrValidation, cveID)
	}
	return nil
}
