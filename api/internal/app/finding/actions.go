// Package finding implements the application service for the finding bounded context — orchestrates pkg/domain/finding entities and cross-cutting concerns (audit, notifications, RBAC).
package finding

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"

	"github.com/openctemio/openctem/api/internal/app/activity"
	"github.com/openctemio/openctem/api/internal/app/datascope"
	"github.com/openctemio/openctem/api/internal/app/validation"
	"github.com/openctemio/openctem/api/pkg/domain/accesscontrol"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/group"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// AutoValidator dispatches a CTEM Stage-4 safe-check re-check for a finding and
// returns the command ID it was queued under. Implemented by
// *validation.RunService. When wired, marking findings fix_applied auto-queues a
// proof-of-fix re-check so a "fixed" claim is verified rather than trusted.
type AutoValidator interface {
	ValidateFinding(ctx context.Context, tenantID, findingID shared.ID) (shared.ID, error)
}

// FindingActionsService handles the closed-loop finding lifecycle:
// in_progress → fix_applied → resolved (verified by scan or security).
type FindingActionsService struct {
	findingRepo     vulnerability.FindingRepository
	accessCtrlRepo  accesscontrol.Repository
	groupRepo       group.Repository
	assetRepo       asset.Repository
	activityService *activity.FindingActivityService
	autoValidator   AutoValidator       // optional; set via SetAutoValidator
	dataScope       *datascope.Enforcer // optional; Layer 2 scope on by-id actions
	db              *sql.DB
	logger          *logger.Logger
}

// NewFindingActionsService creates a new FindingActionsService.
func NewFindingActionsService(
	findingRepo vulnerability.FindingRepository,
	accessCtrlRepo accesscontrol.Repository,
	groupRepo group.Repository,
	assetRepo asset.Repository,
	activityService *activity.FindingActivityService,
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

// SetDataScope wires the Layer 2 data-scope enforcer for the by-id bulk
// actions (verify / reject-fix) and the fix-applied filter. Nil leaves it off.
func (s *FindingActionsService) SetDataScope(e *datascope.Enforcer) {
	s.dataScope = e
}

// loadVerificationChecklist loads the structured closure checklist for a
// finding. Returns (nil, nil) when the row is absent — the caller passes
// that through to TransitionStatusWithChecklist, which will reject the
// transition with ErrValidation if a checklist was required.
//
// F4: gates FixApplied → Resolved / Resolved → Verified on the
// tenant's verification checklist. Checklist rows are owned by the HTTP
// handler (raw SQL on finding_verification_checklists); this loader is
// the read-only backdoor the service layer uses to enforce the gate
// without introducing a new domain repository.
func (s *FindingActionsService) loadVerificationChecklist(
	ctx context.Context,
	tenantID, findingID shared.ID,
) (*vulnerability.VerificationChecklist, error) {
	return loadVerificationChecklist(ctx, s.db, tenantID, findingID)
}

// loadVerificationChecklist is the package-level, dependency-free loader used by
// both FindingActionsService.BulkVerify and VulnerabilityService.UpdateFindingStatus
// so the F4 verification-checklist gate is enforced identically on the bulk and
// single-finding resolve paths. Returns (nil, nil) when the row is absent.
func loadVerificationChecklist(
	ctx context.Context,
	db *sql.DB,
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
		data                  vulnerability.VerificationChecklistData
		monitoringAdded       sql.NullBool
		regressionScheduled   sql.NullBool
		completedBy           sql.NullString
		completedAt           sql.NullTime
		idStr, tidStr, fidStr string
	)
	err := db.QueryRowContext(ctx, q, tenantID.String(), findingID.String()).Scan(
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

// SetAutoValidator wires the proof-of-fix auto-validator. When set, a successful
// fix_applied transition auto-queues a proof-of-fix check per finding (bounded,
// best-effort): a retest of the finding's own template for a nuclei finding
// (RFC-039), a plain validation re-check otherwise. Optional: nil → none.
func (s *FindingActionsService) SetAutoValidator(v AutoValidator) {
	s.autoValidator = v
}

// maxAutoValidations bounds how many proof-of-fix re-checks a single
// fix_applied batch may auto-queue, so a large bulk remediation cannot flood
// the platform-job queue. Findings beyond the cap are left for manual
// validation (POST /findings/{id}/validate).
const maxAutoValidations = 100

// autoQueueValidations best-effort dispatches a safe-check re-check for each
// freshly fix_applied finding. Non-network assets (code/cloud/container) are
// skipped silently via ErrNotNetworkAddressable; any other error is logged and
// never affects the caller's result. Returns the number of jobs queued.
func (s *FindingActionsService) autoQueueValidations(ctx context.Context, tenantID shared.ID, findingIDs []shared.ID) int {
	if s.autoValidator == nil || len(findingIDs) == 0 {
		return 0
	}
	queued := 0
	for _, fid := range findingIDs {
		if queued >= maxAutoValidations {
			s.logger.Info("proof-of-fix auto-validation capped",
				"tenant_id", tenantID.String(), "cap", maxAutoValidations,
				"remaining", len(findingIDs)-maxAutoValidations)
			break
		}
		if _, err := s.autoValidator.ValidateFinding(ctx, tenantID, fid); err != nil {
			// No validation sensor is a tenant-wide condition: the rest of the
			// batch would answer identically, so log once and stop rather than
			// re-querying per finding. Observable (not silent) — and self-heals
			// the moment a validation sensor comes online.
			if errors.Is(err, validation.ErrNoValidationSensor) {
				s.logger.Info("proof-of-fix auto-validation skipped: no validation-capable sensor online",
					"tenant_id", tenantID.String(), "pending", len(findingIDs)-queued)
				break
			}
			// Non-network assets are the common, expected case — don't log noise.
			if !errors.Is(err, validation.ErrNotNetworkAddressable) {
				s.logger.Warn("proof-of-fix auto-validation failed",
					"tenant_id", tenantID.String(), "finding_id", fid.String(), "error", err)
			}
			continue
		}
		queued++
	}
	return queued
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
		"cve_id": true, "rule_id": true, "asset_id": true, "owner_id": true,
		"component_id": true, "severity": true, "source": true, "finding_type": true,
	}
	if !validDimensions[groupBy] {
		return pagination.Result[*vulnerability.FindingGroup]{}, fmt.Errorf("%w: invalid group_by: %s", shared.ErrValidation, groupBy)
	}

	filter, err = s.visibleTo(ctx, tid, filter)
	if err != nil {
		return pagination.Result[*vulnerability.FindingGroup]{}, err
	}
	return s.findingRepo.ListFindingGroups(ctx, tid, groupBy, filter, page)
}

// visibleTo narrows a filter to the findings the request's caller may see,
// with the rules the findings list applies: the Layer 2 data scope (resolved
// by the shared enforcer, so admins, internal calls and the organization's
// policy for members without an access group behave the same everywhere),
// and pentest findings only for members of their campaign.
func (s *FindingActionsService) visibleTo(
	ctx context.Context, tid shared.ID, filter vulnerability.FindingFilter,
) (vulnerability.FindingFilter, error) {
	return visibleFilter(ctx, s.dataScope, tid, filter)
}

// visibleFilter pins filter to tid and narrows it to what the request's
// caller may see: the enforcer's data scope and the findings list's
// pentest-membership rule. Shared by every filter-driven finding path so none
// sets the scope fields by hand.
func visibleFilter(
	ctx context.Context, e *datascope.Enforcer, tid shared.ID, filter vulnerability.FindingFilter,
) (vulnerability.FindingFilter, error) {
	filter.TenantID = &tid
	scope, err := e.Resolve(ctx, tid)
	if err != nil {
		return filter, fmt.Errorf("failed to resolve data scope: %w", err)
	}
	filter = filter.WithDataScope(scope)
	if c := e.CallerOf(ctx); !c.IsAdmin && c.UserID != "" {
		if uid, err := shared.IDFromString(c.UserID); err == nil {
			filter = filter.WithPentestMemberOrNonPentest(uid)
		}
	}
	return filter, nil
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

	filter, err = s.visibleTo(ctx, tid, filter)
	if err != nil {
		return nil, err
	}
	return s.findingRepo.FindRelatedCVEs(ctx, tid, cveID, filter)
}

// --- Bulk Fix Applied ---

// BulkFixAppliedInput is the input for bulk fix-applied operation.
type BulkFixAppliedInput struct {
	Filter             vulnerability.FindingFilter
	IncludeRelatedCVEs bool
	Note               string // REQUIRED
	Reference          string // optional (commit hash, patch ID)
}

// BulkFixAppliedResult is the result of bulk fix-applied operation.
type BulkFixAppliedResult struct {
	Updated           int            `json:"updated"`
	Skipped           int            `json:"skipped"` // not permitted / invalid transition (expected)
	Failed            int            `json:"failed"`  // persistence error — retry-worthy, distinct from Skipped
	ByCVE             map[string]int `json:"by_cve,omitempty"`
	AssetsAffected    int            `json:"assets_affected"`
	ValidationsQueued int            `json:"validations_queued"` // proof-of-fix safe-check re-checks auto-dispatched
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

	// Layer 2: only findings in the caller's data scope — also when looking
	// up related CVEs, so out-of-scope findings do not widen the CVE list.
	input.Filter, err = s.visibleTo(ctx, tid, input.Filter)
	if err != nil {
		return nil, err
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
	fixedIDs := make([]shared.ID, 0, int(count)) // findings that reached fix_applied → auto-validate

	// Collect all findings (cap already checked at 1000)
	allFindings := make([]*vulnerability.Finding, 0, int(count))
	const batchSize = 100
	// pagination.New is (page, perPage) — page is 1-based. Walk pages, not
	// offsets (an earlier version passed (batchSize, offset), which clamped
	// perPage and skewed OFFSET, fetching the wrong rows).
	for offset := int64(0); offset < count; offset += batchSize {
		page := pagination.New(int(offset/batchSize)+1, batchSize)
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

	// Preload the assets this user owns (1 query). asset_owners is the only
	// owner store: a primary or secondary user owner of the asset is "the
	// asset owner" for this check.
	ownedAssets := s.assetsOwnedBy(ctx, tid, uid, allFindings)

	// Process findings with preloaded data (all auth checks in-memory)
	for _, f := range allFindings {
		if !s.canMarkFixApplied(uid, groupIDSet, findingGroupMap, ownedAssets, f) {
			result.Skipped++
			continue
		}

		// Transition status
		if err := f.TransitionStatus(vulnerability.FindingStatusFixApplied, input.Note, &uid); err != nil {
			result.Skipped++
			continue
		}

		if err := s.findingRepo.Update(ctx, f); err != nil {
			// A persistence failure is NOT a skip — count it separately so the
			// caller can distinguish "not permitted / invalid" (Skipped) from
			// "write failed, the fix_applied transition was lost, retry" (Failed).
			s.logger.Warn("failed to update finding", "finding_id", f.ID(), "error", err)
			result.Failed++
			continue
		}

		result.Updated++
		result.ByCVE[f.CVEID()]++
		assetSet[f.AssetID()] = true
		fixedIDs = append(fixedIDs, f.ID())
	}

	result.AssetsAffected = len(assetSet)

	// Closed-loop CTEM: auto-queue a proof-of-fix safe-check re-check per fixed
	// finding so a "fix applied" claim is verified, not trusted. Bounded and
	// best-effort — never affects the fix_applied result above.
	result.ValidationsQueued = s.autoQueueValidations(ctx, tid, fixedIDs)

	return result, nil
}

// canMarkFixApplied checks if a user can mark a finding as fix_applied.
// User must be: direct assignee, member of assigned group, or asset owner.
// findingGroupMap and assetOwnerMap are preloaded to avoid N+1 queries.
func (s *FindingActionsService) canMarkFixApplied(
	userID shared.ID,
	userGroupIDs map[shared.ID]bool,
	findingGroupMap map[shared.ID][]shared.ID, // finding ID → assigned group IDs
	ownedAssets map[shared.ID]bool, // assets the user is a primary or secondary owner of
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

	// 3. Asset owner (in-memory via preloaded set)
	if ownedAssets[finding.AssetID()] {
		return true
	}

	return false
}

// assetsOwnedBy returns the assets of the findings that the user is a primary
// or secondary owner of (asset_owners, one query). A lookup failure is logged
// and yields no owned assets, so the owner path never widens on error.
func (s *FindingActionsService) assetsOwnedBy(ctx context.Context, tenantID, userID shared.ID, findings []*vulnerability.Finding) map[shared.ID]bool {
	if s.accessCtrlRepo == nil || len(findings) == 0 {
		return map[shared.ID]bool{}
	}
	seen := make(map[shared.ID]bool, len(findings))
	assetIDs := make([]shared.ID, 0, len(findings))
	for _, f := range findings {
		if !seen[f.AssetID()] {
			seen[f.AssetID()] = true
			assetIDs = append(assetIDs, f.AssetID())
		}
	}
	owned, err := s.accessCtrlRepo.FilterAssetsOwnedByUser(ctx, tenantID, userID, assetIDs)
	if err != nil {
		s.logger.Warn("failed to load the user's owned assets", "error", err)
		return map[shared.ID]bool{}
	}
	return owned
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
		if err == nil && s.dataScope.AssertAsset(ctx, tid, f.AssetID()) != nil {
			// Layer 2: an out-of-scope finding reads exactly as a missing one.
			err = vulnerability.FindingNotFoundError(fid)
		}
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
		if err == nil && s.dataScope.AssertAsset(ctx, tid, f.AssetID()) != nil {
			// Layer 2: an out-of-scope finding reads exactly as a missing one.
			err = vulnerability.FindingNotFoundError(fid)
		}
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
	input.Filter, err = s.visibleTo(ctx, tid, input.Filter)
	if err != nil {
		return 0, err
	}

	resolution := "Verified by security review"
	if input.Note != "" {
		resolution = input.Note
	}

	count, err := s.findingRepo.BulkUpdateStatusByFilter(ctx, tid, input.Filter,
		vulnerability.FindingStatusResolved, resolution, &uid, vulnerability.ResolutionMethodSecurityReviewed)
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
	input.Filter, err = s.visibleTo(ctx, tid, input.Filter)
	if err != nil {
		return 0, err
	}

	count, err := s.findingRepo.BulkUpdateStatusByFilter(ctx, tid, input.Filter,
		vulnerability.FindingStatusInProgress, input.Reason, &uid, "")
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

	// Only findings the caller may see: the enforcer's scope (admins and the
	// organization's policy for members without a group as everywhere else)
	// and pentest findings only for members of their campaign.
	filter, err = s.visibleTo(ctx, tid, filter)
	if err != nil {
		return nil, err
	}
	result := &AutoAssignToOwnersResult{ByOwner: make(map[string]int)}

	// Cache asset lookups by ID across all pages so repeated findings on the same
	// asset don't re-query it (mirror BulkFixApplied's dedup). Many findings
	// typically share one asset, so this collapses an N+1 into one query/asset.
	type assetInfo struct {
		ownerID *shared.ID
		name    string
		found   bool
	}
	assetCache := make(map[shared.ID]assetInfo)

	const batchSize = 100
	// pagination.New is (page, perPage) — page is 1-based. Iterate by page;
	// the prior (batchSize, offset) call clamped perPage and pinned OFFSET to
	// a fixed window, which skipped findings and could loop forever.
	for page := 1; ; page++ {
		pg := pagination.New(page, batchSize)
		findings, err := s.findingRepo.List(ctx, filter, vulnerability.NewFindingListOptions(), pg)
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

			// Get asset owner (cached — dedup repeated assets across pages)
			info, ok := assetCache[f.AssetID()]
			if !ok {
				if assetEntity, err := s.assetRepo.GetByID(ctx, f.TenantID(), f.AssetID()); err == nil {
					// The assignee is the asset's primary user owner in
					// asset_owners (the one owner model). A group primary is
					// not an assignee.
					var ownerID *shared.ID
					if s.accessCtrlRepo != nil {
						owners, oErr := s.accessCtrlRepo.GetPrimaryUserOwnersByAssetIDs(ctx, f.TenantID(), []shared.ID{f.AssetID()})
						if oErr != nil {
							s.logger.Warn("failed to load the asset's primary owner", "asset_id", f.AssetID(), "error", oErr)
						} else if uid, ok := owners[f.AssetID()]; ok {
							ownerID = &uid
						}
					}
					info = assetInfo{ownerID: ownerID, name: assetEntity.Name(), found: true}
				}
				assetCache[f.AssetID()] = info
			}
			if !info.found {
				continue
			}

			if info.ownerID == nil {
				result.Unassigned++
				continue
			}

			if err := f.Assign(*info.ownerID, aid); err != nil {
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
			result.ByOwner[info.name]++
		}
	}

	return result, nil
}

// --- Validation helpers ---

var cveIDRegex = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

func validateCVEID(cveID string) error {
	if !cveIDRegex.MatchString(cveID) {
		return fmt.Errorf("%w: invalid CVE ID format: %s (expected CVE-YYYY-NNNNN)", shared.ErrValidation, cveID)
	}
	return nil
}
