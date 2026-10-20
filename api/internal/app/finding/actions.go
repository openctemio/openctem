// Package finding implements the application service for the finding bounded context — orchestrates pkg/domain/finding entities and cross-cutting concerns (audit, notifications, RBAC).
package finding

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"

	lc "github.com/openctemio/openctem/api/pkg/domain/findinglifecycle"

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
	lifecycles      LifecycleSchemes // organization lifecycles (RFC-110); nil = the platform alone
	statusEffects   StatusEffects    // side effects of applied status moves; nil = proof-of-fix only
}

// SetStatusEffects wires the shared side effects of a status change
// (VulnerabilityService.AfterStatusMoves): every action that moves findings
// runs them once per finding it moved.
func (s *FindingActionsService) SetStatusEffects(e StatusEffects) { s.statusEffects = e }

// ticketSyncCtx puts the ticket status pushes of the linked findings among
// ids on ctx for the status write to queue with the moves.
func (s *FindingActionsService) ticketSyncCtx(ctx context.Context, tid shared.ID, ids []shared.ID) context.Context {
	if s.statusEffects == nil {
		return ctx
	}
	return s.statusEffects.TicketSyncContext(ctx, tid, ids)
}

// afterMoves runs the side effects of the moves an action applied and returns
// the proof-of-fix re-checks queued. Without the shared effects wired, a fix
// claim still queues its proof-of-fix re-check.
func (s *FindingActionsService) afterMoves(ctx context.Context, tid shared.ID, actorID string, moves []vulnerability.StatusMove) int {
	if len(moves) == 0 {
		return 0
	}
	if s.statusEffects != nil {
		return s.statusEffects.AfterStatusMoves(ctx, tid, actorID, moves)
	}
	claims := make([]shared.ID, 0, len(moves))
	for _, m := range moves {
		if m.New == vulnerability.FindingStatusFixApplied {
			claims = append(claims, m.FindingID)
		}
	}
	return s.autoQueueValidations(ctx, tid, claims)
}

// personActionCtx marks an action's status write as a person's decision with
// its timeline entry written in the same transaction (the transition
// trigger), naming the actor.
func personActionCtx(ctx context.Context, reason string, uid shared.ID, message string) context.Context {
	return vulnerability.WithPersonMove(vulnerability.WithStatusTransition(ctx, vulnerability.StatusTransition{
		Source: string(vulnerability.SourceAPI), Reason: reason, ActorType: "user", ActorID: uid.String(), Message: message,
	}))
}

// SetLifecycles wires the organization lifecycles: each action is then also
// decided by the scheme selected for the finding, which can only narrow it.
func (s *FindingActionsService) SetLifecycles(l LifecycleSchemes) { s.lifecycles = l }

func (s *FindingActionsService) lifecycleCandidates(ctx context.Context, tenantID shared.ID) ([]lc.Candidate, error) {
	if s.lifecycles == nil {
		return nil, nil
	}
	return s.lifecycles.Candidates(ctx, tenantID)
}

// actionAllowed decides one finding's move for an action route: the
// platform engine narrowed by the organization's lifecycle (the move lands
// on the target's default sub-status; action routes take no lifecycle
// fields, so a move that needs them is refused here).
func actionAllowed(ctx context.Context, cands []lc.Candidate, f *vulnerability.Finding, facts vulnerability.TransitionFacts,
	actor vulnerability.TransitionActor, to vulnerability.FindingStatus, note string,
) error {
	d, _ := lifecycleDecision(cands, f, facts, lifecycleActor(ctx, actor), lc.Target{Status: to})
	_, err := lifecycleError(d, note, nil)
	return err
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

// validGroupDimensions are the group_by values of the grouped view.
var validGroupDimensions = vulnerability.FindingGroupDimensions()

// ListFindingGroups returns findings grouped by a dimension.
func (s *FindingActionsService) ListFindingGroups(
	ctx context.Context, tenantID string, groupBy string, filter vulnerability.FindingFilter, page pagination.Pagination,
) (pagination.Result[*vulnerability.FindingGroup], error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return pagination.Result[*vulnerability.FindingGroup]{}, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	if !validGroupDimensions[groupBy] {
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
	return visibleFilterWith(ctx, e, tid, filter, e.Resolve)
}

// visibleFilterStrict is visibleFilter for a read that must never fall back
// to "unrestricted" when the enforcer is not wired: that is an error.
func visibleFilterStrict(
	ctx context.Context, e *datascope.Enforcer, tid shared.ID, filter vulnerability.FindingFilter,
) (vulnerability.FindingFilter, error) {
	return visibleFilterWith(ctx, e, tid, filter, e.ResolveStrict)
}

func visibleFilterWith(
	ctx context.Context, e *datascope.Enforcer, tid shared.ID, filter vulnerability.FindingFilter,
	resolve func(context.Context, shared.ID) (*shared.DataScope, error),
) (vulnerability.FindingFilter, error) {
	filter.TenantID = &tid
	scope, err := resolve(ctx, tid)
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

	// Process findings with preloaded data (all auth checks in-memory). The
	// transition engine decides each claim, with whose finding it is as a
	// fact (the route requires findings:fix_apply).
	actor := personActor(uid, TransitionPermissions{FixApply: true})
	cands, err := s.lifecycleCandidates(ctx, tid)
	if err != nil {
		return nil, err
	}
	byID := make(map[shared.ID]*vulnerability.Finding, len(allFindings))
	claimIDs := make([]shared.ID, 0, len(allFindings))
	for _, f := range allFindings {
		facts := transitionFactsOf(f)
		facts.CanClaimFix = s.canMarkFixApplied(uid, groupIDSet, findingGroupMap, ownedAssets, f)
		if actionAllowed(ctx, cands, f, facts, actor, vulnerability.FindingStatusFixApplied, input.Note) != nil {
			result.Skipped++
			continue
		}
		byID[f.ID()] = f
		claimIDs = append(claimIDs, f.ID())
	}

	// One status-guarded write (still in_progress), with the timeline entry
	// in the same transaction. A finding that moved on since it was read is
	// not claimed: counted as failed, so the caller can retry.
	moved, err := moveStatusBatch(s.ticketSyncCtx(personActionCtx(ctx, "fix_applied", uid, input.Note), tid, claimIDs), s.findingRepo, tid, claimIDs,
		[]vulnerability.FindingStatus{vulnerability.FindingStatusInProgress}, vulnerability.FindingStatusFixApplied, input.Note, &uid, vulnerability.Closure{})
	if err != nil {
		return nil, fmt.Errorf("failed to mark findings fix applied: %w", err)
	}
	result.Failed += len(claimIDs) - len(moved)
	for _, id := range moved {
		f := byID[id]
		result.Updated++
		result.ByCVE[f.CVEID()]++
		assetSet[f.AssetID()] = true
		fixedIDs = append(fixedIDs, id)
	}

	result.AssetsAffected = len(assetSet)

	// The side effects of each claim, once: workflow event, assignee
	// notification, ticket sync and a proof-of-fix re-check (a fix claim is
	// verified, not trusted). Best effort; never affects the result above.
	result.ValidationsQueued = s.afterMoves(ctx, tid, uid.String(),
		movesOf(fixedIDs, func(shared.ID) vulnerability.FindingStatus { return vulnerability.FindingStatusInProgress }, vulnerability.FindingStatusFixApplied))

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

// actionTarget is a finding an action by id may move, after its checks.
type actionTarget struct {
	ids []shared.ID
	old map[shared.ID]vulnerability.FindingStatus
}

func (t *actionTarget) add(id shared.ID, old vulnerability.FindingStatus) {
	if t.old == nil {
		t.old = map[shared.ID]vulnerability.FindingStatus{}
	}
	t.ids = append(t.ids, id)
	t.old[id] = old
}

// loadActionFinding reads one finding of a by-id action in the caller's data
// scope (out of scope reads as not found).
func (s *FindingActionsService) loadActionFinding(ctx context.Context, tid shared.ID, idStr string) (*vulnerability.Finding, error) {
	fid, err := shared.IDFromString(idStr)
	if err != nil {
		return nil, errors.New("invalid id")
	}
	f, err := s.findingRepo.GetByID(ctx, tid, fid)
	if err == nil && s.dataScope.AssertAsset(ctx, tid, f.AssetID()) != nil {
		// Layer 2: an out-of-scope finding reads exactly as a missing one.
		err = vulnerability.FindingNotFoundError(fid)
	}
	return f, err
}

// applyFixDecision writes a verifier's decision on the checked fix_applied
// findings in one status-guarded statement (still fix_applied) with the
// timeline entry in the same transaction, counts what it moved, reports a
// finding that moved on since it was read, and runs the side effects of the
// moves once.
func (s *FindingActionsService) applyFixDecision(ctx context.Context, tid, uid shared.ID, t actionTarget, reason string,
	to vulnerability.FindingStatus, note string, closure vulnerability.Closure, result *BulkUpdateResult,
) error {
	if len(t.ids) == 0 {
		return nil
	}
	moved, err := moveStatusBatch(s.ticketSyncCtx(personActionCtx(ctx, reason, uid, note), tid, t.ids), s.findingRepo, tid, t.ids,
		[]vulnerability.FindingStatus{vulnerability.FindingStatusFixApplied}, to, note, &uid, closure)
	if err != nil {
		return fmt.Errorf("failed to update findings: %w", err)
	}
	movedSet := make(map[shared.ID]bool, len(moved))
	for _, id := range moved {
		movedSet[id] = true
	}
	for _, id := range t.ids {
		if !movedSet[id] {
			result.fail(id.String(), "changed since it was read; reload and retry")
		}
	}
	result.Updated += len(moved)
	result.ValidationsQueued += s.afterMoves(ctx, tid, uid.String(),
		movesOf(moved, func(id shared.ID) vulnerability.FindingStatus { return t.old[id] }, to))
	return nil
}

// BulkVerify resolves fix_applied findings (manual security review).
func (s *FindingActionsService) BulkVerify(
	ctx context.Context, tenantID string, userID string, findingIDs []string, note string,
) (*BulkUpdateResult, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	uid, err := shared.IDFromString(userID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid user id", shared.ErrValidation)
	}
	cands, err := s.lifecycleCandidates(ctx, tid)
	if err != nil {
		return nil, err
	}
	resolution := "Verified by security review"
	if note != "" {
		resolution = note
	}

	result := &BulkUpdateResult{}
	var target actionTarget
	for _, idStr := range findingIDs {
		f, err := s.loadActionFinding(ctx, tid, idStr)
		if err != nil {
			result.fail(idStr, err.Error())
			continue
		}
		if f.Status() != vulnerability.FindingStatusFixApplied {
			result.fail(idStr, "not in fix_applied status")
			continue
		}
		// F4: FixApplied → Resolved goes through the checklist gate. A
		// missing/incomplete checklist is returned to the operator so
		// they can fill it before retrying — the domain layer owns
		// the rejection message.
		checklist, err := s.loadVerificationChecklist(ctx, tid, f.ID())
		if err != nil {
			result.fail(idStr, err.Error())
			continue
		}
		// The transition engine (the route requires findings:verify), with
		// the evidence the finding's risk asks for.
		facts := transitionFactsOf(f)
		if s.db != nil {
			if err := loadResolveEvidence(ctx, s.db, tid, f.ID(), &facts); err != nil {
				result.fail(idStr, err.Error())
				continue
			}
		}
		if err := actionAllowed(ctx, cands, f, facts, personActor(uid, TransitionPermissions{Verify: true}),
			vulnerability.FindingStatusResolved, resolution); err != nil {
			result.fail(idStr, err.Error())
			continue
		}
		// The domain checks the move and the checklist (in memory; the
		// write below is the guarded batch statement).
		if err := f.TransitionStatusWithChecklist(vulnerability.FindingStatusResolved, resolution, &uid, checklist); err != nil {
			result.fail(idStr, err.Error())
			continue
		}
		target.add(f.ID(), vulnerability.FindingStatusFixApplied)
	}

	if err := s.applyFixDecision(ctx, tid, uid, target, "verified", vulnerability.FindingStatusResolved, resolution,
		vulnerability.Fixed(vulnerability.VerificationSecurityReview), result); err != nil {
		return nil, err
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
	cands, err := s.lifecycleCandidates(ctx, tid)
	if err != nil {
		return nil, err
	}

	result := &BulkUpdateResult{}

	uid, uidErr := shared.IDFromString(userID)
	if uidErr != nil {
		return nil, fmt.Errorf("%w: invalid user id", shared.ErrValidation)
	}

	var target actionTarget
	for _, idStr := range findingIDs {
		f, err := s.loadActionFinding(ctx, tid, idStr)
		if err != nil {
			result.fail(idStr, err.Error())
			continue
		}
		if f.Status() != vulnerability.FindingStatusFixApplied {
			result.fail(idStr, fmt.Sprintf("not in fix_applied status (current: %s)", f.Status()))
			continue
		}
		// The transition engine: a verifier may reject a fix (the route
		// requires findings:verify).
		if err := actionAllowed(ctx, cands, f, transitionFactsOf(f),
			personActor(uid, TransitionPermissions{Verify: true}), vulnerability.FindingStatusInProgress, reason); err != nil {
			result.fail(idStr, err.Error())
			continue
		}
		if !f.CanTransitionTo(vulnerability.FindingStatusInProgress) {
			result.fail(idStr, fmt.Sprintf("cannot transition from %s to %s", f.Status(), vulnerability.FindingStatusInProgress))
			continue
		}
		target.add(f.ID(), vulnerability.FindingStatusFixApplied)
	}

	if err := s.applyFixDecision(ctx, tid, uid, target, "fix_rejected", vulnerability.FindingStatusInProgress, reason,
		vulnerability.Closure{}, result); err != nil {
		return nil, err
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
	// The transition engine decides each finding, with the evidence its risk
	// asks for (a high or critical finding needs its checklist or a retest),
	// so the filtered set is read first (at most 1000) and only the findings
	// it allows are resolved.
	count, err := s.findingRepo.Count(ctx, input.Filter)
	if err != nil {
		return 0, fmt.Errorf("failed to count findings: %w", err)
	}
	if count > 1000 {
		return 0, fmt.Errorf("%w: too many findings (%d), max 1000. Use a narrower filter", shared.ErrValidation, count)
	}
	actor := personActor(uid, TransitionPermissions{Verify: true})
	cands, err := s.lifecycleCandidates(ctx, tid)
	if err != nil {
		return 0, err
	}
	allowed := make([]shared.ID, 0, int(count))
	const batchSize = 100
	for offset := int64(0); offset < count; offset += batchSize {
		page, err := s.findingRepo.List(ctx, input.Filter, vulnerability.NewFindingListOptions(), pagination.New(int(offset/batchSize)+1, batchSize))
		if err != nil {
			return 0, fmt.Errorf("failed to list findings: %w", err)
		}
		for _, f := range page.Data {
			facts := transitionFactsOf(f)
			if s.db != nil {
				if err := loadResolveEvidence(ctx, s.db, tid, f.ID(), &facts); err != nil {
					return 0, err
				}
			}
			if actionAllowed(ctx, cands, f, facts, actor, vulnerability.FindingStatusResolved, resolution) == nil {
				allowed = append(allowed, f.ID())
			}
		}
	}
	if len(allowed) == 0 {
		return 0, nil
	}

	// Each verified finding gets its timeline entry in the same transaction.
	moveCtx := vulnerability.WithStatusTransition(ctx, vulnerability.StatusTransition{
		Source: string(vulnerability.SourceAPI), Reason: "verified_by_filter", ActorType: "user", ActorID: uid.String(), Message: resolution,
	})
	moved, err := s.moveFixApplied(moveCtx, tid, allowed,
		vulnerability.FindingStatusResolved, resolution, &uid, vulnerability.Fixed(verifyByFilterVerification))
	if err != nil {
		return 0, fmt.Errorf("failed to verify findings: %w", err)
	}
	s.afterMoves(ctx, tid, uid.String(), movesOf(moved, fixApplied, vulnerability.FindingStatusResolved))
	return int64(len(moved)), nil
}

// moveFixApplied writes a verifier's decision on fix_applied findings, limited
// to findings that are still fix_applied: one that moved on since it was read
// (for example to an approved false positive or accepted risk) is left alone.
// A repository that cannot limit the write is refused, never written blind.
func (s *FindingActionsService) moveFixApplied(ctx context.Context, tid shared.ID, ids []shared.ID,
	to vulnerability.FindingStatus, resolution string, by *shared.ID, closure vulnerability.Closure,
) ([]shared.ID, error) {
	return moveStatusBatch(s.ticketSyncCtx(ctx, tid, ids), s.findingRepo, tid, ids, []vulnerability.FindingStatus{vulnerability.FindingStatusFixApplied},
		to, resolution, by, closure)
}

// fixApplied is the status a by-filter verifier decision reads its findings in.
func fixApplied(shared.ID) vulnerability.FindingStatus { return vulnerability.FindingStatusFixApplied }

// verifyByFilterVerification is how a verify-by-filter close is recorded: it
// reads no per-finding verification checklist, so it is a findings:verify
// holder's attestation, not a checklist-backed security review.
const verifyByFilterVerification = vulnerability.VerificationAttested

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

	// The transition engine for the filtered set (all fix_applied): a
	// verifier rejecting the claims.
	if err := transitionError(vulnerability.EvaluateTransition(
		vulnerability.TransitionFacts{Status: vulnerability.FindingStatusFixApplied},
		personActor(uid, TransitionPermissions{Verify: true}), vulnerability.FindingStatusInProgress), input.Reason); err != nil {
		return 0, err
	}

	input.Filter.Statuses = []vulnerability.FindingStatus{vulnerability.FindingStatusFixApplied}
	input.Filter, err = s.visibleTo(ctx, tid, input.Filter)
	if err != nil {
		return 0, err
	}

	moveCtx := vulnerability.WithStatusTransition(ctx, vulnerability.StatusTransition{
		Source: string(vulnerability.SourceAPI), Reason: "fix_rejected_by_filter", ActorType: "user", ActorID: uid.String(), Message: input.Reason,
	})
	// The set is read (at most 1000) and each finding decided (an
	// organization lifecycle can narrow the move), so the write names the
	// findings and the side effects run for exactly the ones it moved.
	cands, err := s.lifecycleCandidates(ctx, tid)
	if err != nil {
		return 0, err
	}
	allowed, err := s.allowedByFilter(ctx, cands, input.Filter, personActor(uid, TransitionPermissions{Verify: true}),
		vulnerability.FindingStatusInProgress, input.Reason)
	if err != nil || len(allowed) == 0 {
		return 0, err
	}
	moved, err := s.moveFixApplied(moveCtx, tid, allowed,
		vulnerability.FindingStatusInProgress, input.Reason, &uid, vulnerability.Closure{})
	if err != nil {
		return 0, fmt.Errorf("failed to reject findings: %w", err)
	}
	s.afterMoves(ctx, tid, uid.String(), movesOf(moved, fixApplied, vulnerability.FindingStatusInProgress))
	return int64(len(moved)), nil
}

// --- Auto-Assign to Owners ---

// AutoAssignToOwnersResult is the result of auto-assign operation.
type AutoAssignToOwnersResult struct {
	Assigned   int            `json:"assigned"`
	ByOwner    map[string]int `json:"by_owner"`
	Unassigned int            `json:"unassigned"`
	// Started counts the assigned findings that were confirmed and moved to
	// in_progress (work started). A new finding stays new: assignment is not
	// triage.
	Started int `json:"started"`
}

// AutoAssignToOwners assigns open findings to their asset owners.
// Only assigns findings that don't already have an assignee; closed findings
// are never touched. A confirmed finding moves to in_progress (a lifecycle
// edge); any other status is left as it is.
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
	// Closed findings (resolved, false positive, accepted, duplicate) are
	// done: assigning them would put finished work back on someone's plate.
	filter.ExcludeStatuses = vulnerability.ClosedFindingStatuses()
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

	// The organization's lifecycle decides whether assigning starts work.
	cands, candsErr := s.lifecycleCandidates(ctx, tid)

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
			// Skip already assigned, and closed findings (the filter
			// excludes them; a row that closed meanwhile is skipped too).
			if f.AssignedTo() != nil || f.Status().IsClosed() {
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

			// Work starts on a confirmed finding (confirmed → in_progress is
			// a lifecycle edge). A new finding is not triaged by assigning it,
			// so it stays new; no other status is changed.
			started := false
			if f.Status() == vulnerability.FindingStatusConfirmed && s.lifecycleLetsWorkStart(ctx, cands, candsErr, f, aid) {
				if err := f.TransitionStatus(vulnerability.FindingStatusInProgress, "", nil); err != nil {
					s.logger.Warn("failed to start work on an assigned finding", "finding_id", f.ID(), "error", err)
				} else {
					started = true
				}
			}

			// The automatic move to in_progress writes its timeline entry in
			// the same transaction as the assignment.
			msg := "Assigned to the asset owner"
			if started {
				msg += ": work started"
			}
			moveCtx := vulnerability.WithStatusTransition(ctx, vulnerability.StatusTransition{
				Source: "auto_assign", Reason: "assigned_to_owner", ActorType: "user", ActorID: aid.String(),
				Message: msg,
				Changes: map[string]any{"assigned_to": info.ownerID.String()},
			})
			if err := s.findingRepo.Update(moveCtx, f); err != nil {
				s.logger.Warn("failed to assign finding", "finding_id", f.ID(), "error", err)
				continue
			}

			result.Assigned++
			if started {
				result.Started++
			}
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

// FixAppliers returns which of the findings the user may mark fix_applied:
// the direct assignee, a member of an assigned group, or a primary or
// secondary owner of the asset. The same rule as BulkFixApplied, for every
// route that marks a fix applied (the status endpoint, the bulk status change,
// remediation group and campaign resolves). A lookup failure narrows, never
// widens.
func (s *FindingActionsService) FixAppliers(ctx context.Context, tenantID, userID shared.ID, findings []*vulnerability.Finding) map[shared.ID]bool {
	out := make(map[shared.ID]bool, len(findings))
	if len(findings) == 0 {
		return out
	}
	groupIDSet := map[shared.ID]bool{}
	if s.groupRepo != nil {
		ids, err := s.groupRepo.ListGroupIDsByUser(ctx, tenantID, userID)
		if err != nil {
			s.logger.Warn("failed to load user groups", "error", err)
		}
		for _, gid := range ids {
			groupIDSet[gid] = true
		}
	}
	findingIDs := make([]shared.ID, len(findings))
	for i, f := range findings {
		findingIDs[i] = f.ID()
	}
	findingGroupMap := map[shared.ID][]shared.ID{}
	if s.accessCtrlRepo != nil {
		m, err := s.accessCtrlRepo.BatchListFindingGroupIDs(ctx, tenantID, findingIDs)
		if err != nil {
			s.logger.Warn("failed to batch load finding groups", "error", err)
		} else {
			findingGroupMap = m
		}
	}
	owned := s.assetsOwnedBy(ctx, tenantID, userID, findings)
	for _, f := range findings {
		out[f.ID()] = s.canMarkFixApplied(userID, groupIDSet, findingGroupMap, owned, f)
	}
	return out
}

// QueueProofOfFix queues a proof-of-fix re-check for each finding just marked
// fix_applied (the same bounded, best-effort dispatch as BulkFixApplied) and
// returns how many were queued. The bulk status path calls it for a fix claim.
func (s *FindingActionsService) QueueProofOfFix(ctx context.Context, tenantID shared.ID, findingIDs []shared.ID) int {
	return s.autoQueueValidations(ctx, tenantID, findingIDs)
}

// allowedByFilter reads the findings a by-filter action selects (at most
// 1000) and keeps those the lifecycle allows to move to target.
func (s *FindingActionsService) allowedByFilter(ctx context.Context, cands []lc.Candidate, filter vulnerability.FindingFilter,
	actor vulnerability.TransitionActor, target vulnerability.FindingStatus, note string,
) ([]shared.ID, error) {
	count, err := s.findingRepo.Count(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to count findings: %w", err)
	}
	if count > 1000 {
		return nil, fmt.Errorf("%w: too many findings (%d), max 1000. Use a narrower filter", shared.ErrValidation, count)
	}
	allowed := make([]shared.ID, 0, int(count))
	const batchSize = 100
	for offset := int64(0); offset < count; offset += batchSize {
		page, err := s.findingRepo.List(ctx, filter, vulnerability.NewFindingListOptions(), pagination.New(int(offset/batchSize)+1, batchSize))
		if err != nil {
			return nil, fmt.Errorf("failed to list findings: %w", err)
		}
		for _, f := range page.Data {
			if actionAllowed(ctx, cands, f, transitionFactsOf(f), actor, target, note) == nil {
				allowed = append(allowed, f.ID())
			}
		}
	}
	return allowed, nil
}

// lifecycleLetsWorkStart reports whether the organization's lifecycle lets
// assign-to-owners start work on a confirmed finding (confirmed ->
// in_progress, landing on the default sub-status). The move is the
// platform's side effect of an assignment, so only the lifecycle's own
// blocks and requirements are asked; when they refuse, the finding is
// assigned and stays confirmed.
func (s *FindingActionsService) lifecycleLetsWorkStart(ctx context.Context, cands []lc.Candidate, candsErr error,
	f *vulnerability.Finding, assigner shared.ID,
) bool {
	if candsErr != nil {
		s.logger.Warn("assign to owners: finding lifecycle unavailable, work not started", "finding_id", f.ID(), "error", candsErr)
		return false
	}
	if len(cands) == 0 {
		return true
	}
	actor := personActor(assigner, TransitionPermissions{Status: true})
	d, _ := lifecycleDecision(cands, f, transitionFactsOf(f), lifecycleActor(ctx, actor),
		lc.Target{Status: vulnerability.FindingStatusInProgress})
	for _, b := range d.Blocked {
		if _, ok := lifecycleBlockMessage(b); ok {
			return false
		}
	}
	return d.NoteMinLen == 0 && len(d.Fields) == 0
}
