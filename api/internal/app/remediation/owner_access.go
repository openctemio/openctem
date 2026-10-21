package remediation

// Owner access (RFC-098, research/217 D24/D25). A task owner must be able to
// open the findings they are asked to fix. The picker tells the assigner who
// cannot (counts only, never titles); naming an owner who cannot see some of
// the task's open findings needs findings:assign and an explicit
// confirmation, and is audited. "Can see" is the candidate's real data scope
// (their scope rows, the assignee exception), so the answer does not change
// when a task-owner view of the findings is added.

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	remediationdom "github.com/openctemio/openctem/api/pkg/domain/remediation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

const (
	// ownerCandidateLimit bounds the picker answer.
	ownerCandidateLimit = 20
	// ownerGroupMemberLimit bounds the team members evaluated per team.
	ownerGroupMemberLimit = 50
)

// OwnerAccessError is the answer when the chosen owner cannot see some of
// the task's open findings and the request does not carry what that needs.
type OwnerAccessError struct {
	MissingFindings int
	MissingAssets   int
	// NeedsPermission: the caller lacks findings:assign (pick someone with
	// access instead); otherwise the caller must confirm.
	NeedsPermission bool
}

func (e *OwnerAccessError) Error() string {
	if e.NeedsPermission {
		return fmt.Sprintf("%v: the owner cannot see %d finding(s) on %d asset(s); choose someone with access, or ask a person who may assign findings",
			shared.ErrValidation, e.MissingFindings, e.MissingAssets)
	}
	return fmt.Sprintf("%v: the owner cannot see %d finding(s) on %d asset(s); confirm to share them with the owner (confirm_owner_access)",
		shared.ErrValidation, e.MissingFindings, e.MissingAssets)
}

// Unwrap makes the error a validation error (422/400 family) for generic handlers.
func (e *OwnerAccessError) Unwrap() error { return shared.ErrValidation }

// AsOwnerAccessError reports whether err is an OwnerAccessError.
func AsOwnerAccessError(err error) (*OwnerAccessError, bool) {
	var e *OwnerAccessError
	if errors.As(err, &e) {
		return e, true
	}
	return nil, false
}

// SetOwnerAccess wires the repository the owner picker and rule read.
func (s *TaskService) SetOwnerAccess(r remediationdom.OwnerAccessRepository) { s.ownerAccess = r }

// OwnerGap is what an owner candidate cannot see: counts only.
type OwnerGap struct {
	Findings int
	Assets   int
}

// OwnerCandidate is a person or team the picker offers.
type OwnerCandidate struct {
	Team  bool
	ID    shared.ID
	Name  string
	Email string
	OwnerGap
	// Members and MembersMissing: for a team, its active members (all) and
	// how many of the evaluated ones lack access to some finding.
	Members        int
	MembersMissing int
}

// OwnerCandidatesInput asks who may own a task: for an existing task
// (TaskID), or for findings a new task will hold (FindingIDs).
type OwnerCandidatesInput struct {
	TenantID   shared.ID
	TaskID     *shared.ID
	FindingIDs []shared.ID
	Query      string
}

// OwnerCandidatesResult is the picker answer.
type OwnerCandidatesResult struct {
	Findings   int
	Candidates []OwnerCandidate
}

// ownerRefs resolves the open findings an owner would need to see.
func (s *TaskService) ownerRefs(ctx context.Context, tenantID shared.ID, taskID *shared.ID, findingIDs []shared.ID) ([]remediationdom.OwnerFindingRef, error) {
	if s.ownerAccess == nil {
		return nil, errors.New("owner access is not configured")
	}
	if taskID != nil {
		if _, err := s.writableTask(ctx, tenantID, *taskID); err != nil {
			return nil, err
		}
		return s.ownerAccess.TaskOpenPrimaryRefs(ctx, tenantID, *taskID)
	}
	ids := dedupeIDs(findingIDs)
	if len(ids) == 0 {
		return nil, ErrTaskNoFindings
	}
	if len(ids) > remediationdom.MaxMembersPerRequest {
		return nil, ErrTaskTooManyFindings
	}
	// The caller names findings: they must be ones the caller may see.
	if err := s.checkFindings(ctx, tenantID, ids, nil); err != nil {
		return nil, err
	}
	return s.ownerAccess.OpenFindingRefs(ctx, tenantID, ids)
}

// userGap is what the user cannot see among refs: findings whose asset is
// outside their scope and that are not assigned to them.
func (s *TaskService) userGap(ctx context.Context, tenantID, userID shared.ID, refs []remediationdom.OwnerFindingRef) (findings, assets map[shared.ID]struct{}, err error) {
	findings, assets = map[shared.ID]struct{}{}, map[shared.ID]struct{}{}
	if s.dataScope == nil || len(refs) == 0 {
		return findings, assets, nil
	}
	scope, err := s.dataScope.ForUser(ctx, tenantID, userID)
	if err != nil {
		return nil, nil, err
	}
	if scope == nil {
		return findings, assets, nil
	}
	assetIDs := make([]shared.ID, 0, len(refs))
	for _, r := range refs {
		assetIDs = append(assetIDs, r.AssetID)
	}
	inScope, err := s.dataScope.Filter(ctx, scope, assetIDs)
	if err != nil {
		return nil, nil, err
	}
	visible := inScope
	if scope.Restricted() {
		if visible, err = s.dataScope.Filter(ctx, &shared.DataScope{TenantID: scope.TenantID, UserID: scope.UserID, Unrestricted: true}, assetIDs); err != nil {
			return nil, nil, err
		}
	}
	for _, r := range refs {
		if inScope(r.AssetID) || (scope.Restricted() && r.AssignedTo != nil && *r.AssignedTo == userID && visible(r.AssetID)) {
			continue
		}
		findings[r.FindingID] = struct{}{}
		assets[r.AssetID] = struct{}{}
	}
	return findings, assets, nil
}

// ownerGap is the gap of a person or of a team (the union over its active
// members); for a team it also returns the member counts.
func (s *TaskService) ownerGap(ctx context.Context, tenantID shared.ID, user, group *shared.ID, refs []remediationdom.OwnerFindingRef) (OwnerGap, int, int, error) {
	findings, assets := map[shared.ID]struct{}{}, map[shared.ID]struct{}{}
	members, missing := 0, 0
	add := func(f, a map[shared.ID]struct{}) {
		for id := range f {
			findings[id] = struct{}{}
		}
		for id := range a {
			assets[id] = struct{}{}
		}
	}
	if user != nil {
		f, a, err := s.userGap(ctx, tenantID, *user, refs)
		if err != nil {
			return OwnerGap{}, 0, 0, err
		}
		add(f, a)
	}
	if group != nil {
		ids, total, err := s.ownerAccess.GroupActiveMembers(ctx, tenantID, *group, ownerGroupMemberLimit)
		if err != nil {
			return OwnerGap{}, 0, 0, err
		}
		members = total
		for _, id := range ids {
			f, a, err := s.userGap(ctx, tenantID, id, refs)
			if err != nil {
				return OwnerGap{}, 0, 0, err
			}
			if len(f) > 0 {
				missing++
			}
			add(f, a)
		}
	}
	return OwnerGap{Findings: len(findings), Assets: len(assets)}, members, missing, nil
}

// OwnerCandidates lists people and teams to offer as owner, with how much of
// the task's open findings each cannot see (counts only), those who see all
// first.
func (s *TaskService) OwnerCandidates(ctx context.Context, in OwnerCandidatesInput) (*OwnerCandidatesResult, error) {
	refs, err := s.ownerRefs(ctx, in.TenantID, in.TaskID, in.FindingIDs)
	if err != nil {
		return nil, err
	}
	q := strings.TrimSpace(in.Query)
	if len(q) > 100 {
		q = q[:100]
	}
	users, err := s.ownerAccess.SearchOwnerUsers(ctx, in.TenantID, q, ownerCandidateLimit)
	if err != nil {
		return nil, err
	}
	groups, err := s.ownerAccess.SearchOwnerGroups(ctx, in.TenantID, q, ownerCandidateLimit/2)
	if err != nil {
		return nil, err
	}
	res := &OwnerCandidatesResult{Findings: len(refs)}
	for _, u := range users {
		id := u.ID
		gap, _, _, gerr := s.ownerGap(ctx, in.TenantID, &id, nil, refs)
		if gerr != nil {
			return nil, gerr
		}
		res.Candidates = append(res.Candidates, OwnerCandidate{ID: u.ID, Name: u.Name, Email: u.Email, OwnerGap: gap})
	}
	for _, g := range groups {
		id := g.ID
		gap, members, missing, gerr := s.ownerGap(ctx, in.TenantID, nil, &id, refs)
		if gerr != nil {
			return nil, gerr
		}
		res.Candidates = append(res.Candidates, OwnerCandidate{Team: true, ID: g.ID, Name: g.Name, OwnerGap: gap, Members: members, MembersMissing: missing})
	}
	sort.SliceStable(res.Candidates, func(i, j int) bool {
		a, b := res.Candidates[i], res.Candidates[j]
		if (a.Findings == 0) != (b.Findings == 0) {
			return a.Findings == 0
		}
		return false
	})
	if len(res.Candidates) > ownerCandidateLimit {
		res.Candidates = res.Candidates[:ownerCandidateLimit]
	}
	return res, nil
}

// ownerAccessCheck is the input of the owner access rule.
type ownerAccessCheck struct {
	user, group *shared.ID
	refs        func() ([]remediationdom.OwnerFindingRef, error)
	canExtend   bool // the caller holds findings:assign
	confirmed   bool
}

// checkOwnerAccess applies the rule: an owner who cannot see some of the
// open findings needs findings:assign and the caller's confirmation. It
// returns the gap when it was accepted (to audit), a zero gap when none.
func (s *TaskService) checkOwnerAccess(ctx context.Context, tenantID shared.ID, c ownerAccessCheck) (OwnerGap, error) {
	if (c.user == nil && c.group == nil) || s.ownerAccess == nil || s.dataScope == nil {
		return OwnerGap{}, nil
	}
	refs, err := c.refs()
	if err != nil {
		return OwnerGap{}, err
	}
	gap, _, _, err := s.ownerGap(ctx, tenantID, c.user, c.group, refs)
	if err != nil {
		return OwnerGap{}, err
	}
	if gap.Findings == 0 {
		return OwnerGap{}, nil
	}
	if !c.canExtend || !c.confirmed {
		return OwnerGap{}, &OwnerAccessError{MissingFindings: gap.Findings, MissingAssets: gap.Assets, NeedsPermission: !c.canExtend}
	}
	return gap, nil
}

func (s *TaskService) auditOwnerAccess(ctx context.Context, actx auditapp.AuditContext, taskID shared.ID, title string, gap OwnerGap, user, group *shared.ID) {
	if gap.Findings == 0 {
		return
	}
	s.logAudit(ctx, actx, auditapp.NewSuccessEvent(auditdom.ActionRemediationTaskOwnerAccessExtended, auditdom.ResourceTypeRemediationTask, taskID.String()).
		WithResourceName(title).
		WithMessage(fmt.Sprintf("Owner of remediation task %q needs access to %d finding(s) on %d asset(s); confirmed by the assigner", title, gap.Findings, gap.Assets)).
		WithMetadata("findings", gap.Findings).WithMetadata("assets", gap.Assets).
		WithMetadata("owner_user_id", idStr(user)).WithMetadata("owner_group_id", idStr(group)))
}
