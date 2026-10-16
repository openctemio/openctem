package finding

// The approval policy on finding status requests
// (api/docs/rfcs/RFC-111-approval-policy.md): every false-positive and
// accepted-risk request is evaluated from facts read on the server (the
// finding, its asset, its owners, the approver pool, the organization's
// policy). The evaluation decides the tier, who may approve, how many people,
// the longest acceptance end and the decision deadline; it runs again when
// someone approves, so a request is decided on the facts of that moment.
//
// Threat model: a decision that hides a risk must not be made by one stolen
// session, by the person who owns the asset, or under a policy relaxed in the
// same sitting. Controls: the requester and the asset's owners never sign
// off; security and dual tiers need a recent re-authentication of each
// signer; dual needs two distinct people, one of them from the security pool
// (or a recorded fallback); sign-offs are unique per person and the last one
// applies the decision in the same transaction (the request row is locked);
// every read is by (tenant_id, id) and the approver pool is the tenant's
// members with the finding in their data scope; the organization's policy
// only adds constraints above the platform floors.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/approvalpolicy"
	notificationdom "github.com/openctemio/openctem/api/pkg/domain/notification"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// PolicyFacts are the facts of a finding the policy needs beyond the
// finding row: its asset's exposure and owners.
type PolicyFacts struct {
	Facts       approvalpolicy.Facts
	AssetOwners []shared.ID
	AssigneeID  *shared.ID
}

// policyFactsReader reads a finding's policy facts in one query
// (*postgres.FindingApprovalRepository).
type policyFactsReader interface {
	PolicyFacts(ctx context.Context, tenantID, findingID shared.ID) (PolicyFacts, error)
}

// securityPoolReader reads the members of the organization's security pool
// group (*postgres.FindingApprovalRepository). A group of another tenant has
// no members here.
type securityPoolReader interface {
	GroupMemberIDs(ctx context.Context, tenantID, groupID shared.ID, addedBefore time.Time) ([]shared.ID, error)
	GroupInTenant(ctx context.Context, tenantID, groupID shared.ID) (bool, error)
}

// SecurityPoolMinAge is how long a person must have been in the security
// pool group before a sign-off counts as the pool's. The pool is read live
// when someone signs, so without it an administrator could add a colluding
// account to the group and have it sign in the same sitting.
const SecurityPoolMinAge = 24 * time.Hour

// SignoffRecord is one approval given to a request.
type SignoffRecord struct {
	UserID       shared.ID
	SecurityPool bool
	PoolFallback bool
	StepUp       bool
}

// SignoffDecider decides, inside the sign-off transaction with the request
// locked, whether the signer may sign off given the sign-offs already in, and
// whether this one completes the request.
type SignoffDecider func(a *vulnerability.Approval, prior []approvalpolicy.Signoff) (complete bool, err error)

// SignoffFinisher returns the timeline entry of a sign-off; when it
// completes the request it first prepares the request for applying (approve
// it, set its end and decision facts).
type SignoffFinisher func(a *vulnerability.Approval, complete bool) (*vulnerability.FindingActivity, error)

// signoffStore records sign-offs (*postgres.FindingApprovalRepository).
type signoffStore interface {
	SignOff(ctx context.Context, tenantID, approvalID shared.ID, rec SignoffRecord, decide SignoffDecider, finish SignoffFinisher) (*vulnerability.Approval, bool, error)
	Signoffs(ctx context.Context, tenantID shared.ID, subjectType string, subjectID shared.ID) ([]approvalpolicy.Signoff, error)
}

// SignoffSubjectFindingApproval is the subject type of a finding request's
// sign-offs.
const SignoffSubjectFindingApproval = "finding_approval"

// ErrStepUpNotWired: a tier needs a recent re-authentication and the check is
// not available; the approval is refused (fail closed).
var ErrStepUpNotWired = shared.NewDomainError("STEP_UP_UNAVAILABLE",
	"re-authentication is not available; this approval needs it and is refused", shared.ErrForbidden)

// SetStepUpGate wires the recent re-authentication check for approvals whose
// tier needs it. Without it such approvals are refused.
func (s *VulnerabilityService) SetStepUpGate(g shared.RecentAuthGate) { s.stepUpGate = g }

// requireApproverStepUp asks the approver for a recent re-authentication.
func (s *VulnerabilityService) requireApproverStepUp(ctx context.Context, approver shared.ID) error {
	if s.stepUpGate == nil {
		return ErrStepUpNotWired
	}
	return s.stepUpGate.RequireRecentAuth(ctx, approver.String())
}

// orgPolicy is the organization's policy in force and its false-positive
// level and second-look share.
type orgPolicy struct {
	policy            approvalpolicy.Policy
	fpLevel           string
	secondLookPercent int
	poolConfigured    bool
}

func (s *VulnerabilityService) orgApprovalPolicy(ctx context.Context, tid shared.ID) (orgPolicy, error) {
	out := orgPolicy{fpLevel: approvalpolicy.FPLevelAll}
	if s.approvalSettings == nil {
		return out, nil
	}
	settings, err := s.approvalSettings.GetFindingApprovalSettings(ctx, tid.String())
	if err != nil {
		return out, fmt.Errorf("read the organization's approval settings: %w", err)
	}
	now := time.Now()
	out.policy = settings.EffectivePolicy(now)
	out.fpLevel = settings.EffectiveFPApproval(now)
	out.secondLookPercent = settings.EffectiveSecondLookPercent(now)
	out.poolConfigured = out.policy.SecurityPoolGroupID != ""
	return out, nil
}

// findingPolicyFacts are the policy facts of f: from the finding itself,
// and the asset and owners when the repository can read them.
func (s *VulnerabilityService) findingPolicyFacts(ctx context.Context, f *vulnerability.Finding) (PolicyFacts, error) {
	if r, ok := s.approvalRepo.(policyFactsReader); ok {
		pf, err := r.PolicyFacts(ctx, f.TenantID(), f.ID())
		if err != nil {
			return PolicyFacts{}, err
		}
		return pf, nil
	}
	pf := PolicyFacts{Facts: approvalpolicy.Facts{
		Severity:         string(f.Severity()),
		PriorityClass:    priorityClassString(f),
		KEV:              f.IsInKEV(),
		EPSS:             f.EPSSScore(),
		ExploitValidated: f.ValidationOutcome() == "reproducible",
	}, AssigneeID: f.AssignedTo()}
	return pf, nil
}

// approverCandidates is the approver pool of a finding: members who hold
// findings:approve and have the finding in their data scope, marked when
// they are in the security pool. Without an approver directory (a minimal
// wiring) the known signers stand in: they passed the route's permission
// check and the data scope check.
func (s *VulnerabilityService) approverCandidates(ctx context.Context, tid, findingID shared.ID, op orgPolicy, known ...shared.ID) ([]approvalpolicy.Candidate, error) {
	inPool := map[shared.ID]bool{}
	if op.poolConfigured {
		if r, ok := s.approvalRepo.(securityPoolReader); ok {
			gid, err := shared.IDFromString(op.policy.SecurityPoolGroupID)
			if err == nil {
				members, err := r.GroupMemberIDs(ctx, tid, gid, time.Now().Add(-SecurityPoolMinAge))
				if err != nil {
					return nil, err
				}
				for _, id := range members {
					inPool[id] = true
				}
			}
		}
	}
	if s.approverDir == nil {
		out := make([]approvalpolicy.Candidate, 0, len(known))
		for _, id := range known {
			if !id.IsZero() {
				out = append(out, approvalpolicy.Candidate{UserID: id, InSecurityPool: inPool[id]})
			}
		}
		return out, nil
	}
	all, err := s.approverDir.FindingApprovers(ctx, tid)
	if err != nil {
		return nil, fmt.Errorf("list finding approvers: %w", err)
	}
	out := make([]approvalpolicy.Candidate, 0, len(all))
	for _, ap := range all {
		uid, err := shared.IDFromString(ap.UserID)
		if err != nil {
			continue
		}
		if s.dataScope != nil {
			if err := s.dataScope.AssertFindingForUser(ctx, tid, uid, findingID); err != nil {
				if !errors.Is(err, shared.ErrNotFound) {
					s.logger.Warn("approval policy: data scope", "error", logger.SanitizeError(err))
				}
				continue
			}
		}
		out = append(out, approvalpolicy.Candidate{UserID: uid, InSecurityPool: inPool[uid]})
	}
	return out, nil
}

// policyEvaluation is one evaluation with the facts it used.
type policyEvaluation struct {
	result approvalpolicy.Result
	facts  approvalpolicy.Facts
	org    orgPolicy
}

// evaluateFindingRequest evaluates a request of kind on f by requester
// (zero for an actor; actorMade then asks for the extra sign-off). known are people who certainly hold the approve
// permission (the caller of an approve), used only without a directory.
func (s *VulnerabilityService) evaluateFindingRequest(ctx context.Context, f *vulnerability.Finding, kind approvalpolicy.Kind,
	requester shared.ID, actorMade, requesterCanApprove bool, known ...shared.ID,
) (policyEvaluation, error) {
	op, err := s.orgApprovalPolicy(ctx, f.TenantID())
	if err != nil {
		return policyEvaluation{}, err
	}
	pf, err := s.findingPolicyFacts(ctx, f)
	if err != nil {
		return policyEvaluation{}, err
	}
	cands, err := s.approverCandidates(ctx, f.TenantID(), f.ID(), op, known...)
	if err != nil {
		return policyEvaluation{}, err
	}
	res := approvalpolicy.Evaluate(op.policy, approvalpolicy.Request{
		Kind: kind, Facts: pf.Facts, RequesterID: requester, ActorMade: actorMade, RequesterCanApprove: requesterCanApprove,
		FPLevel: op.fpLevel, AssetOwners: pf.AssetOwners, AssigneeID: pf.AssigneeID,
		Approvers: cands, SecurityPoolConfigured: op.poolConfigured,
	})
	return policyEvaluation{result: res, facts: pf.Facts, org: op}, nil
}

// kindOfStatus maps a requested finding status to a policy kind.
func kindOfStatus(status vulnerability.FindingStatus) (approvalpolicy.Kind, bool) {
	switch status {
	case vulnerability.FindingStatusFalsePositive:
		return approvalpolicy.KindFalsePositive, true
	case vulnerability.FindingStatusAccepted:
		return approvalpolicy.KindAccepted, true
	}
	return "", false
}

// policyEvalJSON is the evaluation kept on the request as evidence.
func policyEvalJSON(res approvalpolicy.Result) []byte {
	b, err := json.Marshal(res)
	if err != nil {
		return nil
	}
	return b
}

func factsJSON(f approvalpolicy.Facts) []byte {
	b, err := json.Marshal(f)
	if err != nil {
		return nil
	}
	return b
}

// stampPolicy writes the evaluation onto a new request: tier, class,
// required approvals, the decision deadline and the evidence.
func stampPolicy(a *vulnerability.Approval, ev policyEvaluation, now time.Time) {
	a.Tier = string(ev.result.Tier)
	a.RiskClass = string(ev.result.Class)
	a.RequiredApprovals = ev.result.Required
	a.PolicyEval = policyEvalJSON(ev.result)
	if a.Status == vulnerability.ApprovalStatusPending {
		decideBy := now.Add(ev.result.DecideWithin)
		a.DecideBy = &decideBy
	}
}

// ApprovalPolicyView is how a request of one kind on a finding would be
// decided now, for the request dialog (the "why / who").
type ApprovalPolicyView struct {
	Result approvalpolicy.Result
	// EligibleCount / PoolCount: how many people may sign off.
	EligibleCount int
	PoolCount     int
	// CallerMayApprove: the caller could sign off such a request (not as its
	// requester); CallerExcluded says why not.
	CallerExcluded string
	// MaxAcceptanceDays is the longest acceptance (accepted only).
	MaxAcceptanceDays int
}

// FindingApprovalPolicy evaluates a request of status on the finding as if
// the caller made it. The finding must be in the caller's data scope.
func (s *VulnerabilityService) FindingApprovalPolicy(ctx context.Context, tenantID, findingID, callerID, status string, callerCanApprove bool) (*ApprovalPolicyView, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	fid, err := shared.IDFromString(findingID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid finding id", shared.ErrValidation)
	}
	caller, _ := shared.IDFromString(callerID)
	kind, ok := kindOfStatus(vulnerability.FindingStatus(status))
	if !ok {
		return nil, fmt.Errorf("%w: status must be false_positive or accepted", shared.ErrValidation)
	}
	f, err := s.findingRepo.GetByID(ctx, tid, fid)
	if err != nil {
		return nil, err
	}
	if err := s.assertFindingScope(ctx, f); err != nil {
		return nil, err
	}
	ev, err := s.evaluateFindingRequest(ctx, f, kind, caller, false, callerCanApprove, caller)
	if err != nil {
		return nil, err
	}
	v := &ApprovalPolicyView{Result: ev.result, EligibleCount: len(ev.result.Eligible), PoolCount: len(ev.result.EligiblePool)}
	if why, ok := ev.result.Excluded[caller]; ok && why != approvalpolicy.ExcludedRequester {
		v.CallerExcluded = string(why)
	}
	if ev.result.MaxAcceptance > 0 {
		v.MaxAcceptanceDays = int(ev.result.MaxAcceptance / (24 * time.Hour))
	}
	return v, nil
}

// ValidateSecurityPoolGroup refuses a security pool group that is not a
// group of the organization.
func (s *VulnerabilityService) ValidateSecurityPoolGroup(ctx context.Context, tenantID, groupID string) error {
	if groupID == "" {
		return nil
	}
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	gid, err := shared.IDFromString(groupID)
	if err != nil {
		return fmt.Errorf("%w: security_pool_group_id must be a group id", shared.ErrValidation)
	}
	r, ok := s.approvalRepo.(securityPoolReader)
	if !ok {
		return fmt.Errorf("%w: security pools are not available", shared.ErrValidation)
	}
	in, err := r.GroupInTenant(ctx, tid, gid)
	if err != nil {
		return err
	}
	if !in {
		return fmt.Errorf("%w: security_pool_group_id is not a group of this organization", shared.ErrValidation)
	}
	return nil
}

// signOffApproval records approvedBy's approval of a pending request under
// the policy evaluated now (the facts, pools and policy of this moment) and
// applies the request when it is the last sign-off needed. approval is
// updated in place; it answers whether the request was applied.
func (s *VulnerabilityService) signOffApproval(ctx context.Context, approval *vulnerability.Approval, f *vulnerability.Finding,
	approvedBy shared.ID, now time.Time,
) (bool, error) {
	status := vulnerability.FindingStatus(approval.RequestedStatus)
	kind, ok := kindOfStatus(status)
	if !ok {
		return false, fmt.Errorf("%w: status '%s' cannot be set via the approval workflow", shared.ErrValidation, approval.RequestedStatus)
	}
	// The requester never approves their own request (the sole member has
	// their own path, SelfApproveSolo).
	if !approval.RequestedBy.IsZero() && approval.RequestedBy == approvedBy {
		return false, vulnerability.ErrSelfApproval
	}
	store, hasStore := s.approvalRepo.(signoffStore)
	var prior []approvalpolicy.Signoff
	if hasStore {
		var err error
		if prior, err = store.Signoffs(ctx, approval.TenantID, SignoffSubjectFindingApproval, approval.ID); err != nil {
			return false, err
		}
	}
	known := []shared.ID{approvedBy}
	for _, p := range prior {
		known = append(known, p.UserID)
	}
	ev, err := s.evaluateFindingRequest(ctx, f, kind, approval.RequestedBy, approval.IsActorRequest(), false, known...)
	if err != nil {
		return false, err
	}
	res := ev.result

	// An accepted risk always ends. A request made before the end was
	// required has none: it gets the default (within the cap) from now. An
	// end past the cap of the finding now (its priority may have risen) is
	// refused, never shortened silently: the requester asks again.
	if status == vulnerability.FindingStatusAccepted {
		if approval.ExpiresAt == nil {
			approval.ExpiresAt, _ = vulnerability.AcceptanceEndWithin(nil, now, res.MaxAcceptance, "")
		} else if approval.ExpiresAt.After(now.Add(res.MaxAcceptance)) {
			return false, fmt.Errorf("%w: the requested acceptance end is past the %d-day cap of the finding now; request again with an earlier end",
				shared.ErrValidation, int(res.MaxAcceptance/(24*time.Hour)))
		}
	}
	// Judge the signer before asking them to re-authenticate; the store
	// judges again with the request locked.
	if _, err := res.Sign(approvedBy, prior); err != nil {
		return false, err
	}
	if res.StepUp {
		if err := s.requireApproverStepUp(ctx, approvedBy); err != nil {
			return false, err
		}
	}
	end := approval.ExpiresAt
	finish := func(a *vulnerability.Approval, complete bool) (*vulnerability.FindingActivity, error) {
		changes := map[string]any{
			"approval_id":         a.ID.String(),
			"requested_status":    a.RequestedStatus,
			"tier":                string(res.Tier),
			"approvals_collected": a.ApprovalsCollected,
			"approvals_required":  res.Required,
		}
		a.RequiredApprovals = res.Required
		if !complete {
			changes["signed_by"] = approvedBy.String()
			return vulnerability.NewFindingActivity(a.TenantID, a.FindingID, vulnerability.ActivityApprovalSigned,
				&approvedBy, vulnerability.ActorTypeUser, changes, vulnerability.SourceAPI, nil)
		}
		a.ExpiresAt = end
		a.DecisionFacts = factsJSON(ev.facts)
		if err := a.Approve(approvedBy); err != nil {
			return nil, err
		}
		changes["approved_by"] = approvedBy.String()
		return vulnerability.NewFindingActivity(a.TenantID, a.FindingID, vulnerability.ActivityApprovalApproved,
			&approvedBy, vulnerability.ActorTypeUser, changes, vulnerability.SourceAPI, nil)
	}
	if !hasStore {
		if res.Required > 1 {
			return false, fmt.Errorf("%w: requests that need two approvers are not available", shared.ErrNotImplemented)
		}
		entry, err := finish(approval, true)
		if err != nil {
			return false, err
		}
		return true, s.approvalRepo.ApproveAndApply(ctx, approval, entry)
	}
	rec := SignoffRecord{UserID: approvedBy, PoolFallback: res.PoolFallback, StepUp: res.StepUp}
	for _, id := range res.EligiblePool {
		rec.SecurityPool = rec.SecurityPool || id == approvedBy
	}
	out, applied, err := store.SignOff(ctx, approval.TenantID, approval.ID, rec,
		func(_ *vulnerability.Approval, prior []approvalpolicy.Signoff) (bool, error) {
			return res.Sign(approvedBy, prior)
		},
		finish)
	if err != nil {
		return false, err
	}
	*approval = *out
	return applied, nil
}

// EffectiveApprovalPolicy is the organization's approval policy in force
// (the material-change controller's policy source).
func (s *VulnerabilityService) EffectiveApprovalPolicy(ctx context.Context, tenantID shared.ID) (approvalpolicy.Policy, error) {
	op, err := s.orgApprovalPolicy(ctx, tenantID)
	if err != nil {
		return approvalpolicy.Policy{}, err
	}
	return op.policy, nil
}

// NotifyMaterialChange tells the requester and the approvers of a decision
// the material-change controller ended, flagged or withdrew (in-app; the
// finding title and the change only, never the justification).
func (s *VulnerabilityService) NotifyMaterialChange(ctx context.Context, d vulnerability.StandingDecision,
	action approvalpolicy.Action, signals []approvalpolicy.Signal,
) {
	if s.approvalInApp == nil {
		return
	}
	var title string
	switch action {
	case approvalpolicy.ActionEnd:
		title = "Risk acceptance ended: the finding changed"
	case approvalpolicy.ActionRevoke:
		title = "False positive withdrawn: the finding changed"
	default:
		title = "A finding decision needs review: the finding changed"
	}
	parts := make([]string, 0, len(signals))
	for _, sg := range signals {
		parts = append(parts, strings.ReplaceAll(string(sg), "_", " "))
	}
	body := "Changes since the decision: " + strings.Join(parts, ", ") + "."
	seen := map[shared.ID]bool{}
	recipients := append([]shared.ID{d.RequesterID}, d.ApproverIDs...)
	for _, uid := range recipients {
		if uid.IsZero() || seen[uid] {
			continue
		}
		seen[uid] = true
		u, fid := uid, d.FindingID
		if err := s.approvalInApp.Notify(ctx, notificationdom.NotificationParams{
			TenantID: d.TenantID, Audience: notificationdom.AudienceUser, AudienceID: &u,
			NotificationType: notificationdom.TypeFindingApproval, Title: title, Body: body,
			Severity: notificationdom.SeverityHigh, ResourceType: "finding", ResourceID: &fid,
			URL: "/findings/" + d.FindingID.String(),
		}); err != nil {
			s.logger.Warn("material change: in-app notification", "error", logger.SanitizeError(err))
		}
	}
}
