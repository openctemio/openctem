package approvalpolicy

import (
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// False-positive approval levels of an organization (the values of the
// tenant setting finding_approvals.fp_approval).
const (
	FPLevelAll          = "all"
	FPLevelHighAndAbove = "high_and_above"
	FPLevelOff          = "off"
)

// Tier reason codes (besides the class reasons in facts.go).
const (
	ReasonPlatformFloor       = "platform_floor"
	ReasonPlatformDefault     = "platform_default"
	ReasonOrganizationPolicy  = "organization_policy"
	ReasonFPLevel             = "fp_level"
	ReasonRequesterCannotSelf = "requester_cannot_decide_alone"
	ReasonRequesterOwnsAsset  = "requester_owns_asset"
	ReasonGroupDecision       = "group_decision"
	ReasonPoolFallback        = "security_pool_fallback"
	ReasonNoEligibleApprover  = "no_eligible_approver"
	ReasonNotEnoughApprovers  = "not_enough_eligible_approvers"
)

// ExcludeReason says why a member may not approve a request.
type ExcludeReason string

const (
	ExcludedRequester  ExcludeReason = "requester"
	ExcludedAssetOwner ExcludeReason = "asset_owner"
	ExcludedAssignee   ExcludeReason = "assignee"
)

// Candidate is one member of the approver pool: they hold the kind's approve
// permission and have the subject in their data scope. InSecurityPool: they
// are in the organization's security pool group.
type Candidate struct {
	UserID         shared.ID
	InSecurityPool bool
}

// Request is everything the evaluator needs about one request. The caller
// reads it on the server.
type Request struct {
	Kind  Kind
	Facts Facts
	// RequesterID is the person who asks (zero for an actor: AI triage, VEX,
	// a ticket integration).
	RequesterID shared.ID
	// RequesterCanApprove: the requester holds the approve permission and
	// the subject is in their data scope (only then may they decide alone).
	RequesterCanApprove bool
	// FPLevel is the organization's false-positive level in force (false
	// positives only; "" = all).
	FPLevel string
	// AssetOwners are the people who own the subject's asset (user owners
	// and members of owner groups).
	AssetOwners []shared.ID
	// AssigneeID is the finding's assignee, if any.
	AssigneeID *shared.ID
	// Approvers is the approver pool.
	Approvers []Candidate
	// SecurityPoolConfigured: the organization named a security pool group.
	SecurityPoolConfigured bool
}

// Result is the evaluation of one request.
type Result struct {
	Kind  Kind  `json:"kind"`
	Class Class `json:"risk_class"`
	Tier  Tier  `json:"tier"`
	Floor Tier  `json:"floor"`
	// Required is how many people other than the requester must sign off.
	Required int `json:"required_approvals"`
	// Reasons explain the class and the tier (stable codes).
	Reasons []string `json:"reasons"`
	// SecurityPool: a sign-off must come from the security pool.
	SecurityPool bool `json:"security_pool"`
	// PoolFallback: nobody in the security pool is eligible (or there is no
	// pool), so the approver pool stands in.
	PoolFallback bool `json:"security_pool_fallback"`
	// StepUp: the approver must have re-authenticated recently.
	StepUp bool `json:"step_up"`
	// MaxAcceptance is the longest end of an accepted risk (0 otherwise).
	MaxAcceptance time.Duration `json:"-"`
	// DecideWithin is how long the request waits for a decision.
	DecideWithin time.Duration `json:"-"`
	// Eligible are the people who may sign off; EligiblePool those of them
	// in the security pool.
	Eligible     []shared.ID `json:"-"`
	EligiblePool []shared.ID `json:"-"`
	// Excluded says why members of the approver pool may not sign off.
	Excluded map[shared.ID]ExcludeReason `json:"-"`
	// MinNoteLength is the shortest note the request carries.
	MinNoteLength int `json:"min_note_length"`
}

// SinglePerson reports whether the requester decides alone.
func (r Result) SinglePerson() bool { return r.Tier == TierSingle }

// Satisfiable reports whether enough eligible people exist to complete the
// request.
func (r Result) Satisfiable() bool {
	if r.Tier == TierSingle {
		return true
	}
	if len(r.Eligible) < r.Required {
		return false
	}
	if r.SecurityPool && !r.PoolFallback && len(r.EligiblePool) == 0 {
		return false
	}
	return true
}

func containsID(ids []shared.ID, id shared.ID) bool {
	for _, v := range ids {
		if v == id {
			return true
		}
	}
	return false
}

// Evaluate decides one request under policy p.
func Evaluate(p Policy, r Request) Result {
	threshold := p.EPSS()
	class, reasons := ClassOf(r.Kind, r.Facts, threshold)
	res := Result{Kind: r.Kind, Class: class, Floor: Floor(r.Kind, class), Reasons: reasons}

	tier := p.TierFor(r.Kind, class)
	switch {
	case p.cellSet(r.Kind, class):
		res.Reasons = append(res.Reasons, ReasonOrganizationPolicy)
	case tier == res.Floor:
		res.Reasons = append(res.Reasons, ReasonPlatformFloor)
	default:
		res.Reasons = append(res.Reasons, ReasonPlatformDefault)
	}
	if r.Kind == KindFalsePositive {
		// The organization's false-positive level replaces the default;
		// an explicit cell still raises it.
		level := fpLevelTier(r.FPLevel, MaterialForFalsePositive(r.Facts, threshold))
		if p.cellSet(r.Kind, class) {
			tier = MaxTier(level, tier)
		} else {
			tier = level
		}
		res.Reasons = append(res.Reasons, ReasonFPLevel)
	}
	tier = MaxTier(res.Floor, tier)

	isOwner := func(id shared.ID) bool { return containsID(r.AssetOwners, id) }
	if tier == TierSingle {
		switch {
		case r.RequesterID.IsZero() || !r.RequesterCanApprove:
			tier = TierPeer
			res.Reasons = append(res.Reasons, ReasonRequesterCannotSelf)
		case isOwner(r.RequesterID):
			// A person never hides a risk on an asset they own alone.
			tier = TierPeer
			res.Reasons = append(res.Reasons, ReasonRequesterOwnsAsset)
		}
	}
	res.Tier = tier
	res.Required = tier.RequiredApprovals()
	res.SecurityPool = tier.NeedsSecurityPool()
	res.StepUp = tier.NeedsStepUp() || (p.StepUpAllTiers && tier != TierSingle)
	res.MinNoteLength = tier.MinNoteLength()
	res.DecideWithin = p.DecideWithin()
	if r.Kind.IsAcceptance() {
		res.MaxAcceptance = p.AcceptanceCap(r.Facts)
	}
	res.fillPools(p, r, isOwner)
	return res
}

// fillPools computes who may sign off.
func (res *Result) fillPools(p Policy, r Request, isOwner func(shared.ID) bool) {
	res.Excluded = map[shared.ID]ExcludeReason{}
	for _, c := range r.Approvers {
		switch {
		case !r.RequesterID.IsZero() && c.UserID == r.RequesterID:
			res.Excluded[c.UserID] = ExcludedRequester
		case isOwner(c.UserID):
			res.Excluded[c.UserID] = ExcludedAssetOwner
		case p.ExcludeAssignee && r.AssigneeID != nil && c.UserID == *r.AssigneeID:
			res.Excluded[c.UserID] = ExcludedAssignee
		default:
			if !containsID(res.Eligible, c.UserID) {
				res.Eligible = append(res.Eligible, c.UserID)
				if c.InSecurityPool && r.SecurityPoolConfigured {
					res.EligiblePool = append(res.EligiblePool, c.UserID)
				}
			}
		}
	}
	res.finishPools(p, r.SecurityPoolConfigured)
}

// fpLevelTier is the false-positive tier the organization's level gives.
func fpLevelTier(level string, material bool) Tier {
	switch level {
	case FPLevelOff:
		return TierSingle
	case FPLevelHighAndAbove:
		if material {
			return TierPeer
		}
		return TierSingle
	}
	return TierPeer
}

// Combine merges the evaluations of every finding a group decision covers
// into one: the highest class and tier (never below peer), the most
// approvals, the union of exclusions and only the people eligible for every
// member. Each member keeps its own acceptance cap (the caller applies it
// per member); MaxAcceptance here is the shortest.
func Combine(p Policy, securityPoolConfigured bool, results []Result) Result {
	if len(results) == 0 {
		return Result{Tier: TierPeer, Required: 1, Class: ClassStandard, Floor: TierPeer, MinNoteLength: 1,
			DecideWithin: p.DecideWithin(), Excluded: map[shared.ID]ExcludeReason{},
			Reasons: []string{ReasonGroupDecision, ReasonNoEligibleApprover}}
	}
	out := Result{Kind: results[0].Kind, Class: ClassStandard, Tier: TierPeer, Floor: TierPeer,
		Excluded: map[shared.ID]ExcludeReason{}, Reasons: []string{ReasonGroupDecision}}
	seen := map[string]bool{ReasonGroupDecision: true}
	eligible, pool := map[shared.ID]int{}, map[shared.ID]int{}
	for _, r := range results {
		out.mergeMember(r, seen)
		for _, id := range r.Eligible {
			eligible[id]++
		}
		for _, id := range r.EligiblePool {
			pool[id]++
		}
	}
	for id, n := range eligible {
		if _, excluded := out.Excluded[id]; n == len(results) && !excluded {
			out.Eligible = append(out.Eligible, id)
			if pool[id] == len(results) {
				out.EligiblePool = append(out.EligiblePool, id)
			}
		}
	}
	sortIDs(out.Eligible)
	sortIDs(out.EligiblePool)
	out.Required = out.Tier.RequiredApprovals()
	out.SecurityPool = out.Tier.NeedsSecurityPool()
	out.StepUp = out.StepUp || out.Tier.NeedsStepUp()
	out.MinNoteLength = out.Tier.MinNoteLength()
	out.finishPools(p, securityPoolConfigured)
	return out
}

// mergeMember folds one member's evaluation into a group's.
func (res *Result) mergeMember(r Result, seen map[string]bool) {
	res.Class = MaxClass(res.Class, r.Class)
	res.Tier = MaxTier(res.Tier, r.Tier)
	res.Floor = MaxTier(res.Floor, r.Floor)
	res.StepUp = res.StepUp || r.StepUp
	if res.MaxAcceptance == 0 || (r.MaxAcceptance > 0 && r.MaxAcceptance < res.MaxAcceptance) {
		res.MaxAcceptance = r.MaxAcceptance
	}
	if res.DecideWithin == 0 || r.DecideWithin < res.DecideWithin {
		res.DecideWithin = r.DecideWithin
	}
	for _, reason := range r.Reasons {
		switch reason {
		case ReasonNoEligibleApprover, ReasonNotEnoughApprovers, ReasonPoolFallback:
			continue // recomputed for the group
		}
		if !seen[reason] {
			seen[reason] = true
			res.Reasons = append(res.Reasons, reason)
		}
	}
	for id, why := range r.Excluded {
		if _, ok := res.Excluded[id]; !ok {
			res.Excluded[id] = why
		}
	}
}

// finishPools decides the security-pool fallback and explains a request
// nobody (or not enough people) can complete.
func (res *Result) finishPools(p Policy, securityPoolConfigured bool) {
	res.PoolFallback = false
	if res.SecurityPool && len(res.EligiblePool) == 0 && !(p.SecurityPoolStrict && securityPoolConfigured) {
		res.PoolFallback = true
		res.Reasons = append(res.Reasons, ReasonPoolFallback)
	}
	if res.Tier == TierSingle {
		return
	}
	switch {
	case len(res.Eligible) == 0 || (res.SecurityPool && !res.PoolFallback && len(res.EligiblePool) == 0):
		res.Reasons = append(res.Reasons, ReasonNoEligibleApprover)
	case len(res.Eligible) < res.Required:
		res.Reasons = append(res.Reasons, ReasonNotEnoughApprovers)
	}
}

func sortIDs(ids []shared.ID) {
	sort.Slice(ids, func(i, j int) bool { return ids[i].String() < ids[j].String() })
}

// Signoff is one approval already given.
type Signoff struct {
	UserID         shared.ID
	InSecurityPool bool
}

// Refusal codes of a sign-off (stable, returned by the API).
const (
	CodeApproverNotEligible = "APPROVER_NOT_ELIGIBLE"
	CodeNoEligibleApprover  = "NO_ELIGIBLE_APPROVER"
)

// Refusal reasons beyond ExcludeReason.
const (
	RefusedNotInPool     = "not_in_security_pool"
	RefusedAlreadySigned = "already_signed"
	RefusedNotApprover   = "not_an_approver"
)

// RefusalError is a refused sign-off with a stable code and reason.
type RefusalError struct {
	Code   string
	Reason string
	msg    string
}

func (e *RefusalError) Error() string { return e.msg }

// Unwrap lets callers map the refusal to an HTTP status.
func (e *RefusalError) Unwrap() error {
	if e.Code == CodeNoEligibleApprover {
		return shared.ErrConflict
	}
	return shared.ErrForbidden
}

// IsRefusal reports whether err is a refused sign-off and returns it.
func IsRefusal(err error) (*RefusalError, bool) {
	var r *RefusalError
	if errors.As(err, &r) {
		return r, true
	}
	return nil, false
}

func refuse(code, reason, msg string) error {
	return &RefusalError{Code: code, Reason: reason, msg: msg}
}

// NewRefusal builds a refused sign-off (for stores that detect one, such as
// a second sign-off by the same person).
func NewRefusal(code, reason, msg string) error { return refuse(code, reason, msg) }

// ValidPrior keeps the sign-offs whose signer still qualifies under r (the
// facts or the pools may have changed since they signed).
func (r Result) ValidPrior(prior []Signoff) []Signoff {
	out := make([]Signoff, 0, len(prior))
	for _, s := range prior {
		if containsID(r.Eligible, s.UserID) {
			s.InSecurityPool = containsID(r.EligiblePool, s.UserID)
			out = append(out, s)
		}
	}
	return out
}

// Sign checks that signer may sign off now, given the sign-offs already
// collected, and reports whether this sign-off completes the request.
func (r Result) Sign(signer shared.ID, prior []Signoff) (complete bool, err error) {
	if r.Tier == TierSingle {
		return false, refuse(CodeApproverNotEligible, string(ExcludedRequester), "this request is decided by its requester")
	}
	for _, s := range prior {
		if s.UserID == signer {
			return false, refuse(CodeApproverNotEligible, RefusedAlreadySigned, "you already approved this request; another person must approve it too")
		}
	}
	if why, ok := r.Excluded[signer]; ok {
		return false, refuse(CodeApproverNotEligible, string(why), excludedMessage(why))
	}
	if !containsID(r.Eligible, signer) {
		return false, refuse(CodeApproverNotEligible, RefusedNotApprover, "you may not approve this request")
	}
	if !r.Satisfiable() {
		return false, refuse(CodeNoEligibleApprover, ReasonNotEnoughApprovers,
			fmt.Sprintf("this request needs %d approver(s) and the organization does not have enough eligible people; change the approval policy or ask an administrator", r.Required))
	}
	valid := r.ValidPrior(prior)
	inPool := containsID(r.EligiblePool, signer)
	if r.SecurityPool && !r.PoolFallback {
		poolSigned := false
		for _, s := range valid {
			poolSigned = poolSigned || s.InSecurityPool
		}
		// The last required sign-off must come from the pool when none of
		// the earlier ones did.
		if !poolSigned && !inPool && len(valid)+1 >= r.Required {
			return false, refuse(CodeApproverNotEligible, RefusedNotInPool, "this request needs an approver from the security pool")
		}
	}
	return len(valid)+1 >= r.Required, nil
}

func excludedMessage(why ExcludeReason) string {
	switch why {
	case ExcludedRequester:
		return "you cannot approve your own request"
	case ExcludedAssetOwner:
		return "you own the asset of this finding; another person must approve"
	case ExcludedAssignee:
		return "you are assigned to this finding; another person must approve"
	}
	return "you may not approve this request"
}
