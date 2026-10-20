package admin

// Four-eyes approvals for the console's catastrophic actions
// (docs/architecture/platform-console.md, "Four-eyes approvals").
//
// One super admin asks (with a reason); another active, named super admin
// approves; the requester then repeats the action, which spends the approval.
// An approval is bound to its requester, its action and its exact target, is
// single use and expires. Nobody approves their own request (checked here, in
// the service and by a database constraint).

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ApprovalAction names an action that needs a second super admin.
type ApprovalAction string

// The protected actions. Targets are canonical strings the handler builds from
// the request, so an approval for one target never covers another.
const (
	// ApprovalGrantSuperAdmin: a new super admin ("email:<address>"), or an
	// existing administrator who becomes an active super admin or stops being
	// break-glass ("admin:<id>").
	ApprovalGrantSuperAdmin ApprovalAction = "admin.grant_super_admin"
	// ApprovalRevokeSuperAdmin: an active super admin is demoted, deactivated,
	// marked break-glass or removed ("admin:<id>"). Without it one session
	// could remove the other approvers and then act alone.
	ApprovalRevokeSuperAdmin ApprovalAction = "admin.revoke_super_admin"
	// ApprovalConsoleMFAOff: "require security keys" is turned off ("off").
	ApprovalConsoleMFAOff ApprovalAction = "console_mfa.disable"
	// ApprovalPlatformIdPRemove: the administrators' identity provider is
	// removed ("remove"), switched off ("disable") or no longer required
	// ("require_idp_off").
	ApprovalPlatformIdPRemove ApprovalAction = "platform_idp.remove"
	// ApprovalPlatformIdPChange: the administrators' identity provider gets a
	// new issuer or client, or new trusted ACR/AMR values that replace the
	// console second factor. The target is the new configuration
	// (PlatformIdPChangeTarget), so an approval covers exactly that change.
	ApprovalPlatformIdPChange ApprovalAction = "platform_idp.change"
	// ApprovalResetCredentials: another administrator's console second factor
	// is removed ("admin:<id>"). Their next sign-in enrolls a new one, so one
	// session alone must not be able to arrange that.
	ApprovalResetCredentials ApprovalAction = "admin.reset_credentials"
	// ApprovalSignupOpen: the sign-up policy opens beyond its current level
	// ("mode=<mode>;accounts=<accounts>", the new policy).
	ApprovalSignupOpen ApprovalAction = "signup.open"
	// ApprovalAuditChainRebaseline: an organization's audit chain is
	// re-signed ("tenant:<id>").
	ApprovalAuditChainRebaseline ApprovalAction = "audit_chain.rebaseline"
	// ApprovalOrgPurge: an organization is deleted at once, before its grace
	// period ends ("tenant:<id>").
	ApprovalOrgPurge ApprovalAction = "organization.purge"
)

var (
	approvalIDTarget     = regexp.MustCompile(`^(admin|tenant):[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	approvalEmailTarget  = regexp.MustCompile(`^email:[^\s@]{1,64}@[^\s@]{1,255}$`)
	approvalSignupTarget = regexp.MustCompile(`^mode=(admin_only|self_service);accounts=(closed|domain|open)$`)
)

// maxApprovalTarget is the longest target (admin_approvals.target).
const maxApprovalTarget = 320

// ValidTarget reports whether target has the form this action uses.
func (a ApprovalAction) ValidTarget(target string) bool {
	if len(target) > maxApprovalTarget {
		return false
	}
	switch a {
	case ApprovalGrantSuperAdmin:
		return (approvalIDTarget.MatchString(target) && strings.HasPrefix(target, "admin:")) ||
			approvalEmailTarget.MatchString(target)
	case ApprovalRevokeSuperAdmin, ApprovalResetCredentials:
		return approvalIDTarget.MatchString(target) && strings.HasPrefix(target, "admin:")
	case ApprovalConsoleMFAOff:
		return target == "off"
	case ApprovalPlatformIdPRemove:
		return target == "remove" || target == "disable" || target == "require_idp_off"
	case ApprovalPlatformIdPChange:
		return validPlatformIdPChangeTarget(target)
	case ApprovalSignupOpen:
		return approvalSignupTarget.MatchString(target)
	case ApprovalAuditChainRebaseline, ApprovalOrgPurge:
		return approvalIDTarget.MatchString(target) && strings.HasPrefix(target, "tenant:")
	}
	return false
}

// IsValid reports whether a is one of the protected actions.
func (a ApprovalAction) IsValid() bool {
	switch a {
	case ApprovalGrantSuperAdmin, ApprovalRevokeSuperAdmin, ApprovalConsoleMFAOff,
		ApprovalPlatformIdPRemove, ApprovalSignupOpen, ApprovalAuditChainRebaseline, ApprovalOrgPurge,
		ApprovalPlatformIdPChange, ApprovalResetCredentials:
		return true
	}
	return false
}

// platformIdPChange is the canonical form of a platform IdP change target.
type platformIdPChange struct {
	Issuer   string   `json:"issuer"`
	ClientID string   `json:"client_id"`
	ACR      []string `json:"trusted_acr"`
	AMR      []string `json:"trusted_amr"`
}

var approvalHashTarget = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// PlatformIdPChangeTarget is the approval target of a platform IdP change: the
// canonical JSON of the new issuer, client id and trusted ACR/AMR values
// (sorted), readable by the approver. When that is longer than a target may
// be, it is the SHA-256 of the same JSON instead (the requester's reason then
// has to describe the change).
func PlatformIdPChangeTarget(issuer, clientID string, acr, amr []string) string {
	c := platformIdPChange{Issuer: issuer, ClientID: clientID, ACR: sortedCopy(acr), AMR: sortedCopy(amr)}
	raw, _ := json.Marshal(c) // strings and string slices always marshal
	if len(raw) <= maxApprovalTarget {
		return string(raw)
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func sortedCopy(v []string) []string {
	out := append([]string{}, v...)
	sort.Strings(out)
	return out
}

// validPlatformIdPChangeTarget accepts only the exact output of
// PlatformIdPChangeTarget: a hash, or canonical JSON that re-encodes to itself.
func validPlatformIdPChangeTarget(target string) bool {
	if approvalHashTarget.MatchString(target) {
		return true
	}
	var c platformIdPChange
	dec := json.NewDecoder(strings.NewReader(target))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil || c.Issuer == "" || c.ClientID == "" {
		return false
	}
	return PlatformIdPChangeTarget(c.Issuer, c.ClientID, c.ACR, c.AMR) == target
}

// TargetID returns the id in an "admin:<id>" or "tenant:<id>" target.
func TargetID(target string) (shared.ID, bool) {
	_, raw, ok := strings.Cut(target, ":")
	if !ok || !approvalIDTarget.MatchString(target) {
		return shared.ID{}, false
	}
	id, err := shared.IDFromString(raw)
	return id, err == nil
}

// ApprovalTTL is how long a request stays usable: approval and use must both
// happen within it.
const ApprovalTTL = 24 * time.Hour

// Decisions recorded on an approval.
const (
	DecisionApproved = "approved"
	DecisionRejected = "rejected"
	DecisionCanceled = "canceled"
)

// Approval statuses (derived, never stored).
const (
	ApprovalPending  = "pending"
	ApprovalApproved = "approved"
	ApprovalRejected = "rejected"
	ApprovalCanceled = "canceled"
	ApprovalExpired  = "expired"
	ApprovalUsed     = "used"
)

// Approval is one request for a second super admin's approval.
type Approval struct {
	ID          shared.ID
	Action      ApprovalAction
	Target      string
	TargetLabel string
	Reason      string
	RequestedBy shared.ID
	RequestedAt time.Time
	ExpiresAt   time.Time
	DecidedBy   *shared.ID
	DecidedAt   *time.Time
	Decision    string
	Note        string
	ConsumedAt  *time.Time

	// Filled by List for display.
	RequestedByEmail string
	DecidedByEmail   string
}

// Status is the approval's state at now.
func (a *Approval) Status(now time.Time) string {
	switch {
	case a.ConsumedAt != nil:
		return ApprovalUsed
	case a.Decision == DecisionRejected:
		return ApprovalRejected
	case a.Decision == DecisionCanceled:
		return ApprovalCanceled
	case !now.Before(a.ExpiresAt):
		return ApprovalExpired
	case a.Decision == DecisionApproved:
		return ApprovalApproved
	}
	return ApprovalPending
}

// Approval errors.
var (
	ErrApprovalNotFound = fmt.Errorf("%w: approval not found", shared.ErrNotFound)
	// ErrSelfApproval: the requester can never approve or reject their own request.
	ErrSelfApproval = fmt.Errorf("%w: another super admin must decide on your request", shared.ErrForbidden)
	// ErrApproverNotEligible: break-glass and inactive administrators do not approve.
	ErrApproverNotEligible = fmt.Errorf("%w: only an active super admin who is not a break-glass account can approve", shared.ErrForbidden)
	// ErrApprovalNotPending: already decided, used or expired.
	ErrApprovalNotPending = fmt.Errorf("%w: this request is no longer pending", shared.ErrConflict)
	// ErrNotRequester: only the requester cancels a request.
	ErrNotRequester = fmt.Errorf("%w: only the administrator who asked can cancel this request", shared.ErrForbidden)
	// ErrFourEyesInactive: no second super admin exists, so nothing can be requested.
	ErrFourEyesInactive = fmt.Errorf("%w: there is no other super admin to approve; the action runs on your confirmation alone", shared.ErrConflict)
	// ErrInvalidApproval: unknown action, bad target or missing reason.
	ErrInvalidApproval = fmt.Errorf("%w: invalid approval request", shared.ErrValidation)
)

// ApprovalRequiredError is returned by the gate when the action needs an
// approval the requester does not have yet.
type ApprovalRequiredError struct {
	Action      ApprovalAction
	Target      string
	TargetLabel string
	// PendingID is the requester's open request for the same action and
	// target, when there is one.
	PendingID *shared.ID
}

func (e *ApprovalRequiredError) Error() string {
	return fmt.Sprintf("a second super admin must approve %s (%s)", e.Action, e.Target)
}

// ApprovalRepository persists approvals. Every state change is conditional, so
// a concurrent decision or use can never apply twice.
type ApprovalRepository interface {
	Create(ctx context.Context, a *Approval) error
	Get(ctx context.Context, id shared.ID) (*Approval, error)
	// List returns pending requests and those requested after since, newest
	// first, with the administrators' emails.
	List(ctx context.Context, since time.Time, limit int) ([]*Approval, error)
	// FindPending returns the requester's open (undecided, unexpired) request
	// for action and target, or ErrApprovalNotFound.
	FindPending(ctx context.Context, requestedBy shared.ID, action ApprovalAction, target string, now time.Time) (*Approval, error)
	// Decide records a decision on a pending, unexpired request. An approval
	// or rejection by the requester is refused (ErrSelfApproval); anything
	// not pending gives ErrApprovalNotPending.
	Decide(ctx context.Context, id, decidedBy shared.ID, decision, note string, now time.Time) (*Approval, error)
	// Consume spends the requester's oldest approved, unused, unexpired
	// approval for action and target, or returns ErrApprovalNotFound.
	Consume(ctx context.Context, requestedBy shared.ID, action ApprovalAction, target string, now time.Time) (*Approval, error)
	// Release makes a consumed approval usable again (the action failed).
	Release(ctx context.Context, id shared.ID) error
}
