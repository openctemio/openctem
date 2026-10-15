package exposure

import (
	"context"
	"fmt"
	"strings"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	exposuredom "github.com/openctemio/openctem/api/pkg/domain/exposure"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// DispositionGate is the four-eyes rule for accepting the risk of, or marking
// a false positive, a high or critical exposure (leaked credentials
// included). The first approver's call stores a pending request; a different
// approver's call for the same disposition confirms it and the caller then
// applies the state. The requester never confirms their own request, except
// the organization owner when nobody else can approve: that is an explicit
// call (SelfApprove) with a reason and a fresh code from the owner's
// authenticator app, audited Critical; a refused attempt is audited High.
// Nothing is ever approved automatically. Lower severities apply at once.
//
// Threat model: a stolen session or password of a lone owner must not be
// enough to hide a high or critical exposure; the fresh code proves the
// owner is present. Approving one's own request when another approver
// exists stays refused.
//
// Design: api/docs/architecture/finding-status-lifecycle.md ("Four-eyes on
// exposure dispositions").
type DispositionGate struct {
	repo   exposuredom.DispositionRepository
	totp   TOTPVerifier
	audit  *auditapp.AuditService
	logger *logger.Logger
}

// NewDispositionGate creates the gate. audit may be nil (no audit log).
func NewDispositionGate(repo exposuredom.DispositionRepository, audit *auditapp.AuditService, log *logger.Logger) *DispositionGate {
	return &DispositionGate{repo: repo, audit: audit, logger: log.With("component", "exposure-disposition")}
}

// TOTPVerifier checks a fresh code from the user's authenticator app. It
// answers exposuredom.ErrDispositionSelfApprovalNeedsTOTP when the account
// has no authenticator and exposuredom.ErrDispositionSelfApprovalBadCode for
// a wrong or reused code.
type TOTPVerifier interface {
	VerifyFreshTOTP(ctx context.Context, userID, code string) error
}

// SelfApproval is an owner's explicit approval of their own pending
// disposition request, proven by a fresh authenticator code.
type SelfApproval struct {
	Requested bool
	Code      string
}

// SetTOTP wires the authenticator check of an owner's own approval. Without
// it an own approval is refused (fail closed).
func (g *DispositionGate) SetTOTP(v TOTPVerifier) { g.totp = v }

// DispositionInput is one approver's call to set a disposition.
type DispositionInput struct {
	TenantID shared.ID
	Event    *exposuredom.ExposureEvent
	ActorID  shared.ID
	State    exposuredom.State
	Reason   string
	// ApproverPermissions are the permissions the route requires; an
	// eligible second approver holds all of them.
	ApproverPermissions []string
	Audit               auditapp.AuditContext
	// SelfApprove: the requester approves their own pending request (owner
	// only, when no other approver exists), proven by TOTPCode; Reason is
	// required.
	SelfApprove bool
	TOTPCode    string
}

// DispositionDecision says what the caller does next.
type DispositionDecision struct {
	// Apply: set the state now. False: a request is pending.
	Apply bool
	// Notes to record on the state change.
	Notes string
	// Request is the pending request (Apply false) or the one this call
	// approved (Apply true); nil on the one-step path.
	Request      *exposuredom.DispositionRequest
	SelfApproved bool
}

// Decide applies the four-eyes rule to one call.
func (g *DispositionGate) Decide(ctx context.Context, in DispositionInput) (DispositionDecision, error) {
	if in.Event == nil || !exposuredom.IsGatedState(in.State) || !exposuredom.NeedsSecondApprover(in.Event.Severity()) {
		return DispositionDecision{Apply: true, Notes: in.Reason}, nil
	}
	if in.ActorID.IsZero() {
		return DispositionDecision{}, fmt.Errorf("%w: a disposition of a %s exposure needs a signed-in approver", shared.ErrForbidden, in.Event.Severity())
	}
	if len(in.Reason) > exposuredom.MaxDispositionReasonLength {
		return DispositionDecision{}, fmt.Errorf("%w: reason is longer than %d characters", shared.ErrValidation, exposuredom.MaxDispositionReasonLength)
	}
	// A request the state machine could never apply is refused up front.
	if !in.Event.State().CanTransitionTo(in.State) {
		return DispositionDecision{}, fmt.Errorf("%w: %w: cannot transition from %s to %s",
			shared.ErrValidation, exposuredom.ErrInvalidStateTransition, in.Event.State(), in.State)
	}

	pending, err := g.repo.GetPending(ctx, in.TenantID, in.Event.ID())
	if err != nil {
		return DispositionDecision{}, err
	}
	if pending == nil {
		if in.SelfApprove {
			return DispositionDecision{}, exposuredom.ErrNoPendingDisposition
		}
		return g.request(ctx, in)
	}
	if pending.RequestedState != in.State {
		return DispositionDecision{}, exposuredom.ErrDispositionConflict
	}
	if in.SelfApprove {
		return g.selfApprove(ctx, in, pending)
	}
	return g.approve(ctx, in, pending)
}

// request stores a new pending request. It never applies: even a lone
// owner approves their own request in a separate, explicit call.
func (g *DispositionGate) request(ctx context.Context, in DispositionInput) (DispositionDecision, error) {
	req, err := exposuredom.NewDispositionRequest(in.TenantID, in.Event.ID(), in.ActorID, in.State, in.Reason)
	if err != nil {
		return DispositionDecision{}, err
	}
	if err := g.repo.Create(ctx, req); err != nil {
		return DispositionDecision{}, err
	}
	g.record(ctx, in, auditdom.ActionExposureDispositionRequested, req, "Disposition requested; a second approver must confirm")
	return DispositionDecision{Request: req}, nil
}

// approve confirms a pending request by a second approver.
func (g *DispositionGate) approve(ctx context.Context, in DispositionInput, req *exposuredom.DispositionRequest) (DispositionDecision, error) {
	if req.IsRequestedBy(in.ActorID) {
		return DispositionDecision{}, exposuredom.ErrDispositionSelfApproval
	}
	return g.decide(ctx, in, req, false)
}

// selfApprove is the owner's explicit approval of their own request when no
// other approver exists: reason and a fresh authenticator code required.
// Every refusal is audited.
func (g *DispositionGate) selfApprove(ctx context.Context, in DispositionInput, req *exposuredom.DispositionRequest) (DispositionDecision, error) {
	if err := g.checkSelfApproval(ctx, in, req); err != nil {
		g.recordRefusal(ctx, in, req, err)
		return DispositionDecision{}, err
	}
	return g.decide(ctx, in, req, true)
}

func (g *DispositionGate) checkSelfApproval(ctx context.Context, in DispositionInput, req *exposuredom.DispositionRequest) error {
	if !req.IsRequestedBy(in.ActorID) {
		return fmt.Errorf("%w: only the requester approves their own request; approve it as a second approver instead", shared.ErrValidation)
	}
	ok, err := g.mayApproveOwn(ctx, in)
	if err != nil {
		return err
	}
	if !ok {
		return exposuredom.ErrDispositionSelfApprovalNotAllowed
	}
	if strings.TrimSpace(in.Reason) == "" {
		return exposuredom.ErrDispositionSelfApprovalNeedsReason
	}
	if g.totp == nil || strings.TrimSpace(in.TOTPCode) == "" {
		return exposuredom.ErrDispositionSelfApprovalBadCode
	}
	return g.totp.VerifyFreshTOTP(ctx, in.ActorID.String(), strings.TrimSpace(in.TOTPCode))
}

// SelfApprovalAvailable reports whether the user could approve their own
// request (an owner, and fewer than two eligible approvers). The UI uses it
// to offer the explicit call; the call re-checks everything.
func (g *DispositionGate) SelfApprovalAvailable(ctx context.Context, tenantID, userID shared.ID, perms []string) (bool, error) {
	return g.mayApproveOwn(ctx, DispositionInput{TenantID: tenantID, ActorID: userID, ApproverPermissions: perms})
}

// decide moves the request to approved and audits it.
func (g *DispositionGate) decide(ctx context.Context, in DispositionInput, req *exposuredom.DispositionRequest, self bool) (DispositionDecision, error) {
	won, err := g.repo.Decide(ctx, in.TenantID, req.ID, exposuredom.DispositionApproved, in.ActorID, in.Reason, self)
	if err != nil {
		return DispositionDecision{}, err
	}
	if !won {
		return DispositionDecision{}, fmt.Errorf("%w: the request was decided by someone else", shared.ErrConflict)
	}
	req.Status = exposuredom.DispositionApproved
	approver := in.ActorID
	req.DecidedBy = &approver
	req.SelfApproved = self

	action, msg := auditdom.ActionExposureDispositionApproved, "Disposition approved by a second approver"
	if self {
		action = auditdom.ActionExposureDispositionSelfApproved
		msg = "Disposition approved by its own requester (the owner, the only eligible approver) with a fresh authenticator code"
	}
	g.record(ctx, in, action, req, msg)

	notes := req.Reason
	if in.Reason != "" && in.Reason != req.Reason {
		notes = fmt.Sprintf("%s (approved: %s)", req.Reason, in.Reason)
	}
	return DispositionDecision{Apply: true, Notes: notes, Request: req, SelfApproved: self}, nil
}

// Undo puts an approved request back to pending after the state change it
// approved failed, so it can be approved again or rejected.
func (g *DispositionGate) Undo(ctx context.Context, d DispositionDecision) {
	if d.Request == nil || d.Request.Status != exposuredom.DispositionApproved {
		return
	}
	if err := g.repo.Reopen(ctx, d.Request.TenantID, d.Request.ID); err != nil {
		g.logger.Warn("failed to reopen disposition request", "request_id", d.Request.ID.String(), "error", err)
	}
}

// Reject rejects the exposure's pending request; the requester rejecting
// their own request cancels it.
func (g *DispositionGate) Reject(ctx context.Context, in DispositionInput) (*exposuredom.DispositionRequest, error) {
	if len(in.Reason) > exposuredom.MaxDispositionReasonLength {
		return nil, fmt.Errorf("%w: reason is longer than %d characters", shared.ErrValidation, exposuredom.MaxDispositionReasonLength)
	}
	pending, err := g.repo.GetPending(ctx, in.TenantID, in.Event.ID())
	if err != nil {
		return nil, err
	}
	if pending == nil {
		return nil, exposuredom.ErrNoPendingDisposition
	}
	status := exposuredom.DispositionRejected
	if pending.IsRequestedBy(in.ActorID) {
		status = exposuredom.DispositionCanceled
	}
	won, err := g.repo.Decide(ctx, in.TenantID, pending.ID, status, in.ActorID, in.Reason, false)
	if err != nil {
		return nil, err
	}
	if !won {
		return nil, fmt.Errorf("%w: the request was decided by someone else", shared.ErrConflict)
	}
	pending.Status = status
	by := in.ActorID
	pending.DecidedBy = &by
	pending.DecisionReason = in.Reason
	g.record(ctx, in, auditdom.ActionExposureDispositionRejected, pending, "Disposition request "+string(status))
	return pending, nil
}

// Pending returns the pending requests of the given exposures.
func (g *DispositionGate) Pending(ctx context.Context, tenantID shared.ID, ids []shared.ID) (map[shared.ID]*exposuredom.DispositionRequest, error) {
	return g.repo.ListPending(ctx, tenantID, ids)
}

// mayApproveOwn: only the owner, and only when nobody else can approve.
func (g *DispositionGate) mayApproveOwn(ctx context.Context, in DispositionInput) (bool, error) {
	n, err := g.repo.CountEligibleApprovers(ctx, in.TenantID, in.ApproverPermissions)
	if err != nil {
		return false, err
	}
	if n >= 2 {
		return false, nil
	}
	return g.repo.IsTenantOwner(ctx, in.TenantID, in.ActorID)
}

// recordRefusal audits a refused own approval at High.
func (g *DispositionGate) recordRefusal(ctx context.Context, in DispositionInput, req *exposuredom.DispositionRequest, cause error) {
	if g.audit == nil {
		return
	}
	actx := in.Audit
	if actx.TenantID == "" {
		actx.TenantID = in.TenantID.String()
	}
	if actx.ActorID == "" {
		actx.ActorID = in.ActorID.String()
	}
	action := auditdom.ActionExposureDispositionSelfApprovalRefused
	event := auditapp.NewFailureEvent(action, auditdom.ResourceTypeExposure, in.Event.ID().String(), cause).
		WithResourceName(in.Event.Title()).
		WithMessage("Own approval of a disposition refused").
		WithMetadata("request_id", req.ID.String()).
		WithMetadata("requested_state", string(req.RequestedState)).
		WithMetadata("severity", in.Event.Severity().String()).
		WithSeverity(auditdom.SeverityForAction(action))
	if err := g.audit.LogEvent(ctx, actx, event); err != nil {
		g.logger.Warn("failed to audit refused own approval", "error", err)
	}
}

func (g *DispositionGate) record(ctx context.Context, in DispositionInput, action auditdom.Action, req *exposuredom.DispositionRequest, msg string) {
	if g.audit == nil {
		return
	}
	actx := in.Audit
	if actx.TenantID == "" {
		actx.TenantID = in.TenantID.String()
	}
	if actx.ActorID == "" {
		actx.ActorID = in.ActorID.String()
	}
	requestedBy := ""
	if req.RequestedBy != nil {
		requestedBy = req.RequestedBy.String()
	}
	event := auditapp.NewSuccessEvent(action, auditdom.ResourceTypeExposure, in.Event.ID().String()).
		WithResourceName(in.Event.Title()).
		WithMessage(msg).
		WithMetadata("request_id", req.ID.String()).
		WithMetadata("requested_state", string(req.RequestedState)).
		WithMetadata("requested_by", requestedBy).
		WithMetadata("severity", in.Event.Severity().String()).
		WithMetadata("status", string(req.Status)).
		WithSeverity(auditdom.SeverityForAction(action))
	if err := g.audit.LogEvent(ctx, actx, event); err != nil {
		g.logger.Warn("failed to audit exposure disposition", "action", string(action), "error", err)
	}
}

// PendingDispositionView is the API view of a pending disposition request.
// It names the requester by id only; the web shows "you" or "another
// approver".
type PendingDispositionView struct {
	ID             string    `json:"id"`
	RequestedState string    `json:"requested_state"`
	RequestedBy    string    `json:"requested_by,omitempty"`
	Reason         string    `json:"reason"`
	CreatedAt      time.Time `json:"created_at"`
	// SelfApprovalAvailable: the viewer made this request and may approve it
	// themselves (the owner, no other approver) with a fresh authenticator
	// code. Set only for the viewer's own request.
	SelfApprovalAvailable bool `json:"self_approval_available,omitempty"`
}

// PendingView converts a pending request; nil for nil or a decided one.
func PendingView(r *exposuredom.DispositionRequest) *PendingDispositionView {
	if r == nil || r.Status != exposuredom.DispositionPending {
		return nil
	}
	v := &PendingDispositionView{ID: r.ID.String(), RequestedState: string(r.RequestedState), Reason: r.Reason, CreatedAt: r.CreatedAt}
	if r.RequestedBy != nil {
		v.RequestedBy = r.RequestedBy.String()
	}
	return v
}
