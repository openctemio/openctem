package exposure

import (
	"context"
	"fmt"
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
// the organization owner when nobody else can approve (audited Critical).
// Lower severities apply at once.
//
// Design: api/docs/architecture/finding-status-lifecycle.md ("Four-eyes on
// exposure dispositions").
type DispositionGate struct {
	repo   exposuredom.DispositionRepository
	audit  *auditapp.AuditService
	logger *logger.Logger
}

// NewDispositionGate creates the gate. audit may be nil (no audit log).
func NewDispositionGate(repo exposuredom.DispositionRepository, audit *auditapp.AuditService, log *logger.Logger) *DispositionGate {
	return &DispositionGate{repo: repo, audit: audit, logger: log.With("component", "exposure-disposition")}
}

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
		return g.request(ctx, in)
	}
	if pending.RequestedState != in.State {
		return DispositionDecision{}, exposuredom.ErrDispositionConflict
	}
	return g.approve(ctx, in, pending)
}

// request stores a new pending request, or applies at once when the caller
// is the owner and nobody else can approve.
func (g *DispositionGate) request(ctx context.Context, in DispositionInput) (DispositionDecision, error) {
	req, err := exposuredom.NewDispositionRequest(in.TenantID, in.Event.ID(), in.ActorID, in.State, in.Reason)
	if err != nil {
		return DispositionDecision{}, err
	}
	if err := g.repo.Create(ctx, req); err != nil {
		return DispositionDecision{}, err
	}
	g.record(ctx, in, auditdom.ActionExposureDispositionRequested, req, "Disposition requested; a second approver must confirm")

	self, err := g.mayApproveOwn(ctx, in)
	if err != nil || !self {
		return DispositionDecision{Request: req}, err
	}
	return g.approve(ctx, in, req)
}

// approve confirms a pending request.
func (g *DispositionGate) approve(ctx context.Context, in DispositionInput, req *exposuredom.DispositionRequest) (DispositionDecision, error) {
	self := false
	if req.IsRequestedBy(in.ActorID) {
		ok, err := g.mayApproveOwn(ctx, in)
		if err != nil {
			return DispositionDecision{}, err
		}
		if !ok {
			return DispositionDecision{}, exposuredom.ErrDispositionSelfApproval
		}
		self = true
	}
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
		msg = "Disposition approved by its own requester (the owner, the only eligible approver)"
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
