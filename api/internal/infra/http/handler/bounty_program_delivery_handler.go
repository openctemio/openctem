package handler

// Where events about a program's private assets may be delivered
// (docs/rfcs/RFC-065-bug-bounty-programs.md §15.4): the program's channels
// and the owner's organization-channel opt-in. Every change is audited.

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	auditsvc "github.com/openctemio/openctem/api/internal/app/audit"
	bpapp "github.com/openctemio/openctem/api/internal/app/bountyprogram"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	bp "github.com/openctemio/openctem/api/pkg/domain/bountyprogram"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ProgramChannelResponse is a notification integration attached to a program.
type ProgramChannelResponse struct {
	IntegrationID string    `json:"integration_id"`
	Name          string    `json:"name"`
	Provider      string    `json:"provider"`
	CreatedBy     *ActorRef `json:"created_by,omitempty"`
}

// ProgramDeliveryResponse is a program's delivery settings.
type ProgramDeliveryResponse struct {
	ProgramID string `json:"program_id"`
	// OrgChannels: an owner let events about the program's private assets
	// reach every organization-wide integration.
	OrgChannels bool                     `json:"org_channels"`
	Channels    []ProgramChannelResponse `json:"channels"`
}

// ProgramOrgChannelsRequest turns organization channels on or off.
type ProgramOrgChannelsRequest struct {
	Enabled bool `json:"enabled"`
	// Reason is required (10 to 500 characters) to turn them on.
	Reason string `json:"reason"`
}

func toDeliveryResponse(p *bp.Program, d bpapp.DeliverySettings) ProgramDeliveryResponse {
	out := ProgramDeliveryResponse{ProgramID: p.ID.String(), OrgChannels: d.OrgChannels,
		Channels: make([]ProgramChannelResponse, 0, len(d.Channels))}
	for _, c := range d.Channels {
		out.Channels = append(out.Channels, ProgramChannelResponse{IntegrationID: c.IntegrationID.String(),
			Name: c.Name, Provider: c.Provider, CreatedBy: idRef(c.CreatedBy)})
	}
	return out
}

// Delivery handles GET /api/v1/programs/{id}/delivery
// @Summary      Program delivery settings
// @Description  Where events about the program's private assets go: the notification integrations attached to it, and whether an owner lets them reach every organization-wide integration. Members and owners who accepted a private program's current terms; anyone else gets 404.
// @Tags         Programs
// @Produce      json
// @Param        id   path      string  true  "Program ID"
// @Success      200  {object}  ProgramDeliveryResponse
// @Failure      404  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /programs/{id}/delivery [get]
func (h *BountyProgramHandler) Delivery(w http.ResponseWriter, r *http.Request) {
	tenantID, actor, ok := h.caller(r)
	if !ok {
		apierror.Unauthorized("").WriteJSON(w)
		return
	}
	id, ok := h.programID(w, r)
	if !ok {
		return
	}
	p, d, err := h.svc.Delivery(r.Context(), tenantID, actor, id)
	if err != nil {
		h.writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toDeliveryResponse(p, d))
}

func (h *BountyProgramHandler) integrationID(w http.ResponseWriter, r *http.Request) (shared.ID, bool) {
	id, err := shared.IDFromString(chi.URLParam(r, "integration_id"))
	if err != nil {
		apierror.NotFound("Integration").WriteJSON(w)
		return shared.ID{}, false
	}
	return id, true
}

// AttachChannel handles PUT /api/v1/programs/{id}/notification-channels/{integration_id}
// @Summary      Attach program channel
// @Description  Let a notification integration of the organization receive events about the program's private assets (with the program's name). Needs integrations:manage, membership (or owner) with the current terms accepted, and a recent re-authentication. Idempotent. Audited.
// @Tags         Programs
// @Produce      json
// @Param        id             path      string  true  "Program ID"
// @Param        integration_id  path      string  true  "Notification integration ID"
// @Success      200  {object}  ProgramDeliveryResponse
// @Failure      404  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /programs/{id}/notification-channels/{integration_id} [put]
func (h *BountyProgramHandler) AttachChannel(w http.ResponseWriter, r *http.Request) {
	h.changeChannel(w, r, true)
}

// DetachChannel handles DELETE /api/v1/programs/{id}/notification-channels/{integration_id}
// @Summary      Detach program channel
// @Description  Stop sending events about the program's private assets to the integration. Needs integrations:manage and membership (or owner). Audited.
// @Tags         Programs
// @Produce      json
// @Param        id             path      string  true  "Program ID"
// @Param        integration_id  path      string  true  "Notification integration ID"
// @Success      200  {object}  ProgramDeliveryResponse
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /programs/{id}/notification-channels/{integration_id} [delete]
func (h *BountyProgramHandler) DetachChannel(w http.ResponseWriter, r *http.Request) {
	h.changeChannel(w, r, false)
}

func (h *BountyProgramHandler) changeChannel(w http.ResponseWriter, r *http.Request, attach bool) {
	tenantID, actor, ok := h.caller(r)
	if !ok {
		apierror.Unauthorized("").WriteJSON(w)
		return
	}
	id, ok := h.programID(w, r)
	if !ok {
		return
	}
	iid, ok := h.integrationID(w, r)
	if !ok {
		return
	}
	fn, action, msg := h.svc.DetachChannel, audit.ActionBountyProgramChannelDetached, "Program channel detached"
	if attach {
		fn, action, msg = h.svc.AttachChannel, audit.ActionBountyProgramChannelAttached, "Program channel attached"
	}
	p, err := fn(r.Context(), tenantID, actor, id, iid)
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.auditProgram(r, action, p, msg, map[string]any{"integration_id": iid.String()})
	_, d, err := h.svc.Delivery(r.Context(), tenantID, actor, id)
	if err != nil {
		// The change is made; a member may not read the settings back
		// (terms not accepted after a detach).
		writeJSON(w, http.StatusOK, toDeliveryResponse(p, bpapp.DeliverySettings{Channels: []bp.Channel{}}))
		return
	}
	writeJSON(w, http.StatusOK, toDeliveryResponse(p, d))
}

// SetOrgChannels handles PUT /api/v1/programs/{id}/org-channels
// @Summary      Organization channels for a private program
// @Description  Owners only: let events about a private program's assets reach every organization-wide integration (enabled=true, with a 10 to 500 character reason), or stop it. Program names stay scrubbed from those messages. Needs a recent re-authentication. Audited with the reason. A member who is not an owner gets 403; anyone who may not see the program gets 404.
// @Tags         Programs
// @Accept       json
// @Produce      json
// @Param        id    path      string                     true  "Program ID"
// @Param        body  body      ProgramOrgChannelsRequest  true  "Setting and reason"
// @Success      200   {object}  ProgramDeliveryResponse
// @Failure      400   {object}  apierror.Error
// @Failure      403   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /programs/{id}/org-channels [put]
func (h *BountyProgramHandler) SetOrgChannels(w http.ResponseWriter, r *http.Request) {
	tenantID, actor, ok := h.caller(r)
	if !ok {
		apierror.Unauthorized("").WriteJSON(w)
		return
	}
	id, ok := h.programID(w, r)
	if !ok {
		return
	}
	var req ProgramOrgChannelsRequest
	if !h.decode(w, r, &req) {
		return
	}
	p, reason, err := h.svc.ChangeOrgChannels(r.Context(), tenantID, actor, id, req.Enabled, req.Reason)
	if err != nil {
		h.writeError(w, err)
		return
	}
	msg := "Organization channels turned off for program"
	if req.Enabled {
		msg = "Organization channels turned on for program"
	}
	event := auditsvc.NewSuccessEvent(audit.ActionBountyProgramOrgChannelsChanged, audit.ResourceTypeBountyProgram, p.ID.String()).
		WithResourceName(p.Name).WithMessage(msg).
		WithMetadata("enabled", req.Enabled).
		WithMetadata("reason", reason).
		WithMetadata("visibility", string(visibility(p))).
		WithSeverity(audit.SeverityHigh)
	logRequestChange(h.audit, h.logger, r, event)
	_, d, err := h.svc.Delivery(r.Context(), tenantID, actor, id)
	if err != nil {
		writeJSON(w, http.StatusOK, toDeliveryResponse(p, bpapp.DeliverySettings{OrgChannels: req.Enabled, Channels: []bp.Channel{}}))
		return
	}
	writeJSON(w, http.StatusOK, toDeliveryResponse(p, d))
}
