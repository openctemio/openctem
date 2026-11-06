package handler

// Ticket create policy endpoints (docs/architecture/ticket-create-policy.md):
// the per-integration "create issues automatically when" rule, its preview,
// and a finding's holds.

import (
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/jira"
	"github.com/openctemio/openctem/api/pkg/apierror"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/ticketpolicy"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// SetCreatePolicy wires the create policy gate (nil: the policy routes are
// not served).
func (h *TicketMappingHandler) SetCreatePolicy(g *jira.PolicyGate) { h.policy = g }

// HasCreatePolicy reports whether the policy routes are served.
func (h *TicketMappingHandler) HasCreatePolicy() bool { return h != nil && h.policy != nil }

// TicketCreatePolicyRequest is the editable part of a policy.
type TicketCreatePolicyRequest struct {
	MinSeverity      string `json:"min_severity"`
	MinPriorityClass string `json:"min_priority_class"`
	AlwaysKEV        bool   `json:"always_kev"`
	DailyCap         int    `json:"daily_cap"`
}

func (q TicketCreatePolicyRequest) policy() ticketpolicy.Policy {
	return ticketpolicy.Policy{
		MinSeverity: vulnerability.Severity(q.MinSeverity), MinPriorityClass: q.MinPriorityClass,
		AlwaysKEV: q.AlwaysKEV, DailyCap: q.DailyCap,
	}
}

// TicketCreatePolicyResponse is a policy with its counts.
type TicketCreatePolicyResponse struct {
	Policy   ticketpolicy.Policy `json:"policy"`
	Defaults ticketpolicy.Policy `json:"defaults"`
	Stored   bool                `json:"stored"`
	Stats    ticketpolicy.Stats  `json:"stats"`
}

func (h *TicketMappingHandler) policyTarget(w http.ResponseWriter, r *http.Request) (shared.ID, shared.ID, bool) {
	tid, ok := h.tenant(r)
	if !ok {
		apierror.Unauthorized("invalid tenant context").WriteJSON(w)
		return tid, shared.ID{}, false
	}
	iid, err := shared.IDFromString(chi.URLParam(r, "id"))
	if err != nil {
		apierror.NotFound("integration").WriteJSON(w)
		return tid, iid, false
	}
	return tid, iid, true
}

func (h *TicketMappingHandler) policyFail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("integration").WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.SafeBadRequest(err).WriteJSON(w)
	default:
		h.logger.Error("ticket create policy request failed", "error", logger.SanitizeValue(err.Error()))
		apierror.InternalServerError("internal server error").WriteJSON(w)
	}
}

// GetCreatePolicy handles GET /api/v1/integrations/{id}/ticket-create-policy.
//
//	@Summary		Ticket create policy of an integration
//	@Description	Which findings the automatic path files as issues on this Jira integration, with held counts by reason and today's creates. Defaults when none is stored.
//	@Tags			Integrations
//	@Produce		json
//	@Security		BearerAuth
//	@Param			id	path		string	true	"Integration ID"
//	@Success		200	{object}	TicketCreatePolicyResponse
//	@Failure		404	{object}	apierror.Error
//	@Router			/integrations/{id}/ticket-create-policy [get]
func (h *TicketMappingHandler) GetCreatePolicy(w http.ResponseWriter, r *http.Request) {
	tid, iid, ok := h.policyTarget(w, r)
	if !ok {
		return
	}
	p, st, err := h.policy.Policy(r.Context(), tid, iid)
	if err != nil {
		h.policyFail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, TicketCreatePolicyResponse{Policy: p, Defaults: ticketpolicy.Default(), Stored: !p.UpdatedAt.IsZero(), Stats: st})
}

// PutCreatePolicy handles PUT /api/v1/integrations/{id}/ticket-create-policy.
//
//	@Summary		Save the ticket create policy of an integration
//	@Description	Applies to automatic creates from the next one; held findings that now pass are created by the background job within the daily cap. Audited.
//	@Tags			Integrations
//	@Accept			json
//	@Produce		json
//	@Security		BearerAuth
//	@Param			id		path		string						true	"Integration ID"
//	@Param			body	body		TicketCreatePolicyRequest	true	"Policy"
//	@Success		200	{object}	TicketCreatePolicyResponse
//	@Failure		400	{object}	apierror.Error
//	@Failure		404	{object}	apierror.Error
//	@Router			/integrations/{id}/ticket-create-policy [put]
func (h *TicketMappingHandler) PutCreatePolicy(w http.ResponseWriter, r *http.Request) {
	tid, iid, ok := h.policyTarget(w, r)
	if !ok {
		return
	}
	var req TicketCreatePolicyRequest
	if !h.decode(w, r, &req) {
		return
	}
	before, after, err := h.policy.SavePolicy(r.Context(), tid, iid, req.policy(), mappingActor(r))
	if err != nil {
		h.policyFail(w, err)
		return
	}
	ev := auditapp.NewChangeEvent(auditdom.ActionTicketCreatePolicyUpdated, auditdom.ResourceTypeTicketCreatePolicy, iid.String(),
		policyAuditView(before), policyAuditView(after)).
		WithSeverity(auditdom.SeverityMedium).
		WithMessage("Ticket create policy updated").
		WithMetadata("integration_id", iid.String())
	recordConfigAudit(r.Context(), h.audit, h.logger, configAuditContext(r), ev)
	_, stats, err := h.policy.Policy(r.Context(), tid, iid)
	if err != nil {
		h.policyFail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, TicketCreatePolicyResponse{Policy: after, Defaults: ticketpolicy.Default(), Stored: true, Stats: stats})
}

func policyAuditView(p ticketpolicy.Policy) map[string]any {
	return map[string]any{
		"min_severity": string(p.MinSeverity), "min_priority_class": p.MinPriorityClass,
		"always_kev": p.AlwaysKEV, "daily_cap": p.DailyCap,
	}
}

// PreviewCreatePolicy handles POST /api/v1/integrations/{id}/ticket-create-policy/preview.
//
//	@Summary		Preview a ticket create policy
//	@Description	Counts only: of the findings first seen in the last 30 days, how many the policy lets through; of the integration's current holds, how many it would release.
//	@Tags			Integrations
//	@Accept			json
//	@Produce		json
//	@Security		BearerAuth
//	@Param			id		path		string						true	"Integration ID"
//	@Param			body	body		TicketCreatePolicyRequest	true	"Policy"
//	@Success		200	{object}	ticketpolicy.Preview
//	@Failure		400	{object}	apierror.Error
//	@Failure		404	{object}	apierror.Error
//	@Router			/integrations/{id}/ticket-create-policy/preview [post]
func (h *TicketMappingHandler) PreviewCreatePolicy(w http.ResponseWriter, r *http.Request) {
	tid, iid, ok := h.policyTarget(w, r)
	if !ok {
		return
	}
	var req TicketCreatePolicyRequest
	if !h.decode(w, r, &req) {
		return
	}
	pv, err := h.policy.Preview(r.Context(), tid, iid, req.policy())
	if err != nil {
		h.policyFail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, pv)
}

// SetCreatePolicy wires the create policy gate into the finding ticket
// routes (nil: no policy, every create goes through as before).
func (h *JiraWebhookHandler) SetCreatePolicy(g *jira.PolicyGate) { h.policy = g }

// ListTicketHolds handles GET /api/v1/findings/{id}/ticket-holds.
//
//	@Summary		Why a finding has no tracker issue yet
//	@Description	The finding's holds: the automatic path held it back on an integration (below the create policy, over the daily cap, or a failed create).
//	@Tags			Findings
//	@Produce		json
//	@Security		BearerAuth
//	@Param			id	path		string	true	"Finding ID"
//	@Success		200	{object}	map[string]any
//	@Failure		404	{object}	apierror.Error
//	@Router			/findings/{id}/ticket-holds [get]
func (h *JiraWebhookHandler) ListTicketHolds(w http.ResponseWriter, r *http.Request) {
	tid, fid, ok := h.linkIDs(w, r)
	if !ok {
		return
	}
	holds := []ticketpolicy.Hold{}
	if h.policy != nil {
		var err error
		if holds, err = h.policy.FindingHolds(r.Context(), tid, fid); err != nil {
			h.handleError(w, err)
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"holds": holds})
}

// writeBelowThreshold answers a manual create of a finding below the
// integration's policy without the confirmation: 409
// TICKET_BELOW_THRESHOLD with the policy, so the console can ask.
func writeBelowThreshold(w http.ResponseWriter, b *jira.BelowThreshold) {
	apierror.New(http.StatusConflict, apierror.Code("TICKET_BELOW_THRESHOLD"),
		"This finding is below the integration's create policy. Confirm to create the issue anyway.").
		WithDetails(map[string]any{
			"integration_id":     b.IntegrationID.String(),
			"min_severity":       string(b.Policy.MinSeverity),
			"min_priority_class": b.Policy.MinPriorityClass,
			"always_kev":         b.Policy.AlwaysKEV,
		}).WriteJSON(w)
}

// auditBelowThreshold records a confirmed create below the policy.
func (h *JiraWebhookHandler) auditBelowThreshold(r *http.Request, findingID string, b *jira.BelowThreshold, ticketKey string) {
	if h.audit == nil || b == nil {
		return
	}
	ev := auditapp.NewSuccessEvent(auditdom.ActionTicketCreatedBelowThreshold, auditdom.ResourceTypeFinding, findingID).
		WithSeverity(auditdom.SeverityMedium).
		WithMessage("Issue created for a finding below the create policy").
		WithMetadata("integration_id", b.IntegrationID.String()).
		WithMetadata("ticket_key", ticketKey).
		WithMetadata("min_severity", string(b.Policy.MinSeverity)).
		WithMetadata("min_priority_class", b.Policy.MinPriorityClass)
	recordConfigAudit(r.Context(), h.audit, h.logger, configAuditContext(r), ev)
}
