package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	auditsvc "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/auth/domainverify"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/verifieddomain"
)

// Settings > Domains: what the organization's verified SSO domains do to
// accounts on them (docs/rfcs/RFC-104). The tenant comes from the
// credential; a domain id of another organization is not found.

// SetDomainSignupPolicy wires the verified-domain service and the audit log
// for Settings > Domains.
func (h *TenantHandler) SetDomainSignupPolicy(svc *domainverify.Service, audit *auditsvc.AuditService) {
	h.domains, h.domainAudit = svc, audit
}

// SetDomainCapture wires the notice to existing accounts on a domain the
// organization starts to manage.
func (h *TenantHandler) SetDomainCapture(f func(ctx context.Context, vd *verifieddomain.VerifiedDomain)) {
	h.domainCapture = f
}

// DomainSignupPolicyResponse is one of the organization's domains with its
// sign-up policy. Only a verified SSO claim has effects.
type DomainSignupPolicyResponse struct {
	ID     string `json:"id"`
	Domain string `json:"domain"`
	Status string `json:"status"`
	// Purpose: sso or easm. Only sso domains have a sign-up policy.
	Purpose string `json:"purpose"`
	// Effective: the claim is verified, for SSO and unambiguous, so the
	// policy applies now. A lapsed claim stops every effect at once.
	Effective bool `json:"effective"`
	// JoinPolicy: off, approval or auto.
	JoinPolicy string `json:"join_policy"`
	// JoinRole: viewer or member.
	JoinRole           string `json:"join_role"`
	Discoverable       bool   `json:"discoverable"`
	SSORequired        bool   `json:"sso_required"`
	BlockNewWorkspaces bool   `json:"block_new_workspaces"`
	IncludeSubdomains  bool   `json:"include_subdomains"`
}

// UpdateDomainSignupPolicyRequest changes a domain's sign-up policy.
type UpdateDomainSignupPolicyRequest struct {
	JoinPolicy         string `json:"join_policy"`
	JoinRole           string `json:"join_role"`
	Discoverable       bool   `json:"discoverable"`
	SSORequired        bool   `json:"sso_required"`
	BlockNewWorkspaces bool   `json:"block_new_workspaces"`
	IncludeSubdomains  bool   `json:"include_subdomains"`
}

func toDomainSignupPolicyResponse(vd *verifieddomain.VerifiedDomain) DomainSignupPolicyResponse {
	p := vd.SignupPolicy()
	return DomainSignupPolicyResponse{
		ID: vd.ID().String(), Domain: vd.Domain(), Status: string(vd.Status()), Purpose: string(vd.Purpose()),
		Effective:  vd.AdmitsSSO() && !vd.ClaimConflict(),
		JoinPolicy: string(p.Join), JoinRole: p.JoinRole, Discoverable: p.Discoverable,
		SSORequired: p.SSORequired, BlockNewWorkspaces: p.BlockNewWorkspaces, IncludeSubdomains: p.IncludeSubdomains,
	}
}

// ListDomainSignupPolicies lists the organization's domains with their
// sign-up policy.
// @Summary      List the organization's domains and their sign-up policy
// @Description  Owner or admin. What each verified SSO domain does to accounts on it (join, discovery, SSO required, new organizations).
// @Tags         Tenants
// @Produce      json
// @Success      200  {array}  DomainSignupPolicyResponse
// @Router       /organization/settings/domains [get]
func (h *TenantHandler) ListDomainSignupPolicies(w http.ResponseWriter, r *http.Request) {
	tenantID, err := shared.IDFromString(middleware.GetTenantID(r.Context()))
	if err != nil {
		apierror.Unauthorized("Authentication required").WriteJSON(w)
		return
	}
	if h.domains == nil {
		apierror.ServiceUnavailable("Domain settings are not available").WriteJSON(w)
		return
	}
	rows, err := h.domains.List(r.Context(), tenantID)
	if err != nil {
		h.logger.Error("list domains", "error", err)
		apierror.InternalServerError("could not list domains").WriteJSON(w)
		return
	}
	out := make([]DomainSignupPolicyResponse, 0, len(rows))
	for _, vd := range rows {
		out = append(out, toDomainSignupPolicyResponse(vd))
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// UpdateDomainSignupPolicy changes what a verified SSO domain does to
// accounts on it. Owner, with a fresh step-up. Audited.
// @Summary      Change a domain's sign-up policy
// @Description  Owner with step-up. Only a verified SSO domain of this organization; sso_required needs a working SSO connection. Every effect stops when the claim lapses.
// @Tags         Tenants
// @Accept       json
// @Produce      json
// @Param        domain_id  path  string  true  "Domain ID"
// @Param        request   body  UpdateDomainSignupPolicyRequest  true  "Policy"
// @Success      200  {object}  DomainSignupPolicyResponse
// @Router       /organization/settings/domains/{domain_id}/signup-policy [put]
func (h *TenantHandler) UpdateDomainSignupPolicy(w http.ResponseWriter, r *http.Request) {
	tenantID, err := shared.IDFromString(middleware.GetTenantID(r.Context()))
	if err != nil {
		apierror.Unauthorized("Authentication required").WriteJSON(w)
		return
	}
	if h.domains == nil {
		apierror.ServiceUnavailable("Domain settings are not available").WriteJSON(w)
		return
	}
	id, err := shared.IDFromString(chi.URLParam(r, "domain_id"))
	if err != nil {
		apierror.NotFound("Domain not found").WriteJSON(w)
		return
	}
	var req UpdateDomainSignupPolicyRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	p := verifieddomain.SignupPolicy{
		Join: verifieddomain.JoinPolicy(strings.TrimSpace(req.JoinPolicy)), JoinRole: strings.TrimSpace(req.JoinRole),
		Discoverable: req.Discoverable, SSORequired: req.SSORequired,
		BlockNewWorkspaces: req.BlockNewWorkspaces, IncludeSubdomains: req.IncludeSubdomains,
	}
	vd, notify, err := h.domains.ChangeSignupPolicy(r.Context(), tenantID, id, p)
	switch {
	case err == nil:
	case errors.Is(err, verifieddomain.ErrNotFound):
		apierror.NotFound("Domain not found").WriteJSON(w)
		return
	case errors.Is(err, domainverify.ErrSSORequiredNeedsSSO):
		apierror.BadRequest("Set up a working single sign-on connection before requiring it").WriteJSON(w)
		return
	case errors.Is(err, verifieddomain.ErrPolicyNeedsSSOClaim):
		apierror.BadRequest("Only a verified single sign-on domain of this organization has a sign-up policy").WriteJSON(w)
		return
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest("join_policy must be off, approval or auto and join_role viewer or member").WriteJSON(w)
		return
	default:
		h.logger.Error("change domain sign-up policy", "error", err)
		apierror.InternalServerError("could not save the domain policy").WriteJSON(w)
		return
	}
	logOrgSSOEvent(r.Context(), h.domainAudit, h.logger, r,
		domainAuditEvent(audit.ActionSSOVerifiedDomainSignupPolicyChanged, vd,
			"Sign-up policy of domain '"+vd.Domain()+"' changed").
			WithMetadata("join_policy", string(p.Join)).WithMetadata("join_role", p.JoinRole).
			WithMetadata("discoverable", p.Discoverable).WithMetadata("sso_required", p.SSORequired).
			WithMetadata("block_new_workspaces", p.BlockNewWorkspaces).
			WithMetadata("include_subdomains", p.IncludeSubdomains).
			WithSeverity(audit.SeverityHigh))
	if notify && h.domainCapture != nil {
		h.domainCapture(r.Context(), vd)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(toDomainSignupPolicyResponse(vd))
}
