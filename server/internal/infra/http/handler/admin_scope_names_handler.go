package handler

// Blocked target names (docs/rfcs/RFC-154-blocked-target-names.md): the
// government and military rule of the scope guardrails, the operator's own
// blocked names and the per-organization exceptions, in the console.
//
// Reads: any console reader (platform.settings.read). Writes: a platform
// owner (platform.settings.scope_guardrails) with a fresh authenticator code
// (route) and a reason; on a hosted service (MANAGED_SERVICE) a grant, an
// extension or turning the rule off also needs a second owner's approval.
// No tenant route reaches any of it.

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/app/adminapproval"
	"github.com/openctemio/openctem/api/internal/app/consolesetting"
	"github.com/openctemio/openctem/api/internal/app/scopenames"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/platformsetting"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// ScopeBlockedNamesResponse is the policy.
type ScopeBlockedNamesResponse struct {
	// GovernmentRule: the built-in government and military rule is on.
	GovernmentRule bool `json:"government_rule"`
	// Names are the operator's blocked names set in the console.
	Names []string `json:"names"`
	// EnvNames are SCOPE_DENY_EXTRA's names: always blocked, read-only here.
	EnvNames []string `json:"env_names"`
	// MaxExceptionDays is the longest exception.
	MaxExceptionDays int `json:"max_exception_days"`
	// SecondApproval: a hosted service; grants, extensions and turning the
	// rule off need a second owner.
	SecondApproval bool `json:"second_approval"`
	Version        int  `json:"version"`
	SettingChange
}

// UpdateScopeBlockedNamesRequest changes the policy.
type UpdateScopeBlockedNamesRequest struct {
	GovernmentRule   *bool    `json:"government_rule"`
	Names            []string `json:"names"`
	MaxExceptionDays int      `json:"max_exception_days"`
	Reason           string   `json:"reason"`
	Version          int      `json:"version"`
}

// ScopeNameExceptionResponse is one exception.
type ScopeNameExceptionResponse struct {
	ID                string  `json:"id"`
	OrganizationID    string  `json:"organization_id"`
	OrganizationName  string  `json:"organization_name"`
	Name              string  `json:"name"`
	IncludeSubdomains bool    `json:"include_subdomains"`
	Reason            string  `json:"reason"`
	AuthorizationRef  string  `json:"authorization_ref"`
	GrantedBy         string  `json:"granted_by"`
	GrantedAt         string  `json:"granted_at"`
	ExpiresAt         string  `json:"expires_at"`
	State             string  `json:"state"`
	RevokedAt         *string `json:"revoked_at,omitempty"`
	RevokedBy         string  `json:"revoked_by,omitempty"`
	RevokeReason      string  `json:"revoke_reason,omitempty"`
}

// ScopeNameExceptionListResponse lists the exceptions.
type ScopeNameExceptionListResponse struct {
	Items []ScopeNameExceptionResponse `json:"items"`
}

// GrantScopeNameExceptionRequest grants an exception. ExpiresAt is RFC 3339
// or a day (YYYY-MM-DD: the end of that day, UTC).
type GrantScopeNameExceptionRequest struct {
	OrganizationID    string `json:"organization_id"`
	Name              string `json:"name"`
	IncludeSubdomains bool   `json:"include_subdomains"`
	Reason            string `json:"reason"`
	AuthorizationRef  string `json:"authorization_ref"`
	ExpiresAt         string `json:"expires_at"`
}

// ExtendScopeNameExceptionRequest moves an exception's expiry.
type ExtendScopeNameExceptionRequest struct {
	ExpiresAt string `json:"expires_at"`
	Reason    string `json:"reason"`
}

// RevokeScopeNameExceptionRequest ends an exception.
type RevokeScopeNameExceptionRequest struct {
	Reason string `json:"reason"`
}

func (h *AdminPlatformSettingsHandler) scopeNamesResponse(r *http.Request, v scopenames.View) ScopeBlockedNamesResponse {
	names := v.Settings.Names
	if names == nil {
		names = []string{}
	}
	env := v.EnvNames
	if env == nil {
		env = []string{}
	}
	return ScopeBlockedNamesResponse{GovernmentRule: v.Settings.RuleOn(), Names: names, EnvNames: env,
		MaxExceptionDays: v.Settings.MaxDays(), SecondApproval: v.Managed, Version: v.Meta.Version,
		SettingChange: h.change(r.Context(), v.Meta.UpdatedAt, v.Meta.UpdatedBy)}
}

func scopeNameExceptionResponse(e scopenames.Exception, now time.Time) ScopeNameExceptionResponse {
	out := ScopeNameExceptionResponse{ID: e.ID.String(), OrganizationID: e.TenantID.String(), OrganizationName: e.TenantName,
		Name: e.Name, IncludeSubdomains: e.Subdomains, Reason: e.Reason, AuthorizationRef: e.AuthorizationRef,
		GrantedBy: e.GrantedByEmail, GrantedAt: e.GrantedAt.UTC().Format(time.RFC3339),
		ExpiresAt: e.ExpiresAt.UTC().Format(time.RFC3339), State: e.State(now),
		RevokedBy: e.RevokedByEmail, RevokeReason: e.RevokeReason}
	if e.RevokedAt != nil {
		s := e.RevokedAt.UTC().Format(time.RFC3339)
		out.RevokedAt = &s
	}
	return out
}

func scopeNamesRequest(r *http.Request) scopenames.Request {
	return scopenames.Request{IP: middleware.ClientIP(r), UserAgent: r.UserAgent(), Method: r.Method, Path: r.URL.Path}
}

// parseExpiry reads RFC 3339 or a day (the end of that day, UTC).
func parseExpiry(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, true
	}
	if d, err := time.Parse(time.DateOnly, s); err == nil {
		return d.Add(24*time.Hour - time.Second), true
	}
	return time.Time{}, false
}

// writeScopeNamesError maps the service's errors.
func (h *AdminPlatformSettingsHandler) writeScopeNamesError(w http.ResponseWriter, err error) {
	var de *shared.DomainError
	switch {
	case errors.Is(err, platformsetting.ErrVersionConflict):
		apierror.Conflict("The blocked names policy was changed by someone else; reload and try again").WriteJSON(w)
	case errors.Is(err, consolesetting.ErrReasonRequired):
		apierror.BadRequest("A reason is required (1-500 characters, one paragraph)").WriteJSON(w)
	case errors.As(err, &de) && de.Code != "":
		status := http.StatusBadRequest
		switch {
		case errors.Is(err, shared.ErrNotFound):
			status = http.StatusNotFound
		case errors.Is(err, shared.ErrConflict):
			status = http.StatusConflict
		}
		apierror.New(status, apierror.Code(de.Code), de.Message).WriteJSON(w)
	default:
		h.logger.Error("blocked names change failed", "error", logger.SanitizeError(err))
		apierror.InternalServerError("could not save the blocked names policy").WriteJSON(w)
	}
}

// GetScopeBlockedNames returns the policy.
// @Summary      Blocked target names policy
// @Description  The government and military rule switch, the operator's blocked names (console and SCOPE_DENY_EXTRA) and the longest exception. Any console reader.
// @Tags         Admin System
// @Produce      json
// @Success      200  {object}  ScopeBlockedNamesResponse
// @Security     AdminAuth
// @Router       /admin/settings/scope-blocked-names [get]
func (h *AdminPlatformSettingsHandler) GetScopeBlockedNames(w http.ResponseWriter, r *http.Request) {
	v, err := h.ScopeNames.Get(r.Context())
	if err != nil {
		h.writeScopeNamesError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, h.scopeNamesResponse(r, v))
}

// UpdateScopeBlockedNames changes the policy.
// @Summary      Change the blocked target names policy
// @Description  Platform owner with a fresh authenticator code and a reason. On a hosted service turning the government and military rule off needs a second owner's approval. Loopback, link-local and cloud metadata addresses, public suffixes, shared provider apexes and the CIDR caps are not part of it and never change. Audited critical; every administrator is told.
// @Tags         Admin System
// @Accept       json
// @Produce      json
// @Param        request  body      UpdateScopeBlockedNamesRequest  true  "Policy"
// @Success      200  {object}  ScopeBlockedNamesResponse
// @Failure      400  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Failure      428  {object}  apierror.Error  "SECOND_APPROVAL_REQUIRED"
// @Security     AdminAuth
// @Router       /admin/settings/scope-blocked-names [put]
func (h *AdminPlatformSettingsHandler) UpdateScopeBlockedNames(w http.ResponseWriter, r *http.Request) {
	actor := requireActor(w, r)
	if actor == nil {
		return
	}
	var req UpdateScopeBlockedNamesRequest
	if !decodeSetting(w, r, &req) {
		return
	}
	if req.GovernmentRule == nil {
		apierror.BadRequest("government_rule must be true or false").WriteJSON(w)
		return
	}
	in := scopenames.PolicyInput{GovernmentRule: *req.GovernmentRule, Names: req.Names,
		MaxExceptionDays: req.MaxExceptionDays, Reason: req.Reason, Version: req.Version}
	if _, err := consolesetting.CheckReason(in.Reason); err != nil {
		h.writeScopeNamesError(w, err)
		return
	}
	needed, err := h.ScopeNames.RuleOffNeedsApproval(r.Context(), in)
	if err != nil {
		h.writeScopeNamesError(w, err)
		return
	}
	var grant *adminapproval.Grant
	if needed {
		g, ok := requireSecondApproval(w, r, h.approvals, actor, admin.ApprovalScopeGovernmentRuleOff, "off", h.logger)
		if !ok {
			return
		}
		grant = g
	}
	v, err := h.ScopeNames.UpdatePolicy(r.Context(), actor, in, scopeNamesRequest(r))
	if err != nil {
		releaseSecondApproval(r, h.approvals, actor, grant)
		h.writeScopeNamesError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, h.scopeNamesResponse(r, v))
}

// ListScopeNameExceptions lists every exception.
// @Summary      Scope name exceptions
// @Description  Every exception to the government and military rule with its organization, name, reason, authorisation reference, who granted it, expiry and state. Any console reader.
// @Tags         Admin System
// @Produce      json
// @Success      200  {object}  ScopeNameExceptionListResponse
// @Security     AdminAuth
// @Router       /admin/settings/scope-blocked-names/exceptions [get]
func (h *AdminPlatformSettingsHandler) ListScopeNameExceptions(w http.ResponseWriter, r *http.Request) {
	list, err := h.ScopeNames.List(r.Context())
	if err != nil {
		h.writeScopeNamesError(w, err)
		return
	}
	now := h.ScopeNames.Now()
	out := ScopeNameExceptionListResponse{Items: make([]ScopeNameExceptionResponse, 0, len(list))}
	for _, e := range list {
		out.Items = append(out.Items, scopeNameExceptionResponse(e, now))
	}
	writeJSON(w, http.StatusOK, out)
}

// GrantScopeNameException grants an exception.
// @Summary      Grant a scope name exception
// @Description  Lets one organization add one government or military name (and, with include_subdomains, the names under it) to its scope until the expiry. The organization still needs a scope entry through every scope rule. Platform owner with a fresh authenticator code, a reason and the written authorisation's reference; on a hosted service a second owner approves. Audited critical; every administrator is told.
// @Tags         Admin System
// @Accept       json
// @Produce      json
// @Param        request  body      GrantScopeNameExceptionRequest  true  "Exception"
// @Success      201  {object}  ScopeNameExceptionResponse
// @Failure      400  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Failure      428  {object}  apierror.Error  "SECOND_APPROVAL_REQUIRED"
// @Security     AdminAuth
// @Router       /admin/settings/scope-blocked-names/exceptions [post]
func (h *AdminPlatformSettingsHandler) GrantScopeNameException(w http.ResponseWriter, r *http.Request) {
	actor := requireActor(w, r)
	if actor == nil {
		return
	}
	var req GrantScopeNameExceptionRequest
	if !decodeSetting(w, r, &req) {
		return
	}
	tid, err := shared.IDFromString(strings.TrimSpace(req.OrganizationID))
	if err != nil {
		apierror.BadRequest("organization_id is not a valid id").WriteJSON(w)
		return
	}
	exp, ok := parseExpiry(req.ExpiresAt)
	if !ok {
		apierror.BadRequest("expires_at must be a date (YYYY-MM-DD) or an RFC 3339 time").WriteJSON(w)
		return
	}
	in, err := h.ScopeNames.PrepareGrant(r.Context(), scopenames.GrantInput{TenantID: tid, Name: req.Name,
		Subdomains: req.IncludeSubdomains, Reason: req.Reason, AuthorizationRef: req.AuthorizationRef, ExpiresAt: exp})
	if err != nil {
		h.writeScopeNamesError(w, err)
		return
	}
	var grant *adminapproval.Grant
	if h.ScopeNames.Managed() {
		g, ok := requireSecondApproval(w, r, h.approvals, actor, admin.ApprovalScopeNameException,
			scopenames.ApprovalTarget(in.TenantID, in.Name, in.Subdomains, in.ExpiresAt), h.logger)
		if !ok {
			return
		}
		grant = g
	}
	e, err := h.ScopeNames.Grant(r.Context(), actor, in, scopeNamesRequest(r))
	if err != nil {
		releaseSecondApproval(r, h.approvals, actor, grant)
		h.writeScopeNamesError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, scopeNameExceptionResponse(e, h.ScopeNames.Now()))
}

func (h *AdminPlatformSettingsHandler) exceptionID(w http.ResponseWriter, r *http.Request) (shared.ID, bool) {
	id, err := shared.IDFromString(chi.URLParam(r, "id"))
	if err != nil {
		apierror.NotFound("Exception").WriteJSON(w)
		return shared.ID{}, false
	}
	return id, true
}

// ExtendScopeNameException moves an exception's expiry.
// @Summary      Extend a scope name exception
// @Description  Sets a new expiry (within the platform's longest exception from today) on an exception that is not revoked; an expired one comes back. Same rules as a grant.
// @Tags         Admin System
// @Accept       json
// @Produce      json
// @Param        id       path      string                           true  "Exception id"
// @Param        request  body      ExtendScopeNameExceptionRequest  true  "New expiry"
// @Success      200  {object}  ScopeNameExceptionResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Failure      428  {object}  apierror.Error  "SECOND_APPROVAL_REQUIRED"
// @Security     AdminAuth
// @Router       /admin/settings/scope-blocked-names/exceptions/{id}/extend [post]
func (h *AdminPlatformSettingsHandler) ExtendScopeNameException(w http.ResponseWriter, r *http.Request) {
	actor := requireActor(w, r)
	if actor == nil {
		return
	}
	id, ok := h.exceptionID(w, r)
	if !ok {
		return
	}
	var req ExtendScopeNameExceptionRequest
	if !decodeSetting(w, r, &req) {
		return
	}
	exp, ok := parseExpiry(req.ExpiresAt)
	if !ok {
		apierror.BadRequest("expires_at must be a date (YYYY-MM-DD) or an RFC 3339 time").WriteJSON(w)
		return
	}
	if _, err := consolesetting.CheckReason(req.Reason); err != nil {
		h.writeScopeNamesError(w, err)
		return
	}
	var grant *adminapproval.Grant
	if h.ScopeNames.Managed() {
		e, err := h.ScopeNames.Exception(r.Context(), id)
		if err != nil {
			h.writeScopeNamesError(w, err)
			return
		}
		g, ok := requireSecondApproval(w, r, h.approvals, actor, admin.ApprovalScopeNameException,
			scopenames.ApprovalTarget(e.TenantID, e.Name, e.Subdomains, exp), h.logger)
		if !ok {
			return
		}
		grant = g
	}
	e, err := h.ScopeNames.Extend(r.Context(), actor, id, exp, req.Reason, scopeNamesRequest(r))
	if err != nil {
		releaseSecondApproval(r, h.approvals, actor, grant)
		h.writeScopeNamesError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, scopeNameExceptionResponse(e, h.ScopeNames.Now()))
}

// RevokeScopeNameException ends an exception at once.
// @Summary      Revoke a scope name exception
// @Description  Ends the exception at once: the organization's entries for the name stop covering anything and dispatch refuses it. Platform owner with a fresh authenticator code and a reason; no second approval (it narrows). Audited critical.
// @Tags         Admin System
// @Accept       json
// @Produce      json
// @Param        id       path      string                           true  "Exception id"
// @Param        request  body      RevokeScopeNameExceptionRequest  true  "Reason"
// @Success      200  {object}  ScopeNameExceptionResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Security     AdminAuth
// @Router       /admin/settings/scope-blocked-names/exceptions/{id}/revoke [post]
func (h *AdminPlatformSettingsHandler) RevokeScopeNameException(w http.ResponseWriter, r *http.Request) {
	actor := requireActor(w, r)
	if actor == nil {
		return
	}
	id, ok := h.exceptionID(w, r)
	if !ok {
		return
	}
	var req RevokeScopeNameExceptionRequest
	if !decodeSetting(w, r, &req) {
		return
	}
	e, err := h.ScopeNames.Revoke(r.Context(), actor, id, req.Reason, scopeNamesRequest(r))
	if err != nil {
		h.writeScopeNamesError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, scopeNameExceptionResponse(e, h.ScopeNames.Now()))
}
