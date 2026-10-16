package handler

// Support access, console side (docs/rfcs/RFC-063-support-access.md): the
// administrator a grant names opens a support session (step-up) and reads the
// organization's findings and assets through it. Every read is authorized
// live (no cache) and written to both audit logs before data is returned.

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	supportapp "github.com/openctemio/openctem/api/internal/app/supportaccess"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/supportaccess"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// codeSupportGrantRequired: no active grant (missing, expired, revoked, not
// yours) or no live support session for this console session.
const codeSupportGrantRequired apierror.Code = "SUPPORT_GRANT_REQUIRED"

// AdminSupportHandler serves the console's support access.
type AdminSupportHandler struct {
	svc *supportapp.Service
	log *logger.Logger
}

// NewAdminSupportHandler creates the handler.
func NewAdminSupportHandler(svc *supportapp.Service, log *logger.Logger) *AdminSupportHandler {
	return &AdminSupportHandler{svc: svc, log: log.With("handler", "admin_support")}
}

// AdminSupportGrantResponse is one grant naming the caller.
type AdminSupportGrantResponse struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	TenantName  string    `json:"tenant_name"`
	Scopes      []string  `json:"scopes"`
	Reason      string    `json:"reason"`
	CaseRef     string    `json:"case_ref,omitempty"`
	ExpiresAt   time.Time `json:"expires_at"`
	OpenSession bool      `json:"open_session"`
}

// AdminSupportGrantListResponse wraps the caller's grants.
type AdminSupportGrantListResponse struct {
	Data []AdminSupportGrantResponse `json:"data"`
}

// AdminSupportSessionRequest opens a support session.
type AdminSupportSessionRequest struct {
	// Reason is optional context for this session (the grant has its own).
	Reason string `json:"reason"`
}

// AdminSupportSessionResponse is an open support session.
type AdminSupportSessionResponse struct {
	ID        string    `json:"id"`
	GrantID   string    `json:"grant_id"`
	TenantID  string    `json:"tenant_id"`
	Scopes    []string  `json:"scopes"`
	ExpiresAt time.Time `json:"expires_at"`
	StartedAt time.Time `json:"started_at"`
}

// AdminSupportFindingList is a page of findings.
type AdminSupportFindingList struct {
	Data  []supportaccess.FindingView `json:"data"`
	Total int64                       `json:"total"`
}

// AdminSupportAssetList is a page of assets.
type AdminSupportAssetList struct {
	Data  []supportaccess.AssetView `json:"data"`
	Total int64                     `json:"total"`
}

func (h *AdminSupportHandler) writeError(w http.ResponseWriter, err error, op string) {
	switch {
	case errors.Is(err, supportaccess.ErrGrantRequired), errors.Is(err, supportaccess.ErrNoLiveSession):
		apierror.New(http.StatusForbidden, codeSupportGrantRequired,
			"No active support access for this organization: the grant is missing, expired or revoked, or the session ended").WriteJSON(w)
	case errors.Is(err, supportaccess.ErrScopeNotGranted):
		apierror.Forbidden("The organization did not grant access to this data").WriteJSON(w)
	case errors.Is(err, supportaccess.ErrNotFound):
		apierror.NotFound("resource").WriteJSON(w)
	case errors.Is(err, supportaccess.ErrAuditUnavailable):
		apierror.ServiceUnavailable("Support access is unavailable: it could not be audited").WriteJSON(w)
	case shared.IsValidation(err):
		apierror.BadRequest(sanitizeLogField(err.Error())).WriteJSON(w)
	default:
		h.log.Error("admin support", "op", op, "error", err)
		apierror.InternalServerError("could not complete the request").WriteJSON(w)
	}
}

func consoleSessionID(r *http.Request) shared.ID {
	if s := middleware.GetAdminSession(r.Context()); s != nil {
		return s.ID
	}
	return shared.ID{}
}

// Grants handles GET /api/v1/admin/support/grants.
// @Summary My support grants
// @Description The active support grants that name the signed-in administrator, across organizations.
// @Tags Admin Support
// @Produce json
// @Success 200 {object} AdminSupportGrantListResponse
// @Router /admin/support/grants [get]
func (h *AdminSupportHandler) Grants(w http.ResponseWriter, r *http.Request) {
	a := middleware.MustGetAdminUser(r.Context())
	grants, err := h.svc.GrantsForAdmin(r.Context(), a)
	if err != nil {
		h.writeError(w, err, "grants")
		return
	}
	out := AdminSupportGrantListResponse{Data: make([]AdminSupportGrantResponse, 0, len(grants))}
	for _, g := range grants {
		out.Data = append(out.Data, AdminSupportGrantResponse{
			ID: g.ID.String(), TenantID: g.TenantID.String(), TenantName: g.TenantName, Scopes: g.Scopes, Reason: g.Reason,
			CaseRef: g.CaseRef, ExpiresAt: g.ExpiresAt, OpenSession: g.OpenSession,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// StartSession handles POST /api/v1/admin/support/grants/{grant_id}/sessions.
// @Summary Open a support session
// @Description Route-level step-up. Opens a read-only support session inside a grant that names the caller; it is bound to this console session. Both audit logs record it and the organization's owners are emailed.
// @Tags Admin Support
// @Accept json
// @Produce json
// @Param grant_id path string true "Grant ID"
// @Param request body AdminSupportSessionRequest false "Reason"
// @Success 201 {object} AdminSupportSessionResponse
// @Failure 403 {object} apierror.Error "No active grant names you"
// @Router /admin/support/grants/{grant_id}/sessions [post]
func (h *AdminSupportHandler) StartSession(w http.ResponseWriter, r *http.Request) {
	a := middleware.MustGetAdminUser(r.Context())
	grantID, err := shared.IDFromString(r.PathValue("grant_id"))
	if err != nil {
		h.writeError(w, supportaccess.ErrGrantRequired, "start")
		return
	}
	var req AdminSupportSessionRequest
	if r.ContentLength != 0 {
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
			apierror.BadRequest("invalid request body").WriteJSON(w)
			return
		}
	}
	sess, g, err := h.svc.StartSession(r.Context(), a, consoleSessionID(r), grantID, req.Reason, supportClient(r))
	if err != nil {
		h.writeError(w, err, "start")
		return
	}
	writeJSON(w, http.StatusCreated, AdminSupportSessionResponse{
		ID: sess.ID.String(), GrantID: g.ID.String(), TenantID: g.TenantID.String(), Scopes: g.Scopes,
		ExpiresAt: g.ExpiresAt, StartedAt: sess.StartedAt,
	})
}

// EndSession handles DELETE /api/v1/admin/support/sessions/{session_id}.
// @Summary End a support session
// @Tags Admin Support
// @Param session_id path string true "Support session ID"
// @Success 204 "No Content"
// @Failure 403 {object} apierror.Error
// @Router /admin/support/sessions/{session_id} [delete]
func (h *AdminSupportHandler) EndSession(w http.ResponseWriter, r *http.Request) {
	a := middleware.MustGetAdminUser(r.Context())
	id, err := shared.IDFromString(r.PathValue("session_id"))
	if err != nil {
		h.writeError(w, supportaccess.ErrNoLiveSession, "end")
		return
	}
	if err := h.svc.EndSession(r.Context(), a, id, supportClient(r)); err != nil {
		h.writeError(w, err, "end")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// access authorizes and audits one read; it writes the refusal and returns
// nil when the read may not happen.
func (h *AdminSupportHandler) access(w http.ResponseWriter, r *http.Request, scope, route, resourceID string) *supportaccess.LiveSession {
	a := middleware.MustGetAdminUser(r.Context())
	id, err := shared.IDFromString(r.PathValue("session_id"))
	if err != nil {
		h.writeError(w, supportaccess.ErrNoLiveSession, route)
		return nil
	}
	ls, err := h.svc.Access(r.Context(), a, supportapp.AccessInput{
		SessionID: id, ConsoleSessionID: consoleSessionID(r), Scope: scope,
		Method: r.Method, Route: route, ResourceID: resourceID,
	}, supportClient(r))
	if err != nil {
		h.writeError(w, err, route)
		return nil
	}
	w.Header().Set("Cache-Control", "no-store")
	return ls
}

func supportListQuery(w http.ResponseWriter, r *http.Request) (supportaccess.ListQuery, bool) {
	p, ok := listPageMax(w, r, 25, 100)
	if !ok {
		return supportaccess.ListQuery{}, false
	}
	q := r.URL.Query()
	return supportaccess.ListQuery{Search: q.Get("search"), Severity: q.Get("severity"), Status: q.Get("status"),
		Limit: p.Limit(), Offset: p.Offset()}, true
}

// Overview handles GET /api/v1/admin/support/sessions/{session_id}/overview.
// @Summary Support: organization overview
// @Description Live support session required; audited in both logs.
// @Tags Admin Support
// @Produce json
// @Param session_id path string true "Support session ID"
// @Success 200 {object} supportaccess.Overview
// @Failure 403 {object} apierror.Error
// @Router /admin/support/sessions/{session_id}/overview [get]
func (h *AdminSupportHandler) Overview(w http.ResponseWriter, r *http.Request) {
	ls := h.access(w, r, "", "overview", "")
	if ls == nil {
		return
	}
	o, err := h.svc.Overview(r.Context(), ls)
	if err != nil {
		h.writeError(w, err, "overview")
		return
	}
	writeJSON(w, http.StatusOK, o)
}

// Findings handles GET /api/v1/admin/support/sessions/{session_id}/findings.
// @Summary Support: findings
// @Description Live support session with the findings scope; allow-listed fields only (no evidence, snippets or secret values); audited in both logs.
// @Tags Admin Support
// @Produce json
// @Param session_id path string true "Support session ID"
// @Param search query string false "Title contains"
// @Param severity query string false "critical, high, medium, low, info"
// @Param status query string false "open, or one status"
// @Param page query int false "Page (1)"
// @Param per_page query int false "1-100 (25)"
// @Success 200 {object} AdminSupportFindingList
// @Failure 403 {object} apierror.Error
// @Router /admin/support/sessions/{session_id}/findings [get]
func (h *AdminSupportHandler) Findings(w http.ResponseWriter, r *http.Request) {
	ls := h.access(w, r, supportaccess.ScopeFindings, "findings", "")
	if ls == nil {
		return
	}
	q, ok := supportListQuery(w, r)
	if !ok {
		return
	}
	items, total, err := h.svc.ListFindings(r.Context(), ls, q)
	if err != nil {
		h.writeError(w, err, "findings")
		return
	}
	writeJSON(w, http.StatusOK, AdminSupportFindingList{Data: items, Total: total})
}

// Finding handles GET /api/v1/admin/support/sessions/{session_id}/findings/{id}.
// @Summary Support: one finding
// @Tags Admin Support
// @Produce json
// @Param session_id path string true "Support session ID"
// @Param id path string true "Finding ID"
// @Success 200 {object} supportaccess.FindingView
// @Failure 403 {object} apierror.Error
// @Failure 404 {object} apierror.Error
// @Router /admin/support/sessions/{session_id}/findings/{id} [get]
func (h *AdminSupportHandler) Finding(w http.ResponseWriter, r *http.Request) {
	fid, err := shared.IDFromString(r.PathValue("id"))
	if err != nil {
		apierror.NotFound("finding").WriteJSON(w)
		return
	}
	ls := h.access(w, r, supportaccess.ScopeFindings, "finding", fid.String())
	if ls == nil {
		return
	}
	f, err := h.svc.GetFinding(r.Context(), ls, fid)
	if err != nil {
		h.writeError(w, err, "finding")
		return
	}
	writeJSON(w, http.StatusOK, f)
}

// Assets handles GET /api/v1/admin/support/sessions/{session_id}/assets.
// @Summary Support: assets
// @Description Live support session with the assets scope; allow-listed fields only; audited in both logs.
// @Tags Admin Support
// @Produce json
// @Param session_id path string true "Support session ID"
// @Param search query string false "Name contains"
// @Param status query string false "Asset status"
// @Param page query int false "Page (1)"
// @Param per_page query int false "1-100 (25)"
// @Success 200 {object} AdminSupportAssetList
// @Failure 403 {object} apierror.Error
// @Router /admin/support/sessions/{session_id}/assets [get]
func (h *AdminSupportHandler) Assets(w http.ResponseWriter, r *http.Request) {
	ls := h.access(w, r, supportaccess.ScopeAssets, "assets", "")
	if ls == nil {
		return
	}
	q, ok := supportListQuery(w, r)
	if !ok {
		return
	}
	items, total, err := h.svc.ListAssets(r.Context(), ls, q)
	if err != nil {
		h.writeError(w, err, "assets")
		return
	}
	writeJSON(w, http.StatusOK, AdminSupportAssetList{Data: items, Total: total})
}

// Asset handles GET /api/v1/admin/support/sessions/{session_id}/assets/{id}.
// @Summary Support: one asset
// @Tags Admin Support
// @Produce json
// @Param session_id path string true "Support session ID"
// @Param id path string true "Asset ID"
// @Success 200 {object} supportaccess.AssetView
// @Failure 403 {object} apierror.Error
// @Failure 404 {object} apierror.Error
// @Router /admin/support/sessions/{session_id}/assets/{id} [get]
func (h *AdminSupportHandler) Asset(w http.ResponseWriter, r *http.Request) {
	aid, err := shared.IDFromString(r.PathValue("id"))
	if err != nil {
		apierror.NotFound("asset").WriteJSON(w)
		return
	}
	ls := h.access(w, r, supportaccess.ScopeAssets, "asset", aid.String())
	if ls == nil {
		return
	}
	v, err := h.svc.GetAsset(r.Context(), ls, aid)
	if err != nil {
		h.writeError(w, err, "asset")
		return
	}
	writeJSON(w, http.StatusOK, v)
}
