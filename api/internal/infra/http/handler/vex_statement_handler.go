package handler

// The organization's VEX statements. Design:
// api/docs/rfcs/RFC-070-software-components-inventory.md.

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	vexapp "github.com/openctemio/openctem/api/internal/app/vex"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	vexdom "github.com/openctemio/openctem/api/pkg/domain/vex"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// VEXStatementHandler serves /api/v1/vex-statements.
type VEXStatementHandler struct {
	service *vexapp.Service
	logger  *logger.Logger
}

// NewVEXStatementHandler creates the handler.
func NewVEXStatementHandler(svc *vexapp.Service, log *logger.Logger) *VEXStatementHandler {
	return &VEXStatementHandler{service: svc, logger: log}
}

// VEXStatementResponse is a VEX statement.
type VEXStatementResponse struct {
	ID              string     `json:"id"`
	VulnID          string     `json:"vuln_id"`
	ProductID       string     `json:"product_id"`
	Versions        []string   `json:"versions"`
	VersionRange    string     `json:"version_range,omitempty"`
	AssetID         *string    `json:"asset_id,omitempty"`
	Status          string     `json:"status"`
	Justification   string     `json:"justification,omitempty"`
	ImpactStatement string     `json:"impact_statement,omitempty"`
	ActionStatement string     `json:"action_statement,omitempty"`
	Origin          string     `json:"origin"`
	DocumentRef     string     `json:"document_ref,omitempty"`
	ExpiresAt       *time.Time `json:"expires_at,omitempty"`
	Expired         bool       `json:"expired"`
	CreatedBy       *string    `json:"created_by,omitempty"`
	UpdatedBy       *string    `json:"updated_by,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

// VEXStatementWriteResponse is a written statement and what it did to findings.
type VEXStatementWriteResponse struct {
	Statement VEXStatementResponse `json:"statement"`
	Applied   vexapp.ApplyResult   `json:"applied"`
}

// VEXStatementDeleteResponse is what deleting a statement did to findings.
type VEXStatementDeleteResponse struct {
	Applied vexapp.ApplyResult `json:"applied"`
}

// CreateVEXStatementRequest creates a statement. product_id or purl names
// the package; asset_id empty = every asset; versions or version_range
// limit the versions (neither = every version).
type CreateVEXStatementRequest struct {
	VulnID          string     `json:"vuln_id"`
	ProductID       string     `json:"product_id,omitempty"`
	PURL            string     `json:"purl,omitempty"`
	AssetID         string     `json:"asset_id,omitempty"`
	Versions        []string   `json:"versions,omitempty"`
	VersionRange    string     `json:"version_range,omitempty"`
	Status          string     `json:"status"`
	Justification   string     `json:"justification,omitempty"`
	ImpactStatement string     `json:"impact_statement,omitempty"`
	ActionStatement string     `json:"action_statement,omitempty"`
	ExpiresAt       *time.Time `json:"expires_at,omitempty"`
}

// UpdateVEXStatementRequest edits a statement's content; omitted fields
// keep their value, clear_expiry removes the expiry.
type UpdateVEXStatementRequest struct {
	Versions        *[]string  `json:"versions,omitempty"`
	VersionRange    *string    `json:"version_range,omitempty"`
	Status          *string    `json:"status,omitempty"`
	Justification   *string    `json:"justification,omitempty"`
	ImpactStatement *string    `json:"impact_statement,omitempty"`
	ActionStatement *string    `json:"action_statement,omitempty"`
	ExpiresAt       *time.Time `json:"expires_at,omitempty"`
	ClearExpiry     bool       `json:"clear_expiry,omitempty"`
}

func idPtrString(id *shared.ID) *string {
	if id == nil {
		return nil
	}
	s := id.String()
	return &s
}

func toVEXStatementResponse(st *vexdom.Statement, now time.Time) VEXStatementResponse {
	versions := st.Versions
	if versions == nil {
		versions = []string{}
	}
	return VEXStatementResponse{
		ID: st.ID.String(), VulnID: st.VulnID, ProductID: st.ProductID.String(), Versions: versions,
		VersionRange: st.VersionRange, AssetID: idPtrString(st.AssetID), Status: string(st.Status),
		Justification: st.Justification, ImpactStatement: st.ImpactStatement, ActionStatement: st.ActionStatement,
		Origin: st.Origin, DocumentRef: st.DocumentRef, ExpiresAt: st.ExpiresAt, Expired: !st.Active(now),
		CreatedBy: idPtrString(st.CreatedBy), UpdatedBy: idPtrString(st.UpdatedBy),
		CreatedAt: st.CreatedAt, UpdatedAt: st.UpdatedAt,
	}
}

func (h *VEXStatementHandler) handleError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("VEX statement").WriteJSON(w)
	case errors.Is(err, shared.ErrForbidden):
		apierror.Forbidden(vexPublicMessage(err)).WriteJSON(w)
	case errors.Is(err, shared.ErrConflict):
		apierror.Conflict(vexPublicMessage(err)).WriteJSON(w)
	case errors.Is(err, shared.ErrValidation), errors.Is(err, pagination.ErrInvalid):
		apierror.BadRequest(vexPublicMessage(err)).WriteJSON(w)
	default:
		h.logger.Error("vex statement service error", "error", strings.NewReplacer("\n", " ", "\r", " ").Replace(err.Error()))
		apierror.InternalError(err).WriteJSON(w)
	}
}

// publicMessage is the message of a domain error without its sentinel prefix.
func vexPublicMessage(err error) string {
	msg := err.Error()
	for _, p := range []string{"validation error: ", "forbidden: ", "conflict: "} {
		msg = strings.TrimPrefix(msg, p)
	}
	return msg
}

func writeVEXJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func decodeVEXBody(r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func vexTenantOf(r *http.Request) (shared.ID, bool) {
	id, err := shared.IDFromString(middleware.GetTenantID(r.Context()))
	return id, err == nil && !id.IsZero()
}

// List handles GET /api/v1/vex-statements
// @Summary      List VEX statements
// @Description  The organization's VEX statements the caller may see: statements for one asset when the asset is in the caller's scope, statements for every asset when an in-scope asset uses the package.
// @Tags         VEX
// @Produce      json
// @Security     BearerAuth
// @Param        vuln_id     query  string  false  "Vulnerability id"
// @Param        product_id  query  string  false  "Package (component) id"
// @Param        asset_id    query  string  false  "Asset id"
// @Param        status      query  string  false  "not_affected, affected, fixed, under_investigation"
// @Param        page        query  int     false  "Page"
// @Param        per_page    query  int     false  "Page size (max 100)"
// @Success      200  {object}  ListResponse[VEXStatementResponse]
// @Failure      400  {object}  apierror.Error
// @Router       /vex-statements [get]
func (h *VEXStatementHandler) List(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := vexTenantOf(r)
	if !ok {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return
	}
	page, err := pagination.FromRequest(r.URL.Query(), 25)
	if err != nil {
		h.handleError(w, err)
		return
	}
	q := r.URL.Query()
	res, err := h.service.List(r.Context(), tenantID, vexapp.ListInput{
		VulnID: q.Get("vuln_id"), ProductID: q.Get("product_id"), AssetID: q.Get("asset_id"), Status: q.Get("status"),
	}, page)
	if err != nil {
		h.handleError(w, err)
		return
	}
	now := time.Now()
	data := make([]VEXStatementResponse, len(res.Data))
	for i, st := range res.Data {
		data[i] = toVEXStatementResponse(st, now)
	}
	writeVEXJSON(w, http.StatusOK, ListResponse[VEXStatementResponse]{
		Data: data, Total: res.Total, Page: res.Page, PerPage: res.PerPage, TotalPages: res.TotalPages,
		Links: NewPaginationLinks(r, res.Page, res.PerPage, res.TotalPages),
	})
}

// Get handles GET /api/v1/vex-statements/{id}
// @Summary      Get a VEX statement
// @Tags         VEX
// @Produce      json
// @Security     BearerAuth
// @Param        id   path  string  true  "Statement id"
// @Success      200  {object}  VEXStatementResponse
// @Failure      404  {object}  apierror.Error
// @Router       /vex-statements/{id} [get]
func (h *VEXStatementHandler) Get(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := vexTenantOf(r)
	if !ok {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return
	}
	st, err := h.service.Get(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		h.handleError(w, err)
		return
	}
	writeVEXJSON(w, http.StatusOK, toVEXStatementResponse(st, time.Now()))
}

// Create handles POST /api/v1/vex-statements
// @Summary      Create a VEX statement
// @Description  States the exploitability of a vulnerability in a package (every version, listed versions or a range), for one asset or every asset. not_affected closes the open findings it covers as false positive, fixed as resolved; affected and under_investigation annotate. Applies to findings reported later too. Human-sourced findings (pentest, manual, bug bounty, red team) are never closed. A statement for every asset needs access to every asset.
// @Tags         VEX
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body  body  CreateVEXStatementRequest  true  "Statement"
// @Success      201  {object}  VEXStatementWriteResponse
// @Failure      400  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Router       /vex-statements [post]
func (h *VEXStatementHandler) Create(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := vexTenantOf(r)
	if !ok {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return
	}
	var req CreateVEXStatementRequest
	if err := decodeVEXBody(r, &req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	st, res, err := h.service.Create(r.Context(), tenantID, vexapp.Input{
		VulnID: req.VulnID, ProductID: req.ProductID, PURL: req.PURL, AssetID: req.AssetID, Versions: req.Versions,
		VersionRange: req.VersionRange, Status: req.Status, Justification: req.Justification,
		ImpactStatement: req.ImpactStatement, ActionStatement: req.ActionStatement, ExpiresAt: req.ExpiresAt,
	}, configAuditContext(r))
	if err != nil && st == nil {
		h.handleError(w, err)
		return
	}
	if err != nil {
		h.logger.Error("vex statement apply incomplete", "error", err)
	}
	writeVEXJSON(w, http.StatusCreated, VEXStatementWriteResponse{Statement: toVEXStatementResponse(st, time.Now()), Applied: res})
}

// Update handles PATCH /api/v1/vex-statements/{id}
// @Summary      Edit a VEX statement
// @Description  Edits the status, justification, statements, versions or expiry and re-applies the statement: findings it no longer closes reopen. The vulnerability, package and asset are fixed.
// @Tags         VEX
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        id    path  string                     true  "Statement id"
// @Param        body  body  UpdateVEXStatementRequest  true  "Changes"
// @Success      200  {object}  VEXStatementWriteResponse
// @Failure      400  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Router       /vex-statements/{id} [patch]
func (h *VEXStatementHandler) Update(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := vexTenantOf(r)
	if !ok {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return
	}
	var req UpdateVEXStatementRequest
	if err := decodeVEXBody(r, &req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	st, res, err := h.service.Update(r.Context(), tenantID, r.PathValue("id"), vexapp.Patch{
		Versions: req.Versions, VersionRange: req.VersionRange, Status: req.Status, Justification: req.Justification,
		ImpactStatement: req.ImpactStatement, ActionStatement: req.ActionStatement, ExpiresAt: req.ExpiresAt,
		ClearExpiry: req.ClearExpiry,
	}, configAuditContext(r))
	if err != nil && st == nil {
		h.handleError(w, err)
		return
	}
	if err != nil {
		h.logger.Error("vex statement apply incomplete", "error", err)
	}
	writeVEXJSON(w, http.StatusOK, VEXStatementWriteResponse{Statement: toVEXStatementResponse(st, time.Now()), Applied: res})
}

// Delete handles DELETE /api/v1/vex-statements/{id}
// @Summary      Delete a VEX statement
// @Description  Findings the statement closed reopen unless another statement covers them.
// @Tags         VEX
// @Produce      json
// @Security     BearerAuth
// @Param        id   path  string  true  "Statement id"
// @Success      200  {object}  VEXStatementDeleteResponse
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Router       /vex-statements/{id} [delete]
func (h *VEXStatementHandler) Delete(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := vexTenantOf(r)
	if !ok {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return
	}
	res, err := h.service.Delete(r.Context(), tenantID, r.PathValue("id"), configAuditContext(r))
	if err != nil {
		h.handleError(w, err)
		return
	}
	writeVEXJSON(w, http.StatusOK, VEXStatementDeleteResponse{Applied: res})
}

// Import handles POST /api/v1/vex-statements/import
// @Summary      Import a VEX document
// @Description  Reads an OpenVEX, CSAF VEX or CycloneDX VEX document (JSON, at most 5 MB, at most 5000 statements) and stores its statements for one asset (asset_id) or every asset, then applies them. dry_run=true returns the preview and writes nothing. Statements whose package is not in the inventory, and statements about components inside a product without a target asset, are reported as skipped. A statement written in the organization is never overwritten.
// @Tags         VEX
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        asset_id  query  string  false  "Target asset (empty: every asset)"
// @Param        dry_run   query  bool    false  "Preview only"
// @Success      200  {object}  vexapp.ImportResult
// @Failure      400  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Router       /vex-statements/import [post]
func (h *VEXStatementHandler) Import(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := vexTenantOf(r)
	if !ok {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return
	}
	body := http.MaxBytesReader(w, r.Body, vexapp.MaxDocumentBytes+1)
	res, err := h.service.Import(r.Context(), tenantID, r.URL.Query().Get("asset_id"), body,
		r.URL.Query().Get("dry_run") == "true", configAuditContext(r))
	if err != nil {
		h.handleError(w, err)
		return
	}
	writeVEXJSON(w, http.StatusOK, res)
}
