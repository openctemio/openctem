package handler

import (
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	apispecapp "github.com/openctemio/openctem/api/internal/app/apispec"
	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/apispec"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// APISpecHandler serves the API descriptions of web origins and their drift
// (RFC-056 WS13).
type APISpecHandler struct {
	svc    *apispecapp.Service
	audit  *auditapp.AuditService
	logger *logger.Logger
}

// NewAPISpecHandler creates the handler.
func NewAPISpecHandler(svc *apispecapp.Service, audit *auditapp.AuditService, log *logger.Logger) *APISpecHandler {
	return &APISpecHandler{svc: svc, audit: audit, logger: log}
}

// APISpecResponse is one stored description (its operations, never the
// document).
type APISpecResponse struct {
	ID             string    `json:"id"`
	OriginAssetID  string    `json:"origin_asset_id"`
	Name           string    `json:"name"`
	Format         string    `json:"format" enums:"openapi3,swagger2,postman,har,graphql"`
	Title          string    `json:"title,omitempty"`
	SpecVersion    string    `json:"spec_version,omitempty"`
	Digest         string    `json:"digest"`
	SizeBytes      int       `json:"size_bytes"`
	OperationCount int       `json:"operation_count"`
	Truncated      int       `json:"truncated"`
	CreatedAt      time.Time `json:"created_at"`
}

// APISpecDriftItem is one difference between a description and the scans.
type APISpecDriftItem struct {
	Method     string   `json:"method"`
	Path       string   `json:"path"`
	EndpointID string   `json:"endpoint_id,omitempty"`
	Params     []string `json:"params,omitempty"`
}

// APISpecDriftResponse is the drift of one description.
type APISpecDriftResponse struct {
	Spec       APISpecResponse    `json:"spec"`
	Shadow     []APISpecDriftItem `json:"shadow"`
	Orphan     []APISpecDriftItem `json:"orphan"`
	Zombie     []APISpecDriftItem `json:"zombie"`
	ParamDrift []APISpecDriftItem `json:"param_drift"`
}

func toAPISpecResponse(r *apispec.Record) APISpecResponse {
	return APISpecResponse{ID: r.ID.String(), OriginAssetID: r.OriginAssetID.String(), Name: r.Name, Format: string(r.Format),
		Title: r.Title, SpecVersion: r.SpecVersion, Digest: r.Digest, SizeBytes: r.SizeBytes,
		OperationCount: r.OperationCount, Truncated: r.Truncated, CreatedAt: r.CreatedAt}
}

func driftItems(in []apispec.DriftItem) []APISpecDriftItem {
	out := make([]APISpecDriftItem, len(in))
	for i, d := range in {
		out[i] = APISpecDriftItem{Method: d.Method, Path: d.Path, Params: d.Params}
		if d.EndpointID != nil {
			out[i].EndpointID = d.EndpointID.String()
		}
	}
	return out
}

func (h *APISpecHandler) writeErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("API description").WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(err.Error()).WriteJSON(w)
	default:
		h.logger.Error("api specs", "error", err)
		apierror.InternalError(err).WriteJSON(w)
	}
}

func (h *APISpecHandler) tenantAnd(w http.ResponseWriter, r *http.Request) (shared.ID, shared.ID, bool) {
	tenantID, err := shared.IDFromString(middleware.MustGetTenantID(r.Context()))
	if err != nil {
		apierror.Unauthorized("Invalid tenant").WriteJSON(w)
		return shared.ID{}, shared.ID{}, false
	}
	id, err := shared.IDFromString(chi.URLParam(r, "id"))
	if err != nil {
		apierror.NotFound("API description").WriteJSON(w)
		return shared.ID{}, shared.ID{}, false
	}
	return tenantID, id, true
}

func (h *APISpecHandler) auditSpec(r *http.Request, tenantID shared.ID, action auditdom.Action, rec *apispec.Record, msg string) {
	if h.audit == nil || rec == nil {
		return
	}
	event := auditapp.NewSuccessEvent(action, auditdom.ResourceTypeAsset, rec.OriginAssetID.String()).
		WithMessage(msg).
		WithMetadata("api_spec_id", rec.ID.String()).
		WithMetadata("format", string(rec.Format)).
		WithMetadata("digest", rec.Digest).
		WithMetadata("operations", rec.OperationCount).
		WithSeverity(auditdom.SeverityLow)
	_ = h.audit.LogEvent(r.Context(), auditapp.AuditContext{
		TenantID: tenantID.String(), ActorID: middleware.GetUserID(r.Context()), ActorEmail: auditActorEmail(r.Context()),
		ActorIP: getClientIP(r), UserAgent: r.UserAgent(), RequestID: r.Header.Get("X-Request-ID"),
	}, event)
}

// Upload handles POST /api/v1/assets/{id}/api-specs
// @Summary      Upload an API description for a web origin
// @Description  Multipart `file` (at most 10 MB): OpenAPI 3 or Swagger 2 (JSON or YAML), a Postman 2.1 collection, a HAR
// @Description  1.2 capture or a GraphQL introspection result. Only the operations (method, path, parameter names,
// @Description  deprecated) and the document's digest are kept; the document, its examples and any captured value are
// @Description  not. No remote reference is fetched. The asset must be a web origin (http service) the caller may see.
// @Tags         Web Surface
// @Accept       multipart/form-data
// @Produce      json
// @Security     BearerAuth
// @Param        id            path      string  true   "Origin asset ID"
// @Param        file          formData  file    true   "API description"
// @Param        name          formData  string  false  "Display name"
// @Param        graphql_path  formData  string  false  "Path a GraphQL introspection result is served at (default /graphql)"
// @Success      201  {object}  APISpecResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      413  {object}  apierror.Error
// @Router       /assets/{id}/api-specs [post]
func (h *APISpecHandler) Upload(w http.ResponseWriter, r *http.Request) {
	tenantID, originID, ok := h.tenantAnd(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, apispec.MaxSpecBytes+(1<<20))
	if err := r.ParseMultipartForm(1 << 20); err != nil {
		apierror.New(http.StatusRequestEntityTooLarge, "PAYLOAD_TOO_LARGE", "The description must be a multipart file of at most 10 MB").WriteJSON(w)
		return
	}
	defer func() {
		if r.MultipartForm != nil {
			_ = r.MultipartForm.RemoveAll()
		}
	}()
	file, _, err := r.FormFile("file")
	if err != nil {
		apierror.BadRequest("A file is required").WriteJSON(w)
		return
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, apispec.MaxSpecBytes+1))
	if err != nil || len(data) > apispec.MaxSpecBytes {
		apierror.New(http.StatusRequestEntityTooLarge, "PAYLOAD_TOO_LARGE", "The description must be at most 10 MB").WriteJSON(w)
		return
	}
	var by *shared.ID
	if u, err := shared.IDFromString(middleware.GetUserID(r.Context())); err == nil {
		by = &u
	}
	rec, err := h.svc.Upload(r.Context(), apispecapp.UploadInput{TenantID: tenantID, OriginAssetID: originID,
		Name: r.FormValue("name"), GraphQLPath: r.FormValue("graphql_path"), Data: data, UploadedBy: by})
	if err != nil {
		h.writeErr(w, err)
		return
	}
	h.auditSpec(r, tenantID, auditdom.ActionAssetUpdated, rec, "API description uploaded")
	writeJSON(w, http.StatusCreated, toAPISpecResponse(rec))
}

// ListByAsset handles GET /api/v1/assets/{id}/api-specs
// @Summary      List the API descriptions of a web origin
// @Tags         Web Surface
// @Produce      json
// @Security     BearerAuth
// @Param        id  path  string  true  "Origin asset ID"
// @Success      200  {object}  object{data=[]APISpecResponse}
// @Failure      404  {object}  apierror.Error
// @Router       /assets/{id}/api-specs [get]
func (h *APISpecHandler) ListByAsset(w http.ResponseWriter, r *http.Request) {
	tenantID, originID, ok := h.tenantAnd(w, r)
	if !ok {
		return
	}
	list, err := h.svc.List(r.Context(), tenantID, originID)
	if err != nil {
		h.writeErr(w, err)
		return
	}
	data := make([]APISpecResponse, len(list))
	for i, rec := range list {
		data[i] = toAPISpecResponse(rec)
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": data})
}

// Get handles GET /api/v1/api-specs/{id}
// @Summary      Get an API description
// @Tags         Web Surface
// @Produce      json
// @Security     BearerAuth
// @Param        id  path  string  true  "API description ID"
// @Success      200  {object}  APISpecResponse
// @Failure      404  {object}  apierror.Error
// @Router       /api-specs/{id} [get]
func (h *APISpecHandler) Get(w http.ResponseWriter, r *http.Request) {
	tenantID, id, ok := h.tenantAnd(w, r)
	if !ok {
		return
	}
	rec, err := h.svc.Get(r.Context(), tenantID, id)
	if err != nil {
		h.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toAPISpecResponse(rec))
}

// Drift handles GET /api/v1/api-specs/{id}/drift
// @Summary      Drift between an API description and the scans
// @Description  shadow: observed, not declared. orphan: declared, never observed. zombie: declared deprecated, still
// @Description  answering 2xx. param_drift: parameters a scan saw that the description does not name.
// @Tags         Web Surface
// @Produce      json
// @Security     BearerAuth
// @Param        id  path  string  true  "API description ID"
// @Success      200  {object}  APISpecDriftResponse
// @Failure      404  {object}  apierror.Error
// @Router       /api-specs/{id}/drift [get]
func (h *APISpecHandler) Drift(w http.ResponseWriter, r *http.Request) {
	tenantID, id, ok := h.tenantAnd(w, r)
	if !ok {
		return
	}
	rec, d, err := h.svc.Drift(r.Context(), tenantID, id)
	if err != nil {
		h.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, APISpecDriftResponse{Spec: toAPISpecResponse(rec), Shadow: driftItems(d.Shadow),
		Orphan: driftItems(d.Orphan), Zombie: driftItems(d.Zombie), ParamDrift: driftItems(d.ParamDrift)})
}

// Delete handles DELETE /api/v1/api-specs/{id}
// @Summary      Delete an API description
// @Tags         Web Surface
// @Security     BearerAuth
// @Param        id  path  string  true  "API description ID"
// @Success      204
// @Failure      404  {object}  apierror.Error
// @Router       /api-specs/{id} [delete]
func (h *APISpecHandler) Delete(w http.ResponseWriter, r *http.Request) {
	tenantID, id, ok := h.tenantAnd(w, r)
	if !ok {
		return
	}
	rec, err := h.svc.Delete(r.Context(), tenantID, id)
	if err != nil {
		h.writeErr(w, err)
		return
	}
	h.auditSpec(r, tenantID, auditdom.ActionAssetUpdated, rec, "API description deleted")
	w.WriteHeader(http.StatusNoContent)
}
