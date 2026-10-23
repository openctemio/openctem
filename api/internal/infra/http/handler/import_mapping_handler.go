package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	appimportmapping "github.com/openctemio/openctem/api/internal/app/importmapping"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/importmapping"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// ImportMappingHandler serves an organization's import mappings
// (docs/rfcs/RFC-126-import-mappings.md).
type ImportMappingHandler struct {
	svc    *appimportmapping.Service
	audit  *auditapp.AuditService
	logger *logger.Logger
}

// NewImportMappingHandler builds the handler.
func NewImportMappingHandler(svc *appimportmapping.Service, audit *auditapp.AuditService, log *logger.Logger) *ImportMappingHandler {
	return &ImportMappingHandler{svc: svc, audit: audit, logger: log}
}

// MaxImportMappingBody bounds a JSON request (a document is at most 256
// KiB, written with whitespace).
const MaxImportMappingBody = 2*importmapping.MaxDocumentBytes + 16*1024

// MaxImportMappingPreviewBody bounds a preview upload: the sample, the
// document and the multipart framing.
const MaxImportMappingPreviewBody = appimportmapping.MaxSampleBytes + MaxImportMappingBody + 64*1024

// CodeIdentityChangeUnconfirmed is the 409 code of a new version whose
// identity differs from the latest one's, sent without confirmation.
const CodeIdentityChangeUnconfirmed apierror.Code = "identity_change_unconfirmed"

// CreateImportMappingRequest creates a mapping.
type CreateImportMappingRequest struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Mapping     json.RawMessage `json:"mapping" swaggertype:"object"`
	Note        string          `json:"note"`
}

// AddImportMappingVersionRequest saves a new version.
type AddImportMappingVersionRequest struct {
	Mapping               json.RawMessage `json:"mapping" swaggertype:"object"`
	Note                  string          `json:"note"`
	ConfirmIdentityChange bool            `json:"confirm_identity_change"`
}

// UpdateImportMappingRequest renames a mapping or changes its description.
type UpdateImportMappingRequest struct {
	Name        *string `json:"name"`
	Description *string `json:"description"`
}

// ValidateImportMappingRequest checks a document.
type ValidateImportMappingRequest struct {
	Mapping json.RawMessage `json:"mapping" swaggertype:"object"`
}

// ImportMappingResponse is a mapping with one version.
type ImportMappingResponse struct {
	Mapping *importmapping.Mapping `json:"mapping"`
	Version *importmapping.Version `json:"version,omitempty"`
}

func (h *ImportMappingHandler) tenant(w http.ResponseWriter, r *http.Request) (shared.ID, bool) {
	tid, err := shared.IDFromString(middleware.MustGetTenantID(r.Context()))
	if err != nil {
		apierror.Unauthorized("invalid tenant context").WriteJSON(w)
		return shared.ID{}, false
	}
	return tid, true
}

func (h *ImportMappingHandler) id(w http.ResponseWriter, r *http.Request) (shared.ID, bool) {
	id, err := shared.IDFromString(chi.URLParam(r, "id"))
	if err != nil {
		apierror.NotFound("import mapping").WriteJSON(w)
		return shared.ID{}, false
	}
	return id, true
}

func (h *ImportMappingHandler) decode(w http.ResponseWriter, r *http.Request, dst any) bool {
	dec := json.NewDecoder(io.LimitReader(r.Body, MaxImportMappingBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return false
	}
	return true
}

// fail answers a service error. Messages are the service's own, never
// the content of a sample or a database error.
func (h *ImportMappingHandler) fail(w http.ResponseWriter, err error) {
	var ve *appimportmapping.ValidationError
	var ic *appimportmapping.IdentityChangeError
	switch {
	case errors.As(err, &ve):
		apierror.ValidationFailed("the mapping has errors", map[string]any{"errors": ve.Problems}).WriteJSON(w)
	case errors.As(err, &ic):
		apierror.New(http.StatusConflict, CodeIdentityChangeUnconfirmed,
			"the new version changes how findings are identified; findings imported with earlier versions will not match new ones. Confirm to save it").
			WithDetails(map[string]any{"previous_identity": ic.Previous, "identity": ic.Next}).WriteJSON(w)
	case errors.Is(err, importmapping.ErrUnknownMapping), errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("import mapping").WriteJSON(w)
	case errors.Is(err, importmapping.ErrLimit):
		apierror.Conflict(err.Error()).WriteJSON(w)
	case errors.Is(err, shared.ErrConflict):
		apierror.Conflict(strings.TrimPrefix(err.Error(), shared.ErrConflict.Error()+": ")).WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(strings.TrimPrefix(err.Error(), shared.ErrValidation.Error()+": ")).WriteJSON(w)
	default:
		h.logger.Error("import mapping request failed", "error", logger.SanitizeValue(err.Error()))
		apierror.InternalServerError("the import mapping request failed").WriteJSON(w)
	}
}

func (h *ImportMappingHandler) auditEvent(r *http.Request, action auditdom.Action, m *importmapping.Mapping, before, after any, msg string, meta map[string]any) {
	ev := auditapp.NewChangeEvent(action, auditdom.ResourceTypeImportMapping, m.ID.String(), before, after).
		WithResourceName(m.Name).
		WithSeverity(auditdom.SeverityMedium).
		WithMessage(msg).
		WithMetadata("source", m.Source).
		WithMetadata("latest_version", m.LatestVersion)
	for k, v := range meta {
		ev = ev.WithMetadata(k, v)
	}
	recordConfigAudit(r.Context(), h.audit, h.logger, configAuditContext(r), ev)
}

// List handles GET /api/v1/import-mappings.
//
//	@Summary		List import mappings
//	@Description	The organization's import mappings. integrations:read or assets:import.
//	@Tags			Imports
//	@Produce		json
//	@Security		BearerAuth
//	@Success		200	{object}	map[string]any
//	@Router			/import-mappings [get]
func (h *ImportMappingHandler) List(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(w, r)
	if !ok {
		return
	}
	items, err := h.svc.List(r.Context(), tid)
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

// Templates handles GET /api/v1/import-mappings/templates.
//
//	@Summary		Starter import mappings
//	@Description	Built-in starter mappings: generic findings CSV, generic findings JSON, JUnit-style XML. integrations:read or assets:import.
//	@Tags			Imports
//	@Produce		json
//	@Security		BearerAuth
//	@Success		200	{object}	map[string]any
//	@Router			/import-mappings/templates [get]
func (h *ImportMappingHandler) Templates(w http.ResponseWriter, _ *http.Request) {
	items, err := appimportmapping.Templates()
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

// Create handles POST /api/v1/import-mappings.
//
//	@Summary		Create an import mapping
//	@Description	Stores a mapping document (openctem.io/mapping/v1) as version 1. The document must pass the language and the organization policy: finding and asset rules only, no reserved member, an identity of identity members when it makes findings. integrations:manage. Audited.
//	@Tags			Imports
//	@Accept			json
//	@Produce		json
//	@Security		BearerAuth
//	@Param			body	body		CreateImportMappingRequest	true	"Request"
//	@Success		201		{object}	ImportMappingResponse
//	@Failure		400		{object}	apierror.Error
//	@Failure		409		{object}	apierror.Error
//	@Failure		422		{object}	apierror.Error
//	@Router			/import-mappings [post]
func (h *ImportMappingHandler) Create(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(w, r)
	if !ok {
		return
	}
	var req CreateImportMappingRequest
	if !h.decode(w, r, &req) {
		return
	}
	m, v, err := h.svc.Create(r.Context(), appimportmapping.CreateInput{
		TenantID: tid, ActorID: mappingActor(r), Name: req.Name, Description: req.Description, Document: req.Mapping, Note: req.Note,
	})
	if err != nil {
		h.fail(w, err)
		return
	}
	h.auditEvent(r, auditdom.ActionImportMappingCreated, m, nil, map[string]any{"version": 1, "digest": v.Digest, "identity": v.Identity},
		fmt.Sprintf("Import mapping %q created", m.Name), nil)
	writeJSON(w, http.StatusCreated, ImportMappingResponse{Mapping: m, Version: v})
}

// Get handles GET /api/v1/import-mappings/{id}.
//
//	@Summary		Get an import mapping
//	@Description	The mapping, its latest version with the document, and the version history. integrations:read or assets:import.
//	@Tags			Imports
//	@Produce		json
//	@Security		BearerAuth
//	@Param			id	path		string	true	"Mapping id"
//	@Success		200	{object}	map[string]any
//	@Failure		404	{object}	apierror.Error
//	@Router			/import-mappings/{id} [get]
func (h *ImportMappingHandler) Get(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(w, r)
	if !ok {
		return
	}
	id, ok := h.id(w, r)
	if !ok {
		return
	}
	d, err := h.svc.Get(r.Context(), tid, id, 0)
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, d)
}

// GetVersion handles GET /api/v1/import-mappings/{id}/versions/{version}.
//
//	@Summary		Get one version of an import mapping
//	@Tags			Imports
//	@Produce		json
//	@Security		BearerAuth
//	@Param			id		path		string	true	"Mapping id"
//	@Param			version	path		int		true	"Version"
//	@Success		200		{object}	ImportMappingResponse
//	@Failure		404		{object}	apierror.Error
//	@Router			/import-mappings/{id}/versions/{version} [get]
func (h *ImportMappingHandler) GetVersion(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(w, r)
	if !ok {
		return
	}
	id, ok := h.id(w, r)
	if !ok {
		return
	}
	n, err := strconv.Atoi(chi.URLParam(r, "version"))
	if err != nil || n <= 0 {
		apierror.NotFound("import mapping version").WriteJSON(w)
		return
	}
	d, err := h.svc.Get(r.Context(), tid, id, n)
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, ImportMappingResponse{Mapping: d.Mapping, Version: d.Version})
}

// AddVersion handles POST /api/v1/import-mappings/{id}/versions.
//
//	@Summary		Save a new version of an import mapping
//	@Description	Versions are immutable. A version that changes the identity (the identity members, or how an identity member or the finding's asset is mapped) answers 409 identity_change_unconfirmed unless confirm_identity_change is set; it is then stored with identity_changed, and findings imported with earlier versions keep their identities. integrations:manage. Audited.
//	@Tags			Imports
//	@Accept			json
//	@Produce		json
//	@Security		BearerAuth
//	@Param			id		path		string							true	"Mapping id"
//	@Param			body	body		AddImportMappingVersionRequest	true	"Request"
//	@Success		201		{object}	ImportMappingResponse
//	@Failure		404		{object}	apierror.Error
//	@Failure		409		{object}	apierror.Error
//	@Failure		422		{object}	apierror.Error
//	@Router			/import-mappings/{id}/versions [post]
func (h *ImportMappingHandler) AddVersion(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(w, r)
	if !ok {
		return
	}
	id, ok := h.id(w, r)
	if !ok {
		return
	}
	var req AddImportMappingVersionRequest
	if !h.decode(w, r, &req) {
		return
	}
	m, v, err := h.svc.AddVersion(r.Context(), appimportmapping.AddVersionInput{
		TenantID: tid, ID: id, ActorID: mappingActor(r), Document: req.Mapping, Note: req.Note, ConfirmIdentityChange: req.ConfirmIdentityChange,
	})
	if err != nil {
		h.fail(w, err)
		return
	}
	h.auditEvent(r, auditdom.ActionImportMappingVersionCreated, m, nil,
		map[string]any{"version": v.Version, "digest": v.Digest, "identity": v.Identity},
		fmt.Sprintf("Import mapping %q version %d saved", m.Name, v.Version),
		map[string]any{"identity_changed": v.IdentityChanged})
	writeJSON(w, http.StatusCreated, ImportMappingResponse{Mapping: m, Version: v})
}

// Update handles PATCH /api/v1/import-mappings/{id}.
//
//	@Summary		Rename an import mapping or change its description
//	@Description	Imports already recorded keep the name they ran under. integrations:manage. Audited.
//	@Tags			Imports
//	@Accept			json
//	@Produce		json
//	@Security		BearerAuth
//	@Param			id		path		string						true	"Mapping id"
//	@Param			body	body		UpdateImportMappingRequest	true	"Request"
//	@Success		200		{object}	ImportMappingResponse
//	@Failure		404		{object}	apierror.Error
//	@Failure		409		{object}	apierror.Error
//	@Router			/import-mappings/{id} [patch]
func (h *ImportMappingHandler) Update(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(w, r)
	if !ok {
		return
	}
	id, ok := h.id(w, r)
	if !ok {
		return
	}
	var req UpdateImportMappingRequest
	if !h.decode(w, r, &req) {
		return
	}
	before, err := h.svc.Get(r.Context(), tid, id, 0)
	if err != nil {
		h.fail(w, err)
		return
	}
	prev := map[string]string{"name": before.Mapping.Name, "description": before.Mapping.Description}
	m, err := h.svc.Update(r.Context(), tid, id, req.Name, req.Description)
	if err != nil {
		h.fail(w, err)
		return
	}
	h.auditEvent(r, auditdom.ActionImportMappingUpdated, m, prev, map[string]string{"name": m.Name, "description": m.Description},
		fmt.Sprintf("Import mapping %q updated", m.Name), nil)
	writeJSON(w, http.StatusOK, ImportMappingResponse{Mapping: m})
}

// Delete handles DELETE /api/v1/import-mappings/{id}.
//
//	@Summary		Delete an import mapping
//	@Description	Removes the mapping and its versions; findings it imported stay. integrations:manage, step-up. Audited.
//	@Tags			Imports
//	@Security		BearerAuth
//	@Param			id	path	string	true	"Mapping id"
//	@Success		204
//	@Failure		404	{object}	apierror.Error
//	@Router			/import-mappings/{id} [delete]
func (h *ImportMappingHandler) Delete(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(w, r)
	if !ok {
		return
	}
	id, ok := h.id(w, r)
	if !ok {
		return
	}
	m, err := h.svc.Delete(r.Context(), tid, id)
	if err != nil {
		h.fail(w, err)
		return
	}
	h.auditEvent(r, auditdom.ActionImportMappingDeleted, m, map[string]any{"name": m.Name}, nil,
		fmt.Sprintf("Import mapping %q deleted", m.Name), nil)
	w.WriteHeader(http.StatusNoContent)
}

// Validate handles POST /api/v1/import-mappings/validate.
//
//	@Summary		Validate an import mapping document
//	@Description	Checks a document against the language and the organization policy; stores nothing. integrations:manage.
//	@Tags			Imports
//	@Accept			json
//	@Produce		json
//	@Security		BearerAuth
//	@Param			body	body		ValidateImportMappingRequest	true	"Request"
//	@Success		200		{object}	appimportmapping.Validation
//	@Router			/import-mappings/validate [post]
func (h *ImportMappingHandler) Validate(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.tenant(w, r); !ok {
		return
	}
	var req ValidateImportMappingRequest
	if !h.decode(w, r, &req) {
		return
	}
	writeJSON(w, http.StatusOK, h.svc.Validate(req.Mapping))
}

// Preview handles POST /api/v1/import-mappings/preview.
//
//	@Summary		Preview an import mapping on a sample
//	@Description	Multipart: a "mapping" part (the document as JSON) or "mapping_id" (and optional "version") fields of a saved mapping of the organization, then a "file" part with the sample (at most 5 MiB, the last part). Returns at most 50 CTIS records with the key ingest would store each finding under, warnings (identity collisions, unmapped fields), issues, and the sample's fields. Nothing is stored. integrations:manage; rate-limited per organization.
//	@Tags			Imports
//	@Accept			mpfd
//	@Produce		json
//	@Security		BearerAuth
//	@Param			mapping		formData	string	false	"Mapping document (JSON)"
//	@Param			mapping_id	formData	string	false	"Saved mapping id"
//	@Param			version		formData	int		false	"Saved mapping version (default latest)"
//	@Param			file		formData	file	true	"Sample"
//	@Success		200			{object}	appimportmapping.Preview
//	@Failure		400			{object}	apierror.Error
//	@Failure		404			{object}	apierror.Error
//	@Failure		413			{object}	apierror.Error
//	@Failure		422			{object}	apierror.Error
//	@Failure		429			{object}	apierror.Error
//	@Router			/import-mappings/preview [post]
func (h *ImportMappingHandler) Preview(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(w, r)
	if !ok {
		return
	}
	mr, err := r.MultipartReader()
	if err != nil {
		apierror.BadRequest("expected a multipart/form-data body").WriteJSON(w)
		return
	}
	var doc json.RawMessage
	var mappingID string
	version := 0
	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			apierror.BadRequest("the file part is missing").WriteJSON(w)
			return
		}
		if err != nil {
			apierror.BadRequest("the multipart body could not be read").WriteJSON(w)
			return
		}
		name := part.FormName()
		if name == "file" {
			var p *appimportmapping.Preview
			switch {
			case len(doc) > 0 && mappingID != "":
				apierror.BadRequest("send mapping or mapping_id, not both").WriteJSON(w)
				return
			case len(doc) > 0:
				p, err = h.svc.PreviewDocument(r.Context(), doc, part)
			case mappingID != "":
				id, idErr := shared.IDFromString(mappingID)
				if idErr != nil {
					apierror.NotFound("import mapping").WriteJSON(w)
					return
				}
				p, err = h.svc.PreviewVersion(r.Context(), tid, id, version, part)
			default:
				apierror.BadRequest("send a mapping part or a mapping_id before the file part").WriteJSON(w)
				return
			}
			_ = part.Close()
			if errors.Is(err, appimportmapping.ErrSampleTooLarge) {
				apierror.New(http.StatusRequestEntityTooLarge, apierror.CodeBadRequest, "the sample is larger than 5 MiB").WriteJSON(w)
				return
			}
			if err != nil {
				h.fail(w, err)
				return
			}
			writeJSON(w, http.StatusOK, p)
			return
		}
		value, err := io.ReadAll(io.LimitReader(part, importmapping.MaxDocumentBytes+1))
		_ = part.Close()
		if err != nil || len(value) > importmapping.MaxDocumentBytes {
			apierror.BadRequest("the " + safeFormName(name) + " part is too large").WriteJSON(w)
			return
		}
		switch name {
		case "mapping":
			doc = value
		case "mapping_id":
			mappingID = strings.TrimSpace(string(value))
		case "version":
			n, err := strconv.Atoi(strings.TrimSpace(string(value)))
			if err != nil || n < 0 {
				apierror.BadRequest("version must be a positive integer").WriteJSON(w)
				return
			}
			version = n
		default:
			apierror.BadRequest("unknown part " + safeFormName(name)).WriteJSON(w)
			return
		}
	}
}

// safeFormName bounds a client-chosen part name before it is echoed.
func safeFormName(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r > 0x7e {
			return -1
		}
		return r
	}, s)
	if len(s) > 32 {
		s = s[:32]
	}
	return strconv.Quote(s)
}
