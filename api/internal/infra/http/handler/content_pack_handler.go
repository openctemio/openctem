package handler

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	contentpackapp "github.com/openctemio/openctem/api/internal/app/contentpack"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/contentpack"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// ContentPackHandler serves /api/v1/content-packs: the tenant's content
// packs (RFC-061). Tenant from the JWT; every query is tenant-scoped, and a
// pack of another tenant is 404.
type ContentPackHandler struct {
	service *contentpackapp.Service
	logger  *logger.Logger
}

// NewContentPackHandler creates a ContentPackHandler.
func NewContentPackHandler(svc *contentpackapp.Service, log *logger.Logger) *ContentPackHandler {
	return &ContentPackHandler{service: svc, logger: log.With("handler", "content_pack")}
}

// ContentPackResponse is a content pack. lint is the platform's verdict:
// errors (none for a stored pack), warnings, suspected credentials (kind
// and path only) and the tier.
type ContentPackResponse struct {
	ID           string                 `json:"id"`
	Name         string                 `json:"name"`
	Version      string                 `json:"version"`
	Kind         string                 `json:"kind"`
	Digest       string                 `json:"digest"`
	SizeBytes    int64                  `json:"size_bytes"`
	FileCount    int                    `json:"file_count"`
	Tier         string                 `json:"tier" enums:"T0,T1,T2"`
	Status       string                 `json:"status" enums:"active,revoked"`
	Source       string                 `json:"source"`
	Lint         contentpack.LintReport `json:"lint"`
	CreatedBy    string                 `json:"created_by,omitempty"`
	CreatedAt    time.Time              `json:"created_at"`
	RevokedAt    *time.Time             `json:"revoked_at,omitempty"`
	RevokedBy    string                 `json:"revoked_by,omitempty"`
	RevokeReason string                 `json:"revoke_reason,omitempty"`
}

// ContentPackListResponse is a page of content packs.
type ContentPackListResponse struct {
	Data  []ContentPackResponse `json:"data"`
	Total int                   `json:"total"`
}

// RevokeContentPackRequest revokes a pack.
type RevokeContentPackRequest struct {
	Reason string `json:"reason"`
}

// ContentSigningKeyResponse is the tenant's content-signing public key.
type ContentSigningKeyResponse struct {
	Algorithm string `json:"algorithm"`
	PublicKey string `json:"public_key"` // base64
	KeyID     string `json:"key_id"`
}

func toContentPackResponse(p *contentpack.Pack) ContentPackResponse {
	out := ContentPackResponse{
		ID: p.ID.String(), Name: p.Name, Version: p.Version, Kind: p.Kind, Digest: p.Digest,
		SizeBytes: p.SizeBytes, FileCount: p.FileCount, Tier: string(p.Tier), Status: string(p.Status),
		Source: string(p.Source), Lint: p.Lint, CreatedAt: p.CreatedAt, RevokedAt: p.RevokedAt,
		RevokeReason: p.RevokeReason,
	}
	if p.CreatedBy != nil {
		out.CreatedBy = p.CreatedBy.String()
	}
	if p.RevokedBy != nil {
		out.RevokedBy = p.RevokedBy.String()
	}
	return out
}

// List handles GET /api/v1/content-packs
// @Summary      List content packs
// @Description  The organization's content packs, newest first.
// @Tags         Content Packs
// @Produce      json
// @Param        kind    query     string  false  "Kind (nuclei-templates, semgrep-rules, wordlist, x-<namespace>/<kind>)"
// @Param        name    query     string  false  "Pack name"
// @Param        status  query     string  false  "Status"  Enums(active,revoked)
// @Param        page      query     int     false  "Page (from 1)"
// @Param        per_page  query     int     false  "Page size (default 50, max 100)"
// @Success      200  {object}  ContentPackListResponse
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /content-packs [get]
func (h *ContentPackHandler) List(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	page, ok := listPageMax(w, r, 50, 100)
	if !ok {
		return
	}
	packs, total, err := h.service.List(r.Context(), contentpackapp.ListInput{
		TenantID: middleware.GetTenantID(r.Context()),
		Kind:     q.Get("kind"), Name: q.Get("name"), Status: q.Get("status"),
		Limit: page.Limit(), Offset: page.Offset(),
	})
	if err != nil {
		h.handleError(w, err)
		return
	}
	resp := ContentPackListResponse{Data: make([]ContentPackResponse, 0, len(packs)), Total: total}
	for _, p := range packs {
		resp.Data = append(resp.Data, toContentPackResponse(p))
	}
	writeScanZoneJSON(w, http.StatusOK, resp)
}

// Get handles GET /api/v1/content-packs/{id}
// @Summary      Get content pack
// @Tags         Content Packs
// @Produce      json
// @Param        id   path      string  true  "Content pack ID"
// @Success      200  {object}  ContentPackResponse
// @Failure      401  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /content-packs/{id} [get]
func (h *ContentPackHandler) Get(w http.ResponseWriter, r *http.Request) {
	p, err := h.service.Get(r.Context(), middleware.GetTenantID(r.Context()), chi.URLParam(r, "id"))
	if err != nil {
		h.handleError(w, err)
		return
	}
	writeScanZoneJSON(w, http.StatusOK, toContentPackResponse(p))
}

// Upload handles POST /api/v1/content-packs
// @Summary      Upload content pack
// @Description  multipart/form-data with name, version, kind, acknowledge_secrets (optional, true stores a pack in which lint found what look like credentials) and archive (a tar or tar.gz). The platform refuses links, devices, unsafe paths and archives over its limits, canonicalises the files (the digest is the SHA-256 of the canonical tar), lints them for the kind, classifies the tier, and signs the pack with the organization's content key. A pack is immutable; a change is a new version. 422 CONTENT_LINT_FAILED or CONTENT_SECRETS_FOUND carry the lint report in details. Requires a recent sign-in.
// @Tags         Content Packs
// @Accept       mpfd
// @Produce      json
// @Param        name                 formData  string  true   "Pack name"
// @Param        version              formData  string  true   "Version"
// @Param        kind                 formData  string  true   "Kind"
// @Param        acknowledge_secrets  formData  bool    false  "Store despite suspected credentials"
// @Param        archive              formData  file    true   "tar or tar.gz"
// @Success      201  {object}  ContentPackResponse
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error  "name and version exist"
// @Failure      413  {object}  apierror.Error
// @Failure      422  {object}  apierror.Error  "lint refused the pack"
// @Security     BearerAuth
// @Router       /content-packs [post]
func (h *ContentPackHandler) Upload(w http.ResponseWriter, r *http.Request) {
	maxUpload := h.service.Limits().MaxUpload
	r.Body = http.MaxBytesReader(w, r.Body, maxUpload+64<<10)
	mr, err := r.MultipartReader()
	if err != nil {
		apierror.BadRequest("Expected multipart/form-data").WriteJSON(w)
		return
	}
	actx := buildScanZoneAuditContext(r)
	in := contentpackapp.UploadInput{TenantID: actx.TenantID, CreatedBy: actx.ActorID}
	var archive []byte
	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			h.writeReadError(w, err)
			return
		}
		if archive, err = h.readPart(part, &in, archive, maxUpload); err != nil {
			h.writeReadError(w, err)
			return
		}
	}
	if archive == nil {
		apierror.BadRequest("archive is required").WriteJSON(w)
		return
	}
	in.Archive = bytes.NewReader(archive)
	p, err := h.service.Upload(r.Context(), in, actx)
	if err != nil {
		h.handleError(w, err)
		return
	}
	writeScanZoneJSON(w, http.StatusCreated, toContentPackResponse(p))
}

// errUploadTooLarge is an archive part over the upload limit.
var errUploadTooLarge = errors.New("upload too large")

// readPart reads one form part into in (or the archive, returned).
func (h *ContentPackHandler) readPart(part *multipart.Part, in *contentpackapp.UploadInput, archive []byte, maxUpload int64) ([]byte, error) {
	defer part.Close()
	switch part.FormName() {
	case "archive":
		data, err := io.ReadAll(io.LimitReader(part, maxUpload+1))
		if err != nil {
			return nil, err
		}
		if int64(len(data)) > maxUpload {
			return nil, errUploadTooLarge
		}
		return data, nil
	case "name", "version", "kind", "acknowledge_secrets":
		v, err := io.ReadAll(io.LimitReader(part, 256))
		if err != nil {
			return nil, err
		}
		s := strings.TrimSpace(string(v))
		switch part.FormName() {
		case "name":
			in.Name = s
		case "version":
			in.Version = s
		case "kind":
			in.Kind = s
		default:
			in.AcknowledgeSecrets, _ = strconv.ParseBool(s)
		}
	}
	return archive, nil
}

func (h *ContentPackHandler) writeReadError(w http.ResponseWriter, err error) {
	var tooLarge *http.MaxBytesError
	if errors.Is(err, errUploadTooLarge) || errors.As(err, &tooLarge) {
		apierror.New(http.StatusRequestEntityTooLarge, apierror.CodeBadRequest,
			fmt.Sprintf("The archive is larger than %d bytes", h.service.Limits().MaxUpload)).WriteJSON(w)
		return
	}
	apierror.BadRequest("Invalid multipart body").WriteJSON(w)
}

// Revoke handles POST /api/v1/content-packs/{id}/revoke
// @Summary      Revoke content pack
// @Description  The pack stays listed with who revoked it and why, and is never delivered again. Requires a recent sign-in.
// @Tags         Content Packs
// @Accept       json
// @Produce      json
// @Param        id    path      string                    true  "Content pack ID"
// @Param        body  body      RevokeContentPackRequest  true  "Reason"
// @Success      200   {object}  ContentPackResponse
// @Failure      400   {object}  apierror.Error
// @Failure      401   {object}  apierror.Error
// @Failure      403   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Failure      409   {object}  apierror.Error  "already revoked"
// @Security     BearerAuth
// @Router       /content-packs/{id}/revoke [post]
func (h *ContentPackHandler) Revoke(w http.ResponseWriter, r *http.Request) {
	var req RevokeContentPackRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	actx := buildScanZoneAuditContext(r)
	p, err := h.service.Revoke(r.Context(), actx.TenantID, chi.URLParam(r, "id"), req.Reason, actx)
	if err != nil {
		h.handleError(w, err)
		return
	}
	writeScanZoneJSON(w, http.StatusOK, toContentPackResponse(p))
}

// Download handles GET /api/v1/content-packs/{id}/download
// @Summary      Download content pack archive
// @Description  The canonical tar, checked against the pack digest before it is sent. The digest is in the Digest header.
// @Tags         Content Packs
// @Produce      application/x-tar
// @Param        id   path  string  true  "Content pack ID"
// @Success      200  {file}  file
// @Failure      401  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /content-packs/{id}/download [get]
func (h *ContentPackHandler) Download(w http.ResponseWriter, r *http.Request) {
	p, data, err := h.service.Archive(r.Context(), middleware.GetTenantID(r.Context()), chi.URLParam(r, "id"))
	if err != nil {
		h.handleError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/x-tar")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s-%s.tar"`, p.Name, p.Version))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Digest", p.Digest)
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// SigningKey handles GET /api/v1/content-packs/signing-key
// @Summary      Content signing key
// @Description  The organization's content-signing public key (Ed25519), which its sensors pin to verify packs. Not a secret.
// @Tags         Content Packs
// @Produce      json
// @Success      200  {object}  ContentSigningKeyResponse
// @Failure      401  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      503  {object}  apierror.Error  "content signing not configured"
// @Security     BearerAuth
// @Router       /content-packs/signing-key [get]
func (h *ContentPackHandler) SigningKey(w http.ResponseWriter, r *http.Request) {
	pub, id, err := h.service.SigningKey(middleware.GetTenantID(r.Context()))
	if err != nil {
		h.handleError(w, err)
		return
	}
	writeScanZoneJSON(w, http.StatusOK, ContentSigningKeyResponse{Algorithm: "ed25519", PublicKey: pub, KeyID: id})
}

func (h *ContentPackHandler) handleError(w http.ResponseWriter, err error) {
	var de *shared.DomainError
	switch {
	case errors.Is(err, contentpack.ErrSigningKey):
		apierror.New(http.StatusServiceUnavailable, apierror.Code("CONTENT_SIGNING_UNAVAILABLE"),
			"Content signing is not configured on this platform").WriteJSON(w)
	case errors.As(err, &de) && (de.Code == "CONTENT_LINT_FAILED" || de.Code == "CONTENT_SECRETS_FOUND"):
		apierror.New(http.StatusUnprocessableEntity, apierror.Code(de.Code), de.Message).WithDetails(de.Details).WriteJSON(w)
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Content pack").WriteJSON(w)
	case errors.Is(err, shared.ErrConflict):
		apierror.Conflict(cleanErrorMessage(err, "Conflict")).WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.New(http.StatusBadRequest, apierror.CodeBadRequest, cleanErrorMessage(err, "Invalid content pack")).WriteJSON(w)
	default:
		h.logger.Error("content pack error", "error", err)
		apierror.InternalError(err).WriteJSON(w)
	}
}
