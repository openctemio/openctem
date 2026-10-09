package handler

// Authorization letters (RFC-065 §13): /api/v1/scope/letters.

import (
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	auditsvc "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// ScopeLetterHandler serves authorization letters.
type ScopeLetterHandler struct {
	svc    *scope.LetterService
	audit  *auditsvc.AuditService
	logger *logger.Logger
}

// NewScopeLetterHandler creates the handler.
func NewScopeLetterHandler(svc *scope.LetterService, audit *auditsvc.AuditService, log *logger.Logger) *ScopeLetterHandler {
	return &ScopeLetterHandler{svc: svc, audit: audit, logger: log}
}

// AuthorizationLetterResponse is one letter.
type AuthorizationLetterResponse struct {
	ID         string     `json:"id"`
	Title      string     `json:"title"`
	Issuer     string     `json:"issuer"`
	Reference  string     `json:"reference"`
	ValidFrom  time.Time  `json:"valid_from"`
	ValidUntil time.Time  `json:"valid_until"`
	InEffect   bool       `json:"in_effect"`
	FileSHA256 string     `json:"file_sha256"`
	UploadedBy *ActorRef  `json:"uploaded_by,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	RevokedBy  *ActorRef  `json:"revoked_by,omitempty"`
}

func toLetterResponse(l *scopedom.Letter) AuthorizationLetterResponse {
	return AuthorizationLetterResponse{
		ID: l.ID.String(), Title: l.Title, Issuer: l.Issuer, Reference: l.Reference,
		ValidFrom: l.ValidFrom, ValidUntil: l.ValidUntil, InEffect: l.InEffect(time.Now()),
		FileSHA256: l.FileSHA256, UploadedBy: idRef(l.UploadedBy), CreatedAt: l.CreatedAt,
		RevokedAt: l.RevokedAt, RevokedBy: idRef(l.RevokedBy),
	}
}

func (h *ScopeLetterHandler) ids(w http.ResponseWriter, r *http.Request, withPath bool) (tenantID, actor, id shared.ID, ok bool) {
	tenantID, err := shared.IDFromString(middleware.MustGetTenantID(r.Context()))
	if err != nil {
		apierror.Unauthorized("").WriteJSON(w)
		return
	}
	actor, _ = shared.IDFromString(middleware.GetUserID(r.Context()))
	if withPath {
		if id, err = shared.IDFromString(chi.URLParam(r, "id")); err != nil {
			apierror.NotFound("Authorization letter").WriteJSON(w)
			return
		}
	}
	return tenantID, actor, id, true
}

func (h *ScopeLetterHandler) writeError(w http.ResponseWriter, err error) {
	if writeScopeEntryError(w, err) {
		return
	}
	switch {
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Authorization letter").WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(err.Error()).WriteJSON(w)
	default:
		h.logger.Error("authorization letter request failed", "error", logger.SanitizeError(err))
		apierror.InternalServerError("Authorization letter request failed").WriteJSON(w)
	}
}

// parseLetterTime reads RFC 3339 or a date (YYYY-MM-DD, midnight UTC).
func parseLetterTime(v string) (time.Time, error) {
	if v == "" {
		return time.Time{}, nil
	}
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		return t, nil
	}
	return time.Parse("2006-01-02", v)
}

// Upload handles POST /api/v1/scope/letters
// @Summary      Upload authorization letter
// @Description  Store a letter of authorization (multipart: file as PDF, PNG or JPEG up to 10 MB; title; issuer; reference; valid_from; valid_until, at most 2 years after valid_from). The file's SHA-256 is recorded. A letter authorizes nothing by itself: scope entries with authorization_source authorization_letter name it, go through the organization's approval policy and authorize only while it is valid (RFC-065). Audited.
// @Tags         Scope
// @Accept       multipart/form-data
// @Produce      json
// @Success      201  {object}  AuthorizationLetterResponse
// @Failure      400  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scope/letters [post]
func (h *ScopeLetterHandler) Upload(w http.ResponseWriter, r *http.Request) {
	tenantID, actor, _, ok := h.ids(w, r, false)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, scope.MaxLetterFileSize+1<<20)
	if err := r.ParseMultipartForm(2 << 20); err != nil {
		apierror.BadRequest("Invalid multipart form or file too large").WriteJSON(w)
		return
	}
	defer func() {
		if r.MultipartForm != nil {
			_ = r.MultipartForm.RemoveAll()
		}
	}()
	file, header, err := r.FormFile("file")
	if err != nil {
		apierror.BadRequest("The letter file is required (field file)").WriteJSON(w)
		return
	}
	defer func() { _ = file.Close() }()
	from, err1 := parseLetterTime(r.FormValue("valid_from"))
	until, err2 := parseLetterTime(r.FormValue("valid_until"))
	if err1 != nil || err2 != nil {
		apierror.BadRequest("valid_from and valid_until are RFC 3339 times or YYYY-MM-DD dates").WriteJSON(w)
		return
	}
	l, err := h.svc.Upload(r.Context(), scope.UploadLetterInput{
		TenantID: tenantID, UploadedBy: actor, Title: r.FormValue("title"), Issuer: r.FormValue("issuer"),
		Reference: r.FormValue("reference"), ValidFrom: from, ValidUntil: until,
		Filename: header.Filename, ContentType: header.Header.Get("Content-Type"), Size: header.Size, File: file,
	})
	if err != nil {
		h.writeError(w, err)
		return
	}
	event := auditsvc.NewSuccessEvent(audit.ActionScopeLetterUploaded, audit.ResourceTypeAuthorizationLetter, l.ID.String()).
		WithResourceName(l.Title).WithMessage("Authorization letter uploaded").
		WithMetadata("valid_until", l.ValidUntil.Format(time.RFC3339)).WithMetadata("file_sha256", l.FileSHA256)
	logRequestChange(h.audit, h.logger, r, event)
	writeJSON(w, http.StatusCreated, toLetterResponse(l))
}

// List handles GET /api/v1/scope/letters
// @Summary      List authorization letters
// @Description  The organization's letters of authorization, newest first, with whether each is in effect now.
// @Tags         Scope
// @Produce      json
// @Success      200  {object}  map[string][]AuthorizationLetterResponse
// @Security     BearerAuth
// @Router       /scope/letters [get]
func (h *ScopeLetterHandler) List(w http.ResponseWriter, r *http.Request) {
	tenantID, _, _, ok := h.ids(w, r, false)
	if !ok {
		return
	}
	list, err := h.svc.List(r.Context(), tenantID)
	if err != nil {
		h.writeError(w, err)
		return
	}
	out := make([]AuthorizationLetterResponse, 0, len(list))
	for _, l := range list {
		out = append(out, toLetterResponse(l))
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": out})
}

// File handles GET /api/v1/scope/letters/{id}/file
// @Summary      Download authorization letter
// @Description  The letter's file, as uploaded; its SHA-256 is in the X-Content-SHA256 header.
// @Tags         Scope
// @Produce      application/octet-stream
// @Param        id   path  string  true  "Letter ID"
// @Success      200
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scope/letters/{id}/file [get]
func (h *ScopeLetterHandler) File(w http.ResponseWriter, r *http.Request) {
	tenantID, _, id, ok := h.ids(w, r, true)
	if !ok {
		return
	}
	rc, contentType, _, l, err := h.svc.File(r.Context(), tenantID, id)
	if err != nil {
		h.writeError(w, err)
		return
	}
	defer func() { _ = rc.Close() }()
	if !scopedom.LetterContentTypes[contentType] {
		contentType = "application/octet-stream"
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", `attachment; filename="letter-`+l.ID.String()+`"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Content-SHA256", l.FileSHA256)
	w.Header().Set("Cache-Control", "private, no-store")
	_, _ = io.Copy(w, io.LimitReader(rc, scope.MaxLetterFileSize+1))
}

// Revoke handles POST /api/v1/scope/letters/{id}/revoke
// @Summary      Revoke authorization letter
// @Description  Every scope entry naming the letter stops authorizing at once. Needs attack_surface:scope:approve. Audited; administrators are notified.
// @Tags         Scope
// @Produce      json
// @Param        id   path      string  true  "Letter ID"
// @Success      200  {object}  AuthorizationLetterResponse
// @Failure      404  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scope/letters/{id}/revoke [post]
func (h *ScopeLetterHandler) Revoke(w http.ResponseWriter, r *http.Request) {
	tenantID, actor, id, ok := h.ids(w, r, true)
	if !ok {
		return
	}
	l, err := h.svc.Revoke(r.Context(), tenantID, id, actor)
	if err != nil {
		h.writeError(w, err)
		return
	}
	event := auditsvc.NewSuccessEvent(audit.ActionScopeLetterRevoked, audit.ResourceTypeAuthorizationLetter, l.ID.String()).
		WithResourceName(l.Title).WithMessage("Authorization letter revoked").WithMetadata("revoked_at", strconv.FormatInt(l.RevokedAt.Unix(), 10))
	logRequestChange(h.audit, h.logger, r, event)
	writeJSON(w, http.StatusOK, toLetterResponse(l))
}
