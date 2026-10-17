package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/internal/app/integration"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/attachment"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/httpsec"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// errAttachmentAccessDenied is returned when the caller may not access an
// attachment that exists in their tenant. Handlers map it to 404 (same as a
// missing attachment) to avoid leaking existence.
var errAttachmentAccessDenied = errors.New("attachment access denied")

// Pentest attachment contexts. "finding" and "retest" both carry the finding
// id as context_id; "campaign" carries the campaign id.
const (
	attachmentCtxFinding  = "finding"
	attachmentCtxRetest   = "retest"
	attachmentCtxCampaign = "campaign"
)

// FindingCampaignAccessChecker verifies that a user has access to a finding's
// or campaign's attachments. Returns nil if access is allowed,
// ErrNotFound/ErrForbidden otherwise.
type FindingCampaignAccessChecker interface {
	CheckFindingAccess(ctx context.Context, tenantID, findingID, userID string, isAdmin bool) error
	CheckCampaignAccess(ctx context.Context, tenantID, campaignID, userID string, isAdmin bool) error
	// CheckFindingEvidenceWrite / CheckCampaignEvidenceWrite gate adding and
	// removing evidence: the caller must be able to edit the finding (or
	// write to the campaign), and the campaign must not be locked.
	CheckFindingEvidenceWrite(ctx context.Context, tenantID, findingID, userID string, isAdmin bool) error
	// CheckRetestEvidenceWrite gates retest evidence: the right to submit a
	// retest, allowed while the campaign's remediation is open (completed
	// included).
	CheckRetestEvidenceWrite(ctx context.Context, tenantID, findingID, userID string, isAdmin bool) error
	CheckCampaignEvidenceWrite(ctx context.Context, tenantID, campaignID, userID string, isAdmin bool) error
}

// AttachmentHandler handles file upload/download/delete HTTP endpoints.
type AttachmentHandler struct {
	service         *integration.AttachmentService
	accessChecker   FindingCampaignAccessChecker  // optional; when nil, no campaign check
	storageResolver *auth.SettingsStorageResolver // optional; for storage config CRUD
	audit           *auditapp.AuditService        // optional; audits storage config changes
	logger          *logger.Logger
}

// SetAuditService wires the audit log for storage configuration changes.
func (h *AttachmentHandler) SetAuditService(a *auditapp.AuditService) { h.audit = a }

// NewAttachmentHandler creates a new handler.
func NewAttachmentHandler(svc *integration.AttachmentService, log *logger.Logger) *AttachmentHandler {
	return &AttachmentHandler{service: svc, logger: log}
}

// SetStorageResolver wires the tenant storage config resolver for GET/PATCH storage settings.
func (h *AttachmentHandler) SetStorageResolver(resolver *auth.SettingsStorageResolver) {
	h.storageResolver = resolver
}

// SetAccessChecker wires the campaign-membership checker for finding-scoped attachments.
func (h *AttachmentHandler) SetAccessChecker(checker FindingCampaignAccessChecker) {
	h.accessChecker = checker
}

// validAttachmentContext reports whether contextType is one the access
// checker authorizes: finding, retest, campaign, or empty (a private orphan
// attachment of the uploader). An unknown type would skip every context check,
// so Upload, List and LinkToContext refuse it.
func validAttachmentContext(contextType string) bool {
	switch contextType {
	case "", attachmentCtxFinding, attachmentCtxRetest, attachmentCtxCampaign:
		return true
	}
	return false
}

// verifyContextWrite checks the caller may add evidence to (upload/link into)
// the given context: finding contexts need the right to edit the finding and
// a campaign that is not completed or canceled; retest contexts the right to
// submit a retest and open remediation (completed allowed, canceled or
// archived refused); campaign contexts a role that can upload evidence on a
// campaign that is not completed or canceled. Observers stay read-only.
// Empty/unknown context (a private orphan attachment owned by the uploader) is
// allowed. No-op when no checker is configured.
// Both "finding" and "retest" contexts use finding ID as context_id.
func (h *AttachmentHandler) verifyContextWrite(r *http.Request, contextType, contextID string) error {
	if h.accessChecker == nil || contextID == "" {
		return nil
	}
	tenantID := middleware.MustGetTenantID(r.Context())
	userID := middleware.GetUserID(r.Context())
	isAdmin := middleware.IsAdmin(r.Context())
	switch contextType {
	case attachmentCtxFinding:
		return h.accessChecker.CheckFindingEvidenceWrite(r.Context(), tenantID, contextID, userID, isAdmin)
	case attachmentCtxRetest:
		return h.accessChecker.CheckRetestEvidenceWrite(r.Context(), tenantID, contextID, userID, isAdmin)
	case attachmentCtxCampaign:
		return h.accessChecker.CheckCampaignEvidenceWrite(r.Context(), tenantID, contextID, userID, isAdmin)
	default:
		return nil
	}
}

// verifyContextAccess checks the caller may read the given context's
// attachments: finding/retest contexts require campaign membership for the
// finding; campaign contexts require campaign membership. No-op when no
// checker is configured.
func (h *AttachmentHandler) verifyContextAccess(r *http.Request, contextType, contextID string) error {
	if h.accessChecker == nil || contextID == "" {
		return nil
	}
	tenantID := middleware.MustGetTenantID(r.Context())
	userID := middleware.GetUserID(r.Context())
	isAdmin := middleware.IsAdmin(r.Context())
	switch contextType {
	case attachmentCtxFinding, attachmentCtxRetest:
		return h.accessChecker.CheckFindingAccess(r.Context(), tenantID, contextID, userID, isAdmin)
	case attachmentCtxCampaign:
		return h.accessChecker.CheckCampaignAccess(r.Context(), tenantID, contextID, userID, isAdmin)
	default:
		return nil
	}
}

// authorizeAttachment decides whether the caller may read or delete an
// existing attachment. Deny-by-default: finding/retest and campaign contexts
// require campaign membership; an attachment with no (or unknown) context is
// private to its uploader. Admins bypass. Cross-tenant is already blocked by
// the tenant-scoped GetByID in the caller. Previously campaign-context and
// context-less attachments were reachable by any tenant user with the
// pentest:findings:read permission (same-tenant IDOR on evidence).
func (h *AttachmentHandler) authorizeAttachment(r *http.Request, att *attachment.Attachment) error {
	if h.accessChecker == nil {
		return nil // checker not wired (tests/dev) — preserve legacy behavior
	}
	if middleware.IsAdmin(r.Context()) {
		return nil
	}
	tenantID := middleware.MustGetTenantID(r.Context())
	userID := middleware.GetUserID(r.Context())
	ct, cid := att.ContextType(), att.ContextID()
	switch {
	case cid != "" && (ct == attachmentCtxFinding || ct == attachmentCtxRetest):
		return h.accessChecker.CheckFindingAccess(r.Context(), tenantID, cid, userID, false)
	case cid != "" && ct == attachmentCtxCampaign:
		return h.accessChecker.CheckCampaignAccess(r.Context(), tenantID, cid, userID, false)
	default:
		// No / unknown context → private to the uploader.
		if att.UploadedBy().String() == userID {
			return nil
		}
		return errAttachmentAccessDenied
	}
}

// authorizeAttachmentWrite decides whether the caller may remove an existing
// attachment. Finding/retest and campaign contexts need the same rights as
// adding evidence there (verifyContextWrite); an attachment with no (or
// unknown) context stays private to its uploader. Admins bypass.
func (h *AttachmentHandler) authorizeAttachmentWrite(r *http.Request, att *attachment.Attachment) error {
	if middleware.IsAdmin(r.Context()) {
		return nil
	}
	ct, cid := att.ContextType(), att.ContextID()
	switch {
	case cid != "" && (ct == attachmentCtxFinding || ct == attachmentCtxRetest || ct == attachmentCtxCampaign):
		return h.verifyContextWrite(r, ct, cid)
	default:
		if att.UploadedBy().String() == middleware.GetUserID(r.Context()) {
			return nil
		}
		return errAttachmentAccessDenied
	}
}

// writeAttachmentAccessError answers a refused attachment change: a member
// who may read but not change the evidence gets 403 with the reason; anyone
// else gets 404, so the attachment's existence does not leak.
func writeAttachmentAccessError(w http.ResponseWriter, err error) {
	if errors.Is(err, shared.ErrForbidden) {
		apierror.Forbidden("You cannot change this evidence: your campaign role, the finding's owner or the campaign's status does not allow it").WriteJSON(w)
		return
	}
	apierror.NotFound("Attachment not found").WriteJSON(w)
}

// Upload handles multipart file upload.
// POST /api/v1/attachments
//
// Accepts multipart/form-data with:
//   - file: the file to upload
//   - context_type: optional "finding", "retest", "campaign"
//   - context_id: optional UUID of the linked entity
//
// Returns JSON with the attachment metadata including the download URL.
func (h *AttachmentHandler) Upload(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	userID := middleware.GetUserID(r.Context())

	// Limit request body to max file size + overhead
	const maxBody = attachment.MaxFileSize + 1024*1024 // file + form overhead
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)

	if err := r.ParseMultipartForm(multipartMemory); err != nil {
		apierror.BadRequest("File too large or invalid multipart form").WriteJSON(w)
		return
	}

	// Campaign membership check on upload
	ctxType := r.FormValue("context_type")
	ctxID := r.FormValue("context_id")
	if !validAttachmentContext(ctxType) {
		apierror.BadRequest("context_type must be finding, retest or campaign").WriteJSON(w)
		return
	}
	if err := h.verifyContextWrite(r, ctxType, ctxID); err != nil {
		writeAttachmentAccessError(w, err)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		apierror.BadRequest("Missing 'file' field in multipart form").WriteJSON(w)
		return
	}
	defer file.Close()

	// The type comes from the file's first bytes (the extension only refines
	// generic text or binary); what the client declares is ignored.
	head := make([]byte, attachment.SniffLen)
	n, _ := io.ReadFull(file, head)
	contentType := attachment.DetectContentType(head[:n], header.Filename)
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		apierror.BadRequest("The file could not be read").WriteJSON(w)
		return
	}

	att, err := h.service.Upload(r.Context(), integration.UploadInput{
		TenantID:    tenantID,
		Filename:    header.Filename,
		ContentType: contentType,
		Size:        header.Size,
		Reader:      file,
		UploadedBy:  userID,
		ContextType: r.FormValue("context_type"),
		ContextID:   r.FormValue("context_id"),
	})
	if err != nil {
		switch {
		case errors.Is(err, attachment.ErrTooLarge):
			apierror.BadRequest(err.Error()).WriteJSON(w)
		case errors.Is(err, attachment.ErrUnsupported):
			apierror.BadRequest(err.Error()).WriteJSON(w)
		case errors.Is(err, attachment.ErrImageTooLarge):
			apierror.New(http.StatusBadRequest, "IMAGE_TOO_LARGE",
				fmt.Sprintf("The image is larger than %d megapixels", attachment.MaxImagePixels/1_000_000)).WriteJSON(w)
		case errors.Is(err, attachment.ErrImageInvalid):
			apierror.New(http.StatusBadRequest, "IMAGE_INVALID", "The image file is damaged or not a valid image").WriteJSON(w)
		case errors.Is(err, attachment.ErrQuotaExceeded):
			apierror.New(http.StatusRequestEntityTooLarge, "STORAGE_QUOTA_EXCEEDED",
				"The organization's file storage is full: delete files or ask the operator to raise the quota").WriteJSON(w)
		case errors.Is(err, attachment.ErrStorageUnavailable):
			apierror.ServiceUnavailable("The organization's file storage cannot be reached: check the storage settings").WriteJSON(w)
		default:
			h.logger.Error("attachment upload failed", "error", err)
			apierror.InternalServerError("Upload failed").WriteJSON(w)
		}
		return
	}

	uploaded := auditapp.NewSuccessEvent(auditdom.ActionAttachmentUploaded, auditdom.ResourceTypeAttachment, att.ID().String()).
		WithResourceName(att.Filename()).
		WithMessage("Evidence file uploaded").
		WithMetadata("content_type", att.ContentType()).
		WithMetadata("size", att.Size()).
		WithMetadata("sha256", att.ContentHash()).
		WithMetadata("context_type", att.ContextType()).
		WithMetadata("context_id", att.ContextID())
	if orig := att.OriginalContentHash(); orig != "" {
		// Image metadata was removed: the stored bytes differ from those received.
		uploaded = uploaded.WithMetadata("original_sha256", orig).WithMetadata("metadata_removed", true)
	}
	logRequestChange(h.audit, h.logger, r, uploaded)

	writeJSON(w, http.StatusCreated, attachmentJSON(att))
}

// attachmentJSON is an attachment as the upload and list routes return it.
func attachmentJSON(att *attachment.Attachment) map[string]any {
	return map[string]any{
		"id":           att.ID().String(),
		"filename":     att.Filename(),
		"content_type": att.ContentType(),
		"size":         att.Size(),
		"url":          att.URL(),
		"markdown":     att.MarkdownLink(),
		"created_at":   att.CreatedAt(),
		"scan_status":  string(att.ScanStatus()),
		"scan_result":  att.ScanResult(),
	}
}

// confirmInfectedParam is the query a download of a flagged file needs:
// GET /api/v1/attachments/{id}?confirm=malware.
const confirmInfectedParam = "malware"

// Download serves the file content for an attachment.
// GET /api/v1/attachments/{id}
func (h *AttachmentHandler) Download(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	id := chi.URLParam(r, "id")

	// Resolve the record (tenant-scoped) to check context access and the
	// malware scan state.
	att, aerr := h.service.GetByID(r.Context(), tenantID, id)
	if aerr != nil {
		apierror.NotFound("Attachment not found").WriteJSON(w)
		return
	}
	if h.accessChecker != nil {
		if err := h.authorizeAttachment(r, att); err != nil {
			apierror.NotFound("Attachment not found").WriteJSON(w)
			return
		}
	}
	// A file the malware scanner flagged is kept (evidence is never blocked)
	// but served only on an explicit confirmation, which is audited.
	if att.ScanStatus() == attachment.ScanInfected {
		if r.URL.Query().Get("confirm") != confirmInfectedParam {
			apierror.New(http.StatusConflict, "MALWARE_DETECTED",
				"The malware scanner flagged this file ("+att.ScanResult()+"); download it with ?confirm=malware").WriteJSON(w)
			return
		}
		logRequestChange(h.audit, h.logger, r,
			auditapp.NewSuccessEvent(auditdom.ActionAttachmentInfectedDownloaded, auditdom.ResourceTypeAttachment, att.ID().String()).
				WithResourceName(att.Filename()).
				WithMessage("A file flagged by the malware scanner was downloaded after confirmation").
				WithMetadata("signature", att.ScanResult()).
				WithMetadata("sha256", att.ContentHash()))
	}

	reader, contentType, filename, err := h.service.Download(r.Context(), tenantID, id)
	if err != nil {
		if errors.Is(err, attachment.ErrNotFound) {
			apierror.NotFound("Attachment not found").WriteJSON(w)
			return
		}
		if errors.Is(err, attachment.ErrStorageUnavailable) {
			apierror.ServiceUnavailable("The organization's file storage cannot be reached").WriteJSON(w)
			return
		}
		h.logger.Error("attachment download failed", "error", err, "id", id)
		apierror.InternalServerError("Download failed").WriteJSON(w)
		return
	}
	defer reader.Close()

	// Set headers for inline display (images) or download (other files).
	// Use mime.FormatMediaType to properly escape filename (prevents header injection).
	w.Header().Set("Content-Type", contentType)
	disposition := "attachment"
	if isImageMIME(contentType) && att.ScanStatus() != attachment.ScanInfected {
		disposition = "inline"
	}
	w.Header().Set("Content-Disposition", mime.FormatMediaType(disposition, map[string]string{"filename": filename}))
	// Cache for 1 hour (attachments are immutable once uploaded)
	w.Header().Set("Cache-Control", "private, max-age=3600")
	if att.ScanStatus() == attachment.ScanInfected {
		w.Header().Set("Cache-Control", "no-store")
	}
	w.Header().Set("X-Content-Type-Options", "nosniff")

	if _, err := io.Copy(w, reader); err != nil {
		h.logger.Warn("attachment stream interrupted", "error", logger.SanitizeError(err), "id", logger.SanitizeValue(id))
	}
}

// DownloadURL hands out a short-lived signed URL for the attachment's file in
// its bucket, after the same checks as Download (tenant-scoped lookup, then
// the finding/campaign/uploader rules). The URL works for 60 seconds, for
// this one object, and forces an attachment download. A file the malware
// scanner flagged never gets one; a storage that cannot sign (local
// storage, an endpoint without HTTPS) or direct downloads turned off answer
// 409 DIRECT_DOWNLOAD_UNAVAILABLE, and the caller uses Download.
//
// @Summary      Signed download URL for an attachment
// @Description  A 60-second URL signed for this one file in its bucket, after the same checks as a download. 409 DIRECT_DOWNLOAD_UNAVAILABLE: download through GET /attachments/{id}.
// @Tags         Attachments
// @Produce      json
// @Param        id   path      string  true  "Attachment ID"
// @Success      200  {object}  AttachmentSignedURLResponse
// @Failure      401  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Failure      503  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /attachments/{id}/signed-url [get]
func (h *AttachmentHandler) DownloadURL(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	id := chi.URLParam(r, "id")
	att, err := h.service.GetByID(r.Context(), tenantID, id)
	if err != nil {
		apierror.NotFound("Attachment not found").WriteJSON(w)
		return
	}
	if h.accessChecker != nil {
		if err := h.authorizeAttachment(r, att); err != nil {
			apierror.NotFound("Attachment not found").WriteJSON(w)
			return
		}
	}
	url, expires, err := h.service.DirectDownloadURL(r.Context(), att)
	if err != nil {
		switch {
		case errors.Is(err, attachment.ErrInfected):
			apierror.New(http.StatusConflict, "MALWARE_DETECTED",
				"The malware scanner flagged this file; download it through the API with ?confirm=malware").WriteJSON(w)
		case errors.Is(err, attachment.ErrStorageUnavailable):
			apierror.ServiceUnavailable("The organization's file storage cannot be reached").WriteJSON(w)
		default:
			apierror.New(http.StatusConflict, "DIRECT_DOWNLOAD_UNAVAILABLE",
				"This file downloads through the API").WriteJSON(w)
		}
		return
	}
	// The signed URL is a bearer credential for one object until it expires:
	// never cached, never sent on as a referrer.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	writeJSON(w, http.StatusOK, AttachmentSignedURLResponse{URL: url, ExpiresAt: expires.UTC()})
}

// AttachmentSignedURLResponse is a signed download URL and when it expires.
type AttachmentSignedURLResponse struct {
	URL       string    `json:"url"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Delete removes an attachment and its stored file.
// DELETE /api/v1/attachments/{id}
func (h *AttachmentHandler) Delete(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	id := chi.URLParam(r, "id")

	att, aerr := h.service.GetByID(r.Context(), tenantID, id)
	if aerr != nil {
		apierror.NotFound("Attachment not found").WriteJSON(w)
		return
	}
	// An authorization letter's file is evidence (RFC-065 §13): the letter
	// is revoked, its file never deleted.
	if att.ContextType() == "authorization_letter" {
		apierror.Conflict("An authorization letter's file is kept; revoke the letter instead").WriteJSON(w)
		return
	}

	// Campaign membership check before deletion
	if h.accessChecker != nil {
		if err := h.authorizeAttachmentWrite(r, att); err != nil {
			writeAttachmentAccessError(w, err)
			return
		}
	}

	if err := h.service.Delete(r.Context(), tenantID, id); err != nil {
		switch {
		case errors.Is(err, attachment.ErrNotFound):
			apierror.NotFound("Attachment not found").WriteJSON(w)
		case errors.Is(err, attachment.ErrStorageUnavailable):
			apierror.ServiceUnavailable("The organization's file storage cannot be reached").WriteJSON(w)
		default:
			h.logger.Error("attachment delete failed", "error", err, "id", att.ID().String())
			apierror.InternalServerError("Delete failed").WriteJSON(w)
		}
		return
	}

	logRequestChange(h.audit, h.logger, r,
		auditapp.NewSuccessEvent(auditdom.ActionAttachmentDeleted, auditdom.ResourceTypeAttachment, att.ID().String()).
			WithResourceName(att.Filename()).
			WithMessage("Evidence file deleted").
			WithMetadata("sha256", att.ContentHash()).
			WithMetadata("context_type", att.ContextType()).
			WithMetadata("context_id", att.ContextID()))

	w.WriteHeader(http.StatusNoContent)
}

func isImageMIME(ct string) bool {
	// SVG excluded: can contain <script> tags → stored XSS if served inline
	return ct == "image/png" || ct == "image/jpeg" || ct == "image/gif" || ct == "image/webp"
}

// List returns attachments for a given context (finding, retest, campaign).
// GET /api/v1/attachments?context_type=finding&context_id={uuid}
func (h *AttachmentHandler) List(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	contextType := r.URL.Query().Get("context_type")
	contextID := r.URL.Query().Get("context_id")

	if contextType == "" || contextID == "" {
		apierror.BadRequest("context_type and context_id are required").WriteJSON(w)
		return
	}

	if !validAttachmentContext(contextType) {
		apierror.BadRequest("context_type must be finding, retest or campaign").WriteJSON(w)
		return
	}

	// Campaign membership check for finding-context attachments
	if err := h.verifyContextAccess(r, contextType, contextID); err != nil {
		apierror.NotFound("Attachment not found").WriteJSON(w)
		return
	}

	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		apierror.BadRequest("invalid tenant_id").WriteJSON(w)
		return
	}

	atts, err := h.service.ListByContext(r.Context(), tid, contextType, contextID)
	if err != nil {
		h.logger.Error("list attachments failed", "error", err)
		apierror.InternalServerError("Failed to list attachments").WriteJSON(w)
		return
	}

	items := make([]map[string]any, len(atts))
	for i, att := range atts {
		items[i] = attachmentJSON(att)
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": items, "total": len(items)})
}

// LinkToContext links orphan attachments to a finding after creation.
// POST /api/v1/attachments/link
func (h *AttachmentHandler) LinkToContext(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	userID := middleware.GetUserID(r.Context())

	var req struct {
		AttachmentIDs []string `json:"attachment_ids"`
		ContextType   string   `json:"context_type"`
		ContextID     string   `json:"context_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	if len(req.AttachmentIDs) == 0 || req.ContextType == "" || req.ContextID == "" {
		apierror.BadRequest("attachment_ids, context_type, and context_id are required").WriteJSON(w)
		return
	}

	// Verify the caller may write to the destination context before linking,
	// otherwise a user could attach their own evidence onto a finding/campaign
	// they have no access to.
	if !validAttachmentContext(req.ContextType) {
		apierror.BadRequest("context_type must be finding, retest or campaign").WriteJSON(w)
		return
	}
	if err := h.verifyContextWrite(r, req.ContextType, req.ContextID); err != nil {
		writeAttachmentAccessError(w, err)
		return
	}

	count, err := h.service.LinkToContext(r.Context(), tenantID, userID, req.AttachmentIDs, req.ContextType, req.ContextID)
	if err != nil {
		h.logger.Error("link attachments failed", "error", err)
		apierror.InternalServerError("Failed to link attachments").WriteJSON(w)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"linked": count})
}

// GetStorageConfig returns the tenant's storage configuration.
// GET /api/v1/settings/storage
func (h *AttachmentHandler) GetStorageConfig(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	if h.storageResolver == nil {
		writeJSON(w, http.StatusOK, map[string]any{"provider": "local", "configured": false})
		return
	}
	cfg, err := h.storageResolver.GetTenantStorageConfig(r.Context(), tenantID)
	if err != nil {
		h.logger.Error("failed to get storage config", "error", err)
		apierror.InternalServerError("Failed to get storage config").WriteJSON(w)
		return
	}
	if cfg == nil {
		writeJSON(w, http.StatusOK, map[string]any{"provider": "local", "configured": false})
		return
	}
	// Don't expose secret key in response
	writeJSON(w, http.StatusOK, map[string]any{
		"provider":   cfg.Provider,
		"bucket":     cfg.Bucket,
		"region":     cfg.Region,
		"endpoint":   cfg.Endpoint,
		"base_path":  cfg.BasePath,
		"configured": true,
	})
}

// UpdateStorageConfig saves the tenant's storage configuration.
// PATCH /api/v1/settings/storage
func (h *AttachmentHandler) UpdateStorageConfig(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	if h.storageResolver == nil {
		apierror.InternalServerError("Storage resolver not configured").WriteJSON(w)
		return
	}

	var req struct {
		Provider  string `json:"provider"`
		Bucket    string `json:"bucket"`
		Region    string `json:"region"`
		Endpoint  string `json:"endpoint"`
		BasePath  string `json:"base_path"`
		AccessKey string `json:"access_key"`
		SecretKey string `json:"secret_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	existing, err := h.storageResolver.GetTenantStorageConfig(r.Context(), tenantID)
	if err != nil {
		// The stored keys cannot be decrypted (key rotation, corruption): the
		// admin must re-enter them, so the stored config is not reused.
		h.logger.Warn("stored storage config unreadable; new keys required")
		existing = nil
	}

	cfg, err := tenantStorageConfigFromRequest(attachment.StorageConfig{
		Provider:  req.Provider,
		Bucket:    req.Bucket,
		Region:    req.Region,
		Endpoint:  req.Endpoint,
		BasePath:  req.BasePath,
		AccessKey: req.AccessKey,
		SecretKey: req.SecretKey,
	}, existing)
	if err != nil {
		apierror.BadRequest(err.Error()).WriteJSON(w)
		return
	}

	if err := h.storageResolver.SaveTenantStorageConfig(r.Context(), tenantID, cfg); err != nil {
		h.logger.Error("failed to save storage config", "error", err)
		apierror.InternalServerError("Failed to save storage config").WriteJSON(w)
		return
	}

	// The next upload uses the new setting, not a cached provider.
	if h.service != nil {
		h.service.InvalidateTenantStorage(tenantID)
	}

	// Where evidence files are written is security relevant (a changed
	// bucket or endpoint redirects future uploads): High, keys redacted.
	var before any
	if existing != nil {
		before = *existing
	}
	recordConfigAudit(r.Context(), h.audit, h.logger, configAuditContext(r),
		auditapp.NewChangeEvent(auditdom.ActionStorageConfigUpdated, auditdom.ResourceTypeStorageConfig, tenantID, before, cfg).
			WithSeverity(auditdom.SeverityHigh).
			WithMessage("Evidence storage configuration updated"))

	writeJSON(w, http.StatusOK, map[string]any{"status": "saved", "provider": cfg.Provider})
}

// tenantStorageConfigFromRequest turns a tenant admin's storage settings into
// the config to persist. The tenant chooses the operator's storage ("local")
// or its own S3/MinIO bucket; it can never choose a location on the API
// server (base_path), and a custom endpoint must pass the SSRF guard. Blank
// keys on an edit of the same cloud provider keep the stored keys, since the
// settings page never echoes them back.
func tenantStorageConfigFromRequest(req attachment.StorageConfig, existing *attachment.StorageConfig) (attachment.StorageConfig, error) {
	if req.Provider == attachment.ProviderLocal {
		if req.BasePath != "" {
			return attachment.StorageConfig{}, req.ValidateTenantChoice()
		}
		return attachment.StorageConfig{Provider: attachment.ProviderLocal}, nil
	}
	if existing != nil && existing.Provider == req.Provider && req.AccessKey == "" && req.SecretKey == "" {
		req.AccessKey, req.SecretKey = existing.AccessKey, existing.SecretKey
	}
	if err := req.ValidateTenantChoice(); err != nil {
		return attachment.StorageConfig{}, err
	}
	if req.Endpoint != "" {
		if _, err := httpsec.ValidateURL(req.Endpoint); err != nil {
			return attachment.StorageConfig{}, fmt.Errorf("endpoint is not allowed: it does not resolve, or resolves to an address this server may not contact")
		}
	}
	return req, nil
}
