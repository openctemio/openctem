package handler

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/domain/attachment"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// FindingCampaignAccessChecker verifies that a user has access to a finding's campaign.
// Returns nil if access is allowed, ErrNotFound/ErrForbidden otherwise.
type FindingCampaignAccessChecker interface {
	CheckFindingAccess(ctx context.Context, tenantID, findingID, userID string, isAdmin bool) error
}

// AttachmentHandler handles file upload/download/delete HTTP endpoints.
type AttachmentHandler struct {
	service         *app.AttachmentService
	accessChecker   FindingCampaignAccessChecker     // optional; when nil, no campaign check
	storageResolver *app.SettingsStorageResolver      // optional; for storage config CRUD
	logger          *logger.Logger
}

// NewAttachmentHandler creates a new handler.
func NewAttachmentHandler(svc *app.AttachmentService, log *logger.Logger) *AttachmentHandler {
	return &AttachmentHandler{service: svc, logger: log}
}

// SetStorageResolver wires the tenant storage config resolver for GET/PATCH storage settings.
func (h *AttachmentHandler) SetStorageResolver(resolver *app.SettingsStorageResolver) {
	h.storageResolver = resolver
}

// SetAccessChecker wires the campaign-membership checker for finding-scoped attachments.
func (h *AttachmentHandler) SetAccessChecker(checker FindingCampaignAccessChecker) {
	h.accessChecker = checker
}

// verifyContextAccess checks campaign membership for finding/retest-context attachments.
// For other context types or when no checker is configured, it's a no-op.
// Both "finding" and "retest" contexts use finding ID as context_id.
func (h *AttachmentHandler) verifyContextAccess(r *http.Request, contextType, contextID string) error {
	if h.accessChecker == nil || contextID == "" {
		return nil
	}
	// Both finding and retest contexts store finding_id as context_id
	if contextType != "finding" && contextType != "retest" {
		return nil
	}
	tenantID := middleware.MustGetTenantID(r.Context())
	userID := middleware.GetUserID(r.Context())
	isAdmin := middleware.IsAdmin(r.Context())
	return h.accessChecker.CheckFindingAccess(r.Context(), tenantID, contextID, userID, isAdmin)
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

	if err := r.ParseMultipartForm(attachment.MaxFileSize); err != nil {
		apierror.BadRequest("File too large or invalid multipart form").WriteJSON(w)
		return
	}

	// Campaign membership check on upload
	ctxType := r.FormValue("context_type")
	ctxID := r.FormValue("context_id")
	if err := h.verifyContextAccess(r, ctxType, ctxID); err != nil {
		apierror.NotFound("Access denied").WriteJSON(w)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		apierror.BadRequest("Missing 'file' field in multipart form").WriteJSON(w)
		return
	}
	defer file.Close()

	// Sniff content type from actual bytes first, then fallback to file extension
	// for types that Go's sniffing table doesn't cover (markdown, har+json, mp4 variants).
	buf := make([]byte, 512)
	n, _ := file.Read(buf)
	contentType := http.DetectContentType(buf[:n])
	// Reset reader — Seek back to start
	if seeker, ok := file.(io.Seeker); ok {
		_, _ = seeker.Seek(0, io.SeekStart)
	}
	// DetectContentType only returns ~14 MIME types. For generic results,
	// use file extension as a more specific hint (e.g., .md → text/markdown).
	if contentType == "application/octet-stream" || contentType == "text/plain" {
		ext := strings.ToLower(filepath.Ext(header.Filename))
		extMIME := map[string]string{
			".md": "text/markdown", ".markdown": "text/markdown",
			".csv": "text/csv", ".har": "application/har+json",
			".mp4": "video/mp4", ".webm": "video/webm",
		}
		if better, ok := extMIME[ext]; ok {
			contentType = better
		}
	}

	att, err := h.service.Upload(r.Context(), app.UploadInput{
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
		default:
			h.logger.Error("attachment upload failed", "error", err)
			apierror.InternalServerError("Upload failed").WriteJSON(w)
		}
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"id":           att.ID().String(),
		"filename":     att.Filename(),
		"content_type": att.ContentType(),
		"size":         att.Size(),
		"url":          att.URL(),
		"markdown":     att.MarkdownLink(),
		"created_at":   att.CreatedAt(),
	})
}

// Download serves the file content for an attachment.
// GET /api/v1/attachments/{id}
func (h *AttachmentHandler) Download(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	id := chi.URLParam(r, "id")

	// Campaign membership check: resolve attachment metadata to verify context access
	if h.accessChecker != nil {
		att, aerr := h.service.GetByID(r.Context(), tenantID, id)
		if aerr != nil {
			apierror.NotFound("Attachment not found").WriteJSON(w)
			return
		}
		if err := h.verifyContextAccess(r, att.ContextType(), att.ContextID()); err != nil {
			apierror.NotFound("Attachment not found").WriteJSON(w)
			return
		}
	}

	reader, contentType, filename, err := h.service.Download(r.Context(), tenantID, id)
	if err != nil {
		if errors.Is(err, attachment.ErrNotFound) {
			apierror.NotFound("Attachment not found").WriteJSON(w)
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
	if isImageMIME(contentType) {
		disposition = "inline"
	}
	w.Header().Set("Content-Disposition", mime.FormatMediaType(disposition, map[string]string{"filename": filename}))
	// Cache for 1 hour (attachments are immutable once uploaded)
	w.Header().Set("Cache-Control", "private, max-age=3600")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	if _, err := io.Copy(w, reader); err != nil {
		h.logger.Warn("attachment stream interrupted", "error", err, "id", id)
	}
}

// Delete removes an attachment and its stored file.
// DELETE /api/v1/attachments/{id}
func (h *AttachmentHandler) Delete(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	id := chi.URLParam(r, "id")

	// Campaign membership check before deletion
	if h.accessChecker != nil {
		att, aerr := h.service.GetByID(r.Context(), tenantID, id)
		if aerr != nil {
			apierror.NotFound("Attachment not found").WriteJSON(w)
			return
		}
		if err := h.verifyContextAccess(r, att.ContextType(), att.ContextID()); err != nil {
			apierror.NotFound("Attachment not found").WriteJSON(w)
			return
		}
	}

	if err := h.service.Delete(r.Context(), tenantID, id); err != nil {
		if errors.Is(err, attachment.ErrNotFound) {
			apierror.NotFound("Attachment not found").WriteJSON(w)
			return
		}
		h.logger.Error("attachment delete failed", "error", err, "id", id)
		apierror.InternalServerError("Delete failed").WriteJSON(w)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// GetMeta returns attachment metadata (without file content).
// GET /api/v1/attachments/{id}/meta
func (h *AttachmentHandler) GetMeta(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	id := chi.URLParam(r, "id")

	// Campaign membership check (same as Download/Delete)
	if h.accessChecker != nil {
		att, aerr := h.service.GetByID(r.Context(), tenantID, id)
		if aerr != nil {
			apierror.NotFound("Attachment not found").WriteJSON(w)
			return
		}
		if err := h.verifyContextAccess(r, att.ContextType(), att.ContextID()); err != nil {
			apierror.NotFound("Attachment not found").WriteJSON(w)
			return
		}
	}

	att, err := h.service.GetByID(r.Context(), tenantID, id)
	if err != nil {
		if errors.Is(err, attachment.ErrNotFound) {
			apierror.NotFound("Attachment not found").WriteJSON(w)
			return
		}
		h.logger.Error("attachment meta failed", "error", err, "id", id)
		apierror.InternalServerError("Failed to get attachment").WriteJSON(w)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"id":           att.ID().String(),
		"filename":     att.Filename(),
		"content_type": att.ContentType(),
		"size":         att.Size(),
		"url":          att.URL(),
		"markdown":     att.MarkdownLink(),
		"uploaded_by":  att.UploadedBy().String(),
		"context_type": att.ContextType(),
		"context_id":   att.ContextID(),
		"created_at":   att.CreatedAt(),
	})
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
		items[i] = map[string]any{
			"id":           att.ID().String(),
			"filename":     att.Filename(),
			"content_type": att.ContentType(),
			"size":         att.Size(),
			"url":          att.URL(),
			"markdown":     att.MarkdownLink(),
			"created_at":   att.CreatedAt(),
		}
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

	// Validate provider
	switch req.Provider {
	case "local", "s3", "minio":
		// OK
	default:
		apierror.BadRequest("Provider must be 'local', 's3', or 'minio'").WriteJSON(w)
		return
	}

	cfg := attachment.StorageConfig{
		Provider:  req.Provider,
		Bucket:    req.Bucket,
		Region:    req.Region,
		Endpoint:  req.Endpoint,
		BasePath:  req.BasePath,
		AccessKey: req.AccessKey,
		SecretKey: req.SecretKey,
	}

	if err := h.storageResolver.SaveTenantStorageConfig(r.Context(), tenantID, cfg); err != nil {
		h.logger.Error("failed to save storage config", "error", err)
		apierror.InternalServerError("Failed to save storage config").WriteJSON(w)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"status": "saved", "provider": req.Provider})
}

