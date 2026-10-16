package handler

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	catalogapp "github.com/openctemio/openctem/api/internal/app/contentcatalog"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/contentpkg"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// AdminContentCatalogHandler serves /api/v1/admin/content-catalog: the
// trust status of the instance catalog and the offline import of signed
// bundles (RFC-099). An import changes what every organization can
// install, so it needs a super admin, a reason and a fresh console
// authenticator code, and writes a high admin audit row.
type AdminContentCatalogHandler struct {
	service    *catalogapp.Service
	stepUp     StepUpVerifier
	adminAudit admin.AuditLogRepository
	logger     *logger.Logger
}

// Admin audit action of a bundle import.
const (
	AdminActionContentCatalogImport = "content_catalog.import"
	stepUpPurposeContentCatalog     = "content catalog import"
	// maxContentBundleUpload bounds the multipart body (the bundle limit
	// plus the form fields).
	maxContentBundleUpload = contentpkg.MaxBundleBytes + 1<<20

	formReason   = "reason"
	formTOTPCode = "totp_code"
)

// NewAdminContentCatalogHandler creates the handler. stepUp nil refuses
// every import.
func NewAdminContentCatalogHandler(svc *catalogapp.Service, stepUp StepUpVerifier, adminAudit admin.AuditLogRepository, log *logger.Logger) *AdminContentCatalogHandler {
	return &AdminContentCatalogHandler{service: svc, stepUp: stepUp, adminAudit: adminAudit, logger: log.With("handler", "admin_content_catalog")}
}

// ContentImportResponse is what an import did.
type ContentImportResponse struct {
	KeySetVersion    uint64                 `json:"keyset_version"`
	IndexSequence    uint64                 `json:"index_sequence"`
	Unchanged        bool                   `json:"unchanged"`
	Added            int                    `json:"added"`
	Existing         int                    `json:"existing"`
	Refused          []ContentImportRefusal `json:"refused"`
	RevokedVersions  int                    `json:"revoked_versions"`
	RevokedInstalls  int                    `json:"revoked_installs"`
	AutoUpdated      int                    `json:"auto_updated"`
	RevocationsStale bool                   `json:"revocations_stale"`
}

// ContentImportRefusal is a package of the bundle that was left out.
type ContentImportRefusal struct {
	PackageID string `json:"package_id"`
	Version   string `json:"version"`
	Reason    string `json:"reason"`
}

// Status handles GET /api/v1/admin/content-catalog
// @Summary      Content catalog trust status
// @Tags         Admin Content Catalog
// @Produce      json
// @Success      200  {object}  ContentTrustResponse
// @Failure      401  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /admin/content-catalog [get]
func (h *AdminContentCatalogHandler) Status(w http.ResponseWriter, r *http.Request) {
	t, err := h.service.Trust(r.Context())
	if err != nil {
		h.logger.Error("content catalog trust", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}
	writeScanZoneJSON(w, http.StatusOK, toContentTrust(t))
}

// Import handles POST /api/v1/admin/content-catalog/import
// @Summary      Import a signed content bundle
// @Description  Multipart: bundle (tar or tar.gz, up to 128 MiB), reason, totp_code. Verifies the catalog key set, the signed index (sequence, expiry), the revocation list and every package (catalog statement, publisher signature, digests) before anything is stored. Super admin; audited.
// @Tags         Admin Content Catalog
// @Accept       multipart/form-data
// @Produce      json
// @Param        bundle     formData  file    true  "Bundle"
// @Param        reason     formData  string  true  "Reason"
// @Param        totp_code  formData  string  true  "Console authenticator code"
// @Success      200  {object}  ContentImportResponse
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Failure      422  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /admin/content-catalog/import [post]
func (h *AdminContentCatalogHandler) Import(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxContentBundleUpload)
	mr, err := r.MultipartReader()
	if err != nil {
		apierror.BadRequest("a multipart body is required").WriteJSON(w)
		return
	}
	// Fields come first; the bundle part is streamed into the verifier.
	var reason, code string
	for {
		part, err := mr.NextPart()
		if err != nil {
			apierror.BadRequest("a bundle part is required").WriteJSON(w)
			return
		}
		switch part.FormName() {
		case formReason, formTOTPCode:
			b, err := io.ReadAll(io.LimitReader(part, 1024))
			if err != nil {
				apierror.BadRequest("Invalid request body").WriteJSON(w)
				return
			}
			if part.FormName() == formReason {
				reason = strings.TrimSpace(string(b))
			} else {
				code = strings.TrimSpace(string(b))
			}
			continue
		case "bundle":
		default:
			apierror.BadRequest("unexpected form field").WriteJSON(w)
			return
		}
		h.importBundle(w, r, part, reason, code)
		return
	}
}

func (h *AdminContentCatalogHandler) importBundle(w http.ResponseWriter, r *http.Request, bundle io.Reader, reason, code string) {
	reason, ok := contentPackReason(w, reason)
	if !ok {
		return
	}
	if !confirmAdminStepUp(w, r, h.stepUp, code, stepUpPurposeContentCatalog, h.logger) {
		return
	}
	actor := middleware.GetAdminUser(r.Context())
	var actorID *shared.ID
	if actor != nil {
		id := actor.ID()
		actorID = &id
	}
	body := map[string]any{formReason: reason}
	res, err := h.service.Import(r.Context(), bundle, actorID)
	status := http.StatusOK
	if err != nil {
		switch {
		case errors.Is(err, catalogapp.ErrRollback):
			status = http.StatusConflict
			apierror.Conflict(contentMessage(err)).WriteJSON(w)
		case errors.Is(err, catalogapp.ErrVerification), errors.Is(err, shared.ErrConflict):
			status = http.StatusUnprocessableEntity
			apierror.New(status, apierror.Code("CONTENT_BUNDLE_REFUSED"), contentMessage(err)).WriteJSON(w)
		default:
			status = http.StatusInternalServerError
			h.logger.Error("content bundle import", "error", err)
			apierror.InternalError(err).WriteJSON(w)
		}
		h.audit(r, actor, status, body, sanitizeLogField(err.Error()))
		return
	}
	out := ContentImportResponse{KeySetVersion: res.KeySetVersion, IndexSequence: res.IndexSequence, Unchanged: res.Unchanged,
		Added: res.Added, Existing: res.Existing, RevokedVersions: res.RevokedVersions, RevokedInstalls: res.RevokedInstalls,
		AutoUpdated: res.AutoUpdated, RevocationsStale: res.RevocationsStale, Refused: []ContentImportRefusal{}}
	for _, x := range res.Refused {
		out.Refused = append(out.Refused, ContentImportRefusal{PackageID: x.ID, Version: x.Version, Reason: x.Reason})
	}
	body["index_sequence"], body["added"], body["refused"] = res.IndexSequence, res.Added, len(res.Refused)
	body["revoked_versions"], body["revoked_installs"] = res.RevokedVersions, res.RevokedInstalls
	h.audit(r, actor, status, body, "")
	writeScanZoneJSON(w, status, out)
}

func (h *AdminContentCatalogHandler) audit(r *http.Request, actor *admin.AdminUser, status int, body map[string]any, failure string) {
	if h.adminAudit == nil {
		return
	}
	entry := admin.NewAuditLogBuilder(actor, AdminActionContentCatalogImport).
		Resource("content_catalog", nil, "instance").
		Context(middleware.ClientIP(r), r.UserAgent()).
		Request(r.Method, r.URL.Path, body).
		Response(status).
		High()
	if failure != "" {
		entry.Error(failure)
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
	defer cancel()
	if err := h.adminAudit.Create(ctx, entry.Build()); err != nil {
		h.logger.Error("write admin audit for a content import", "error", err)
	}
}
