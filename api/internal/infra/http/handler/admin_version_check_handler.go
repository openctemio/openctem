package handler

// Platform console: the version check
// (docs/rfcs/RFC-105-version-check-and-usage-telemetry.md). Any administrator
// reads the status; an offline import of the signed release feed file needs
// super_admin and the route-level step-up, and writes a high-severity admin
// audit row. The file is verified exactly like a fetched feed; no request
// names a path or URL.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/internal/app/versioncheck"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/httpsec"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/releasefeed"
)

// VersionCheckService is what the handler needs from the version check.
type VersionCheckService interface {
	View(ctx context.Context) (versioncheck.View, error)
	Import(ctx context.Context, raw []byte) (*releasefeed.Verified, error)
	UpdateEnabled(ctx context.Context, enabled bool, by shared.ID) error
}

// VersionCheckSwitchRequest turns the daily online check on or off.
type VersionCheckSwitchRequest struct {
	Enabled *bool `json:"enabled"`
}

// CodeVersionCheckLockedByEnvironment: VERSION_CHECK_ENABLED=false keeps the
// online check off; the console cannot turn it on.
const CodeVersionCheckLockedByEnvironment apierror.Code = "VERSION_CHECK_LOCKED_BY_ENVIRONMENT"

// SetEnabled handles PUT /api/v1/admin/version-check/enabled
// @Summary      Turn the daily version check on or off
// @Description  Switches the daily anonymous release-feed check without a restart. VERSION_CHECK_ENABLED=false is a ceiling: turning it on is then refused (409). super_admin and a step-up; audited high.
// @Tags         Admin
// @Accept       json
// @Produce      json
// @Param        body  body  VersionCheckSwitchRequest  true  "Switch"
// @Success      200  {object}  versioncheck.View
// @Failure      400  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Security     AdminAuth
// @Router       /admin/version-check/enabled [put]
func (h *AdminVersionCheckHandler) SetEnabled(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetAdminUser(r.Context())
	if actor == nil {
		apierror.Unauthorized("admin authentication required").WriteJSON(w)
		return
	}
	var req VersionCheckSwitchRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10)).Decode(&req); err != nil || req.Enabled == nil {
		apierror.BadRequest("Send {\"enabled\": true|false}").WriteJSON(w)
		return
	}
	err := h.svc.UpdateEnabled(r.Context(), *req.Enabled, actor.ID())
	switch {
	case errors.Is(err, versioncheck.ErrLockedByEnvironment):
		h.auditSwitch(r, actor, *req.Enabled, http.StatusConflict, "locked by VERSION_CHECK_ENABLED")
		apierror.New(http.StatusConflict, CodeVersionCheckLockedByEnvironment,
			"The server configuration (VERSION_CHECK_ENABLED=false) keeps the version check off").WriteJSON(w)
		return
	case err != nil:
		h.logger.Error("version check switch failed", "error", logger.SanitizeError(err))
		apierror.InternalServerError("The version check could not be switched").WriteJSON(w)
		return
	}
	h.auditSwitch(r, actor, *req.Enabled, http.StatusOK, "")
	h.Status(w, r)
}

func (h *AdminVersionCheckHandler) auditSwitch(r *http.Request, actor *admin.AdminUser, enabled bool, status int, failure string) {
	if h.adminAudit == nil {
		return
	}
	entry := admin.NewAuditLogBuilder(actor, "version_check.switched").
		Resource("version_check", nil, "online_check").
		Context(middleware.ClientIP(r), r.UserAgent()).
		Request(r.Method, r.URL.Path, map[string]any{"enabled": enabled}).
		Response(status).
		High()
	if failure != "" {
		entry.Error(failure)
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
	defer cancel()
	if err := h.adminAudit.Create(ctx, entry.Build()); err != nil {
		h.logger.Error("write admin audit for the version check switch", "error", err)
	}
}

// AdminVersionCheckHandler serves /api/v1/admin/version-check.
type AdminVersionCheckHandler struct {
	svc        VersionCheckService
	adminAudit admin.AuditLogRepository
	logger     *logger.Logger
}

// NewAdminVersionCheckHandler creates the handler.
func NewAdminVersionCheckHandler(svc VersionCheckService, adminAudit admin.AuditLogRepository, log *logger.Logger) *AdminVersionCheckHandler {
	return &AdminVersionCheckHandler{svc: svc, adminAudit: adminAudit, logger: log.With("handler", "admin_version_check")}
}

// Status handles GET /api/v1/admin/version-check
// @Summary      Version check status
// @Description  What the signed release feed says about the running version: newer releases, the security advisories that affect it, where the feed came from and when, and the last check's outcome (RFC-105).
// @Tags         Admin
// @Produce      json
// @Success      200  {object}  versioncheck.View
// @Security     AdminAuth
// @Router       /admin/version-check [get]
func (h *AdminVersionCheckHandler) Status(w http.ResponseWriter, r *http.Request) {
	v, err := h.svc.View(r.Context())
	if err != nil {
		h.logger.Error("version check status failed", "error", logger.SanitizeError(err))
		apierror.InternalServerError("Version check status failed").WriteJSON(w)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// Import handles POST /api/v1/admin/version-check/import
// @Summary      Import the release feed file
// @Description  Applies an administrator's copy of the signed release feed (openctem-releases.json) for an instance without internet access. Verified like a fetched feed: pinned root, no rollback, not expired. Needs super_admin and the console step-up; audited (high).
// @Tags         Admin
// @Accept       json
// @Produce      json
// @Success      200  {object}  versioncheck.View
// @Failure      400  {object}  apierror.Error
// @Failure      413  {object}  apierror.Error
// @Security     AdminAuth
// @Router       /admin/version-check/import [post]
func (h *AdminVersionCheckHandler) Import(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetAdminUser(r.Context())
	raw, err := httpsec.ReadLimited(http.MaxBytesReader(w, r.Body, releasefeed.MaxBundleBytes+1), releasefeed.MaxBundleBytes)
	if err != nil {
		h.audit(r, actor, http.StatusRequestEntityTooLarge, nil, versioncheck.ErrCodeTooLarge)
		apierror.New(http.StatusRequestEntityTooLarge, apierror.Code("RELEASE_FEED_TOO_LARGE"), "The file is larger than the release feed limit").WriteJSON(w)
		return
	}
	v, err := h.svc.Import(r.Context(), raw)
	var ie *versioncheck.ImportError
	switch {
	case errors.As(err, &ie):
		h.audit(r, actor, http.StatusBadRequest, nil, ie.Code)
		// No log line: the admin audit row above records the refusal and its
		// code, and nothing derived from the uploaded file reaches the log.
		apierror.New(http.StatusBadRequest, apierror.Code("RELEASE_FEED_"+strings.ToUpper(ie.Code)), importMessage(ie.Code)).WriteJSON(w)
		return
	case err != nil:
		h.audit(r, actor, http.StatusInternalServerError, nil, "store failed")
		h.logger.Error("release feed import failed", "error", logger.SanitizeError(err))
		apierror.InternalServerError("Release feed import failed").WriteJSON(w)
		return
	}
	h.audit(r, actor, http.StatusOK, v, "")
	h.Status(w, r)
}

func importMessage(code string) string {
	switch code {
	case versioncheck.ErrCodeNoKey:
		return "This build pins no release feed key, so no feed can be verified"
	case versioncheck.ErrCodeRollback:
		return "The file is older than the release information already applied"
	case versioncheck.ErrCodeExpired:
		return "The file has expired; download a current copy"
	case versioncheck.ErrCodeTooLarge:
		return "The file is larger than the release feed limit"
	}
	return "The file is not a valid signed release feed"
}

func (h *AdminVersionCheckHandler) audit(r *http.Request, actor *admin.AdminUser, status int, v *releasefeed.Verified, failure string) {
	if h.adminAudit == nil || actor == nil {
		return
	}
	details := map[string]any{}
	if v != nil {
		details["sequence"] = v.Feed.Sequence
		details["key_id"] = v.KeyID
	}
	entry := admin.NewAuditLogBuilder(actor, "version_check.feed_imported").
		Resource("version_check", nil, "release_feed").
		Context(middleware.ClientIP(r), r.UserAgent()).
		Request(r.Method, r.URL.Path, details).
		Response(status).
		High()
	if failure != "" {
		entry.Error(failure)
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
	defer cancel()
	if err := h.adminAudit.Create(ctx, entry.Build()); err != nil {
		h.logger.Error("write admin audit for a release feed import", "error", err)
	}
}
