package handler

// Platform console: program feed sources (RFC-065 §16.6). Any administrator
// reads the state; enabling or disabling the operator's local bundle (owner
// option A) needs super_admin (route), a reason and a fresh console
// authenticator code, and writes a high-severity admin audit row. The bundle
// directory comes only from the server configuration
// (PROGRAMFEED_LOCAL_BUNDLE_DIR); no request can name a path or URL.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	bp "github.com/openctemio/openctem/api/pkg/domain/bountyprogram"
	"github.com/openctemio/openctem/api/pkg/logger"
)

const (
	stepUpPurposeProgramFeed = "program feed source change"
	maxProgramFeedReason     = 500
)

// ProgramFeedState reads the applied state of a stream.
type ProgramFeedState interface {
	FeedState(ctx context.Context, stream string) (bp.FeedState, error)
	bp.FeedSourceSettings
}

// AdminProgramFeedHandler serves /api/v1/admin/program-feed.
type AdminProgramFeedHandler struct {
	repo             ProgramFeedState
	stepUp           StepUpVerifier
	adminAudit       admin.AuditLogRepository
	signedConfigured bool
	localConfigured  bool
	logger           *logger.Logger
}

// NewAdminProgramFeedHandler creates the handler. signedConfigured and
// localConfigured say whether the server configuration names the signed
// feed (directory and root) and the local bundle directory.
func NewAdminProgramFeedHandler(repo ProgramFeedState, stepUp StepUpVerifier, adminAudit admin.AuditLogRepository,
	signedConfigured, localConfigured bool, log *logger.Logger) *AdminProgramFeedHandler {
	return &AdminProgramFeedHandler{repo: repo, stepUp: stepUp, adminAudit: adminAudit,
		signedConfigured: signedConfigured, localConfigured: localConfigured, logger: log.With("handler", "admin_program_feed")}
}

// ProgramFeedStreamResponse is one stream's state.
type ProgramFeedStreamResponse struct {
	Configured      bool       `json:"configured"`
	AppliedSequence uint64     `json:"applied_sequence"`
	AppliedAt       *time.Time `json:"applied_at,omitempty"`
}

// ProgramFeedStatusResponse is the program feed state.
type ProgramFeedStatusResponse struct {
	Signed ProgramFeedStreamResponse `json:"signed"`
	Local  ProgramFeedStreamResponse `json:"local"`
	// LocalEnabled is the administrator's switch for the local bundle.
	LocalEnabled   bool       `json:"local_enabled"`
	LocalReason    string     `json:"local_reason,omitempty"`
	LocalChangedBy string     `json:"local_changed_by,omitempty"`
	LocalChangedAt *time.Time `json:"local_changed_at,omitempty"`
	// Notice is shown with the local source: its records come from the
	// platforms that host the programs and stay subject to their terms.
	Notice string `json:"notice"`
}

// LocalBundleSourceRequest switches the local bundle source.
type LocalBundleSourceRequest struct {
	Enabled bool   `json:"enabled"`
	Reason  string `json:"reason"`
	Code    string `json:"code"`
}

const localBundleNotice = "Records of the local bundle come from the platforms that host the programs and stay subject to their terms; " +
	"they are kept on this platform only, their targets are suggestions until a follower confirms them, and nothing is scanned actively before the program terms are accepted."

// Status handles GET /api/v1/admin/program-feed
// @Summary      Program feed sources
// @Description  The state of the signed program feed and of the operator's local bundle (RFC-065 §16.6): configured, applied sequence, the local bundle switch and who set it.
// @Tags         Admin
// @Produce      json
// @Success      200  {object}  ProgramFeedStatusResponse
// @Security     AdminAuth
// @Router       /admin/program-feed [get]
func (h *AdminProgramFeedHandler) Status(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	signed, err := h.repo.FeedState(ctx, bp.StreamSigned)
	if err != nil {
		h.fail(w, err)
		return
	}
	local, err := h.repo.FeedState(ctx, bp.StreamLocal)
	if err != nil {
		h.fail(w, err)
		return
	}
	set, err := h.repo.LocalBundle(ctx)
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, ProgramFeedStatusResponse{
		Signed:       ProgramFeedStreamResponse{Configured: h.signedConfigured, AppliedSequence: signed.AppliedSequence, AppliedAt: signed.AppliedAt},
		Local:        ProgramFeedStreamResponse{Configured: h.localConfigured, AppliedSequence: local.AppliedSequence, AppliedAt: local.AppliedAt},
		LocalEnabled: set.Enabled, LocalReason: set.Reason, LocalChangedBy: set.ChangedBy, LocalChangedAt: set.ChangedAt,
		Notice: localBundleNotice,
	})
}

// SetLocalBundle handles PUT /api/v1/admin/program-feed/local-bundle
// @Summary      Switch the local program bundle source
// @Description  Enable or disable importing the operator's local bundle (PROGRAMFEED_LOCAL_BUNDLE_DIR, owner option A). Needs super_admin, a reason and a fresh console authenticator code; audited (high).
// @Tags         Admin
// @Accept       json
// @Produce      json
// @Param        body  body      LocalBundleSourceRequest  true  "Switch"
// @Success      200   {object}  ProgramFeedStatusResponse
// @Failure      400   {object}  apierror.Error
// @Failure      401   {object}  apierror.Error
// @Security     AdminAuth
// @Router       /admin/program-feed/local-bundle [put]
func (h *AdminProgramFeedHandler) SetLocalBundle(w http.ResponseWriter, r *http.Request) {
	var req LocalBundleSourceRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	reason := strings.TrimSpace(req.Reason)
	if reason == "" || len(reason) > maxProgramFeedReason {
		apierror.BadRequest(fmt.Sprintf("a reason of 1 to %d characters is required", maxProgramFeedReason)).WriteJSON(w)
		return
	}
	if req.Enabled && !h.localConfigured {
		apierror.BadRequest("PROGRAMFEED_LOCAL_BUNDLE_DIR is not set on the server").WriteJSON(w)
		return
	}
	if !confirmAdminStepUp(w, r, h.stepUp, req.Code, stepUpPurposeProgramFeed, h.logger) {
		return
	}
	actor := middleware.GetAdminUser(r.Context())
	err := h.repo.SetLocalBundle(r.Context(), bp.LocalBundleSetting{Enabled: req.Enabled, Reason: reason, ChangedBy: actor.Email()})
	status := http.StatusOK
	failure := ""
	if err != nil {
		status, failure = http.StatusInternalServerError, "store failed"
	}
	h.audit(r, actor, status, req.Enabled, reason, failure)
	if err != nil {
		h.fail(w, err)
		return
	}
	h.Status(w, r)
}

func (h *AdminProgramFeedHandler) audit(r *http.Request, actor *admin.AdminUser, status int, enabled bool, reason, failure string) {
	if h.adminAudit == nil || actor == nil {
		return
	}
	entry := admin.NewAuditLogBuilder(actor, "program_feed.local_bundle_set").
		Resource("program_feed_source", nil, "local_bundle").
		Context(middleware.ClientIP(r), r.UserAgent()).
		Request(r.Method, r.URL.Path, map[string]any{"enabled": enabled, "reason": reason}).
		Response(status).
		High()
	if failure != "" {
		entry.Error(failure)
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
	defer cancel()
	if err := h.adminAudit.Create(ctx, entry.Build()); err != nil {
		h.logger.Error("write admin audit for a program feed source change", "error", err)
	}
}

func (h *AdminProgramFeedHandler) fail(w http.ResponseWriter, err error) {
	h.logger.Error("program feed admin request failed", "error", logger.SanitizeError(err))
	apierror.InternalServerError("Program feed request failed").WriteJSON(w)
}
