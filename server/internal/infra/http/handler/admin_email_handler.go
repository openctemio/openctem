package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/openctemio/openctem/server/internal/app/adminapproval"
	"github.com/openctemio/openctem/server/internal/app/platformemail"
	"github.com/openctemio/openctem/server/internal/infra/http/middleware"
	"github.com/openctemio/openctem/server/pkg/apierror"
	"github.com/openctemio/openctem/server/pkg/domain/admin"
	"github.com/openctemio/openctem/server/pkg/domain/platformsetting"
	emaildom "github.com/openctemio/openctem/server/pkg/email"
	"github.com/openctemio/openctem/server/pkg/logger"
)

const stepUpPurposeEmailSettings = "platform e-mail settings change"

// AdminEmailHandler serves Console > Settings > E-mail: the platform's SMTP
// server (RFC-079). The password is write-only.
type AdminEmailHandler struct {
	svc       *platformemail.Service
	stepUp    StepUpVerifier
	approvals approvalGate
	appName   string
	logger    *logger.Logger
}

// WithApprovals wires the four-eyes gate of the platform relay.
func (h *AdminEmailHandler) WithApprovals(g approvalGate) *AdminEmailHandler {
	h.approvals = g
	return h
}

// NewAdminEmailHandler creates the handler.
func NewAdminEmailHandler(svc *platformemail.Service, stepUp StepUpVerifier, appName string, log *logger.Logger) *AdminEmailHandler {
	return &AdminEmailHandler{svc: svc, stepUp: stepUp, appName: appName, logger: log.With("handler", "admin_email")}
}

// EmailSettingsResponse is the platform e-mail settings without the password.
type EmailSettingsResponse struct {
	Enabled  bool   `json:"enabled"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	// PasswordSet says whether a password is stored; the value is never returned.
	PasswordSet bool   `json:"password_set"`
	From        string `json:"from"`
	FromName    string `json:"from_name"`
	StartTLS    bool   `json:"starttls"`
	// CASet says an internal CA bundle is stored; the bundle itself is never returned.
	CASet bool `json:"ca_set"`
	// CAFingerprint is the SHA-256 fingerprint of the stored bundle, to compare with the CA you hold.
	CAFingerprint string `json:"ca_fingerprint,omitempty"`
	// Version to send back on PUT (optimistic concurrency); 0 = nothing stored.
	Version   int    `json:"version"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

// UpdateEmailSettingsRequest changes the settings.
type UpdateEmailSettingsRequest struct {
	Enabled  bool   `json:"enabled"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	// Password: omit to keep the stored one, "" to clear it.
	Password *string `json:"password,omitempty"`
	From     string  `json:"from"`
	FromName string  `json:"from_name"`
	StartTLS bool    `json:"starttls"`
	// CAPEM: PEM certificates of the internal CA that signed the relay's
	// certificate, used only to verify that relay's TLS. Omit to keep the stored
	// bundle, "" to remove it. Certificates only: a private key is refused.
	CAPEM   *string `json:"ca_pem,omitempty"`
	Version int     `json:"version"`
	// TOTPCode is a fresh code from the administrator's authenticator.
	TOTPCode string `json:"totp_code"`
}

func toEmailSettingsResponse(s platformemail.Settings) EmailSettingsResponse {
	r := EmailSettingsResponse{Enabled: s.Enabled, Host: s.Host, Port: s.Port, Username: s.Username,
		PasswordSet: s.PasswordSet, From: s.From, FromName: s.FromName, StartTLS: s.StartTLS,
		CASet: s.CASet, CAFingerprint: s.CAFingerprint, Version: s.Version}
	if !s.UpdatedAt.IsZero() {
		r.UpdatedAt = s.UpdatedAt.UTC().Format(time.RFC3339)
	}
	return r
}

// Get returns the platform e-mail settings (any administrator).
// @Summary      Get the platform e-mail settings
// @Description  The platform's SMTP server for sign-up, invitation, verification and password e-mails. The password is never returned (password_set only).
// @Tags         Admin System
// @Produce      json
// @Success      200  {object}  EmailSettingsResponse
// @Router       /admin/settings/email [get]
func (h *AdminEmailHandler) Get(w http.ResponseWriter, r *http.Request) {
	s, err := h.svc.Get(r.Context())
	if err != nil {
		h.logger.Error("read e-mail settings", "error", err)
		apierror.InternalServerError("could not read the e-mail settings").WriteJSON(w)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(toEmailSettingsResponse(s))
}

// Update changes the settings. Super admin, with a fresh authenticator code.
// @Summary      Change the platform e-mail settings
// @Description  Super admin with a fresh authenticator code. Sends the version read (409 when it moved on). The password is encrypted at rest; omit it to keep the stored one. Audited (critical) without the password.
// @Tags         Admin System
// @Accept       json
// @Produce      json
// @Param        request  body      UpdateEmailSettingsRequest  true  "Settings"
// @Success      200  {object}  EmailSettingsResponse
// @Router       /admin/settings/email [put]
func (h *AdminEmailHandler) Update(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetAdminUser(r.Context())
	if actor == nil {
		apierror.Unauthorized("administrator session required").WriteJSON(w)
		return
	}
	var req UpdateEmailSettingsRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 96*1024))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	if !h.verifyStepUp(w, r, actor, req.TOTPCode) {
		return
	}
	in := platformemail.Input{
		Enabled: req.Enabled, Host: req.Host, Port: req.Port, Username: req.Username, Password: req.Password,
		From: req.From, FromName: req.FromName, StartTLS: req.StartTLS, CAPEM: req.CAPEM,
	}
	// SECURITY: the relay receives every set-password, reset and invitation
	// link, so a new host, port, login or weaker connection security is set by one
	// administrator and approved by another. A password rotation on the same
	// relay, the sender and turning e-mail off stay one-person.
	var grant *adminapproval.Grant
	if target, needed := h.svc.ApprovalNeeded(r.Context(), in); needed {
		g, ok := requireSecondApproval(w, r, h.approvals, actor, admin.ApprovalPlatformEmailRelay, target, h.logger)
		if !ok {
			return
		}
		grant = g
	}
	s, err := h.svc.Update(r.Context(), actor, in, req.Version, middleware.ClientIP(r), r.UserAgent())
	if err != nil {
		releaseSecondApproval(r, h.approvals, actor, grant)
		switch {
		case errors.Is(err, platformemail.ErrInvalid):
			apierror.BadRequest(err.Error()).WriteJSON(w)
		case errors.Is(err, platformsetting.ErrVersionConflict):
			apierror.Conflict("The e-mail settings were changed by someone else; reload and try again").WriteJSON(w)
		default:
			h.logger.Error("update e-mail settings", "error", err)
			apierror.InternalServerError("could not save the e-mail settings").WriteJSON(w)
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(toEmailSettingsResponse(s))
}

// SendTest sends a test e-mail to the acting administrator.
// @Summary      Send a test e-mail
// @Description  Sends a test message through the stored settings to the calling administrator's own address (never another address). Super admin.
// @Tags         Admin System
// @Success      204
// @Router       /admin/settings/email/test [post]
func (h *AdminEmailHandler) SendTest(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetAdminUser(r.Context())
	if actor == nil {
		apierror.Unauthorized("administrator session required").WriteJSON(w)
		return
	}
	if err := h.svc.SendTest(r.Context(), actor, h.appName); err != nil {
		// The SMTP error may name the server's reply; log it, answer generically.
		h.logger.Warn("test e-mail failed", "error", logger.SanitizeError(err))
		// reason is one of a fixed set (no server text), so the console can say what to fix.
		reason := emaildom.ClassifySendError(err)
		if errors.Is(err, platformemail.ErrNoAddress) {
			reason = "no_address"
		}
		apierror.New(http.StatusBadGateway, "EMAIL_TEST_FAILED",
			"The test e-mail could not be sent: check the server, port, TLS and credentials (details are in the API log)").
			WithDetails(map[string]string{"reason": reason}).WriteJSON(w)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *AdminEmailHandler) verifyStepUp(w http.ResponseWriter, r *http.Request, _ *admin.AdminUser, code string) bool {
	return confirmAdminStepUp(w, r, h.stepUp, code, stepUpPurposeEmailSettings, h.logger)
}
