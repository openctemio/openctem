package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/openctemio/openctem/api/internal/app/platformlegal"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/platformsetting"
	"github.com/openctemio/openctem/api/pkg/logger"
)

const stepUpPurposeLegalSettings = "legal settings change"

// AdminLegalHandler serves Console > System > Legal and the public read the
// web console renders the sign-in notice, the legal pages and security.txt
// from (RFC-079).
type AdminLegalHandler struct {
	svc    *platformlegal.Service
	stepUp StepUpVerifier
	logger *logger.Logger
}

// NewAdminLegalHandler creates the handler.
func NewAdminLegalHandler(svc *platformlegal.Service, stepUp StepUpVerifier, log *logger.Logger) *AdminLegalHandler {
	return &AdminLegalHandler{svc: svc, stepUp: stepUp, logger: log.With("handler", "admin_legal")}
}

// LegalSettingsResponse is the operator's legal information.
type LegalSettingsResponse struct {
	platformlegal.Settings
	Version   int    `json:"version"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

// UpdateLegalSettingsRequest changes the legal information.
type UpdateLegalSettingsRequest struct {
	platformlegal.Settings
	Version  int    `json:"version"`
	TOTPCode string `json:"totp_code"`
}

func toLegalResponse(st platformlegal.State) LegalSettingsResponse {
	r := LegalSettingsResponse{Settings: st.Settings, Version: st.Version}
	if !st.UpdatedAt.IsZero() {
		r.UpdatedAt = st.UpdatedAt.UTC().Format(time.RFC3339)
	}
	return r
}

// Public returns the legal information for the web console. Public on
// purpose: every value is shown to visitors anyway (links on the sign-in
// page, the legal pages, security.txt); nothing secret is stored here.
// @Summary      Get the operator's legal information
// @Description  Public. Links to the terms and privacy policy, the built-in legal pages' values and the security.txt contact. Empty values mean the defaults.
// @Tags         Legal
// @Produce      json
// @Success      200  {object}  platformlegal.Settings
// @Router       /legal [get]
func (h *AdminLegalHandler) Public(w http.ResponseWriter, r *http.Request) {
	st, err := h.svc.Get(r.Context())
	if err != nil {
		h.logger.Error("read legal settings", "error", err)
		apierror.InternalServerError("could not read the legal settings").WriteJSON(w)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=60")
	_ = json.NewEncoder(w).Encode(st.Settings)
}

// Get returns the legal settings with their version (any administrator).
// @Summary      Get the legal settings
// @Tags         Admin System
// @Produce      json
// @Success      200  {object}  LegalSettingsResponse
// @Router       /admin/settings/legal [get]
func (h *AdminLegalHandler) Get(w http.ResponseWriter, r *http.Request) {
	st, err := h.svc.Get(r.Context())
	if err != nil {
		h.logger.Error("read legal settings", "error", err)
		apierror.InternalServerError("could not read the legal settings").WriteJSON(w)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(toLegalResponse(st))
}

// Update changes the legal settings. Super admin, with a fresh authenticator
// code: the security contact decides where vulnerability reports go.
// @Summary      Change the legal settings
// @Description  Super admin with a fresh authenticator code. Sends the version read (409 when it moved on). Audited (critical).
// @Tags         Admin System
// @Accept       json
// @Produce      json
// @Param        request  body      UpdateLegalSettingsRequest  true  "Settings"
// @Success      200  {object}  LegalSettingsResponse
// @Router       /admin/settings/legal [put]
func (h *AdminLegalHandler) Update(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetAdminUser(r.Context())
	if actor == nil {
		apierror.Unauthorized("administrator session required").WriteJSON(w)
		return
	}
	var req UpdateLegalSettingsRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	if !confirmAdminStepUp(w, r, h.stepUp, req.TOTPCode, stepUpPurposeLegalSettings, h.logger) {
		return
	}
	st, err := h.svc.Update(r.Context(), actor, req.Settings, req.Version, middleware.ClientIP(r), r.UserAgent())
	if err != nil {
		switch {
		case errors.Is(err, platformlegal.ErrInvalid):
			apierror.BadRequest(err.Error()).WriteJSON(w)
		case errors.Is(err, platformsetting.ErrVersionConflict):
			apierror.Conflict("The legal settings were changed by someone else; reload and try again").WriteJSON(w)
		default:
			h.logger.Error("update legal settings", "error", err)
			apierror.InternalServerError("could not save the legal settings").WriteJSON(w)
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(toLegalResponse(st))
}
