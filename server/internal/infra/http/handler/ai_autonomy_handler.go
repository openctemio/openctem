package handler

// Settings > AI > Changes without a person (docs/architecture/ai-autonomy.md):
// the organization's pause switch and limits on changes AI agents make
// without a person.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	auditapp "github.com/openctemio/openctem/server/internal/app/audit"
	authapp "github.com/openctemio/openctem/server/internal/app/auth"
	"github.com/openctemio/openctem/server/internal/app/tenantai"
	"github.com/openctemio/openctem/server/internal/infra/http/middleware"
	"github.com/openctemio/openctem/server/pkg/apierror"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// AIAutonomyStore is the organization's switch and limits (*tenantai.Service).
type AIAutonomyStore interface {
	GetAutonomy(ctx context.Context, tenantID string) (tenantai.AutonomyView, error)
	SaveAutonomy(ctx context.Context, tenantID string, in tenantai.AutonomyInput, actx auditapp.AuditContext) (tenantai.AutonomyView, error)
}

// AIAutonomyResponse is the setting in force.
type AIAutonomyResponse struct {
	// Paused: AI agents make no change without a person; their suggestions
	// are comments for a person to act on.
	Paused   bool       `json:"paused"`
	PausedAt *time.Time `json:"paused_at,omitempty"`
	PausedBy string     `json:"paused_by,omitempty"`
	// PerHour and PerDay limit changes without a person in the current
	// clock hour and the last 24 hours; null is unlimited.
	PerHour   *int       `json:"per_hour"`
	PerDay    *int       `json:"per_day"`
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
	UpdatedBy string     `json:"updated_by,omitempty"`
	// Loosened (answer of a change) lists why the change was a loosening
	// (resumed, limit_raised, limit_removed): it needed a recent sign-in,
	// was audited critical and the owners and administrators were told.
	Loosened []string `json:"loosened,omitempty"`
}

// limitField is a limit that must be present in the request: a number, or
// null for unlimited.
type limitField struct {
	set bool
	v   *int
}

// UnmarshalJSON records that the field was sent.
func (l *limitField) UnmarshalJSON(b []byte) error {
	l.set = true
	if bytes.Equal(bytes.TrimSpace(b), []byte("null")) {
		l.v = nil
		return nil
	}
	var n int
	if err := json.Unmarshal(b, &n); err != nil {
		return err
	}
	l.v = &n
	return nil
}

// UpdateAIAutonomyRequest replaces the setting. Both limits are required: a
// number from 0 to 100000, or null for unlimited.
type UpdateAIAutonomyRequest struct {
	Paused  bool       `json:"paused"`
	PerHour limitField `json:"per_hour" swaggertype:"integer"`
	PerDay  limitField `json:"per_day" swaggertype:"integer"`
}

func toAIAutonomyResponse(v tenantai.AutonomyView) AIAutonomyResponse {
	return AIAutonomyResponse{Paused: v.Paused, PausedAt: v.PausedAt, PausedBy: v.PausedBy, PerHour: v.PerHour,
		PerDay: v.PerDay, UpdatedAt: v.UpdatedAt, UpdatedBy: v.UpdatedBy, Loosened: v.Loosened}
}

func (h *AISettingsHandler) autonomy(w http.ResponseWriter, r *http.Request) (AIAutonomyStore, string, bool) {
	store, ok := h.store.(AIAutonomyStore)
	if !ok {
		apierror.NotFound("AI autonomy").WriteJSON(w)
		return nil, "", false
	}
	tenantID := middleware.GetTenantID(r.Context())
	if tenantID == "" {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return nil, "", false
	}
	return store, tenantID, true
}

// GetAutonomy handles GET /api/v1/organization/settings/ai/autonomy
// @Summary      Read the switch and limits on changes AI agents make without a person
// @Description  Whether changes without a person are paused, and the limits per clock hour and per 24 hours (null: unlimited). The defaults are not paused, 100 an hour, 500 a day. Only changes that add risk information (confirming a finding) can ever happen without a person; lowering risk is always a request. Anyone with settings:read.
// @Tags         Tenants
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  AIAutonomyResponse
// @Router       /organization/settings/ai/autonomy [get]
func (h *AISettingsHandler) GetAutonomy(w http.ResponseWriter, r *http.Request) {
	store, tenantID, ok := h.autonomy(w, r)
	if !ok {
		return
	}
	v, err := store.GetAutonomy(r.Context(), tenantID)
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toAIAutonomyResponse(v))
}

// UpdateAutonomy handles PUT /api/v1/organization/settings/ai/autonomy
// @Summary      Change the switch and limits on changes AI agents make without a person
// @Description  Pausing or lowering a limit applies at once, also to runs in flight, and needs no recent sign-in. Resuming, raising a limit or making it unlimited (null) needs a recent sign-in (403 STEP_UP_REQUIRED), is audited critical and every owner and administrator is told. Both limits are required: 0 to 100000, or null. Owners and administrators with settings:write.
// @Tags         Tenants
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body body UpdateAIAutonomyRequest true "Settings"
// @Success      200  {object}  AIAutonomyResponse
// @Failure      400  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Router       /organization/settings/ai/autonomy [put]
func (h *AISettingsHandler) UpdateAutonomy(w http.ResponseWriter, r *http.Request) {
	store, tenantID, ok := h.autonomy(w, r)
	if !ok {
		return
	}
	var req UpdateAIAutonomyRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10)).Decode(&req); err != nil || !req.PerHour.set || !req.PerDay.set {
		apierror.BadRequest("Invalid request: send paused, per_hour and per_day (a number from 0 to 100000, or null for unlimited)").WriteJSON(w)
		return
	}
	v, err := store.SaveAutonomy(r.Context(), tenantID,
		tenantai.AutonomyInput{Paused: req.Paused, PerHour: req.PerHour.v, PerDay: req.PerDay.v}, h.actx(r))
	if err != nil {
		if middleware.WriteStepUpError(w, err, authapp.StepUpWindow) {
			return
		}
		if errors.Is(err, tenantai.ErrNoActor) {
			apierror.Forbidden("A signed-in owner or administrator must make this change.").WriteJSON(w)
			return
		}
		if errors.Is(err, shared.ErrValidation) {
			apierror.BadRequest("Invalid limits: each is a number from 0 to 100000, or null for unlimited").WriteJSON(w)
			return
		}
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toAIAutonomyResponse(v))
}
