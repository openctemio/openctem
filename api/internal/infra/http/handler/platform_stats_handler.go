package handler

import (
	"encoding/json"
	"net/http"

	"github.com/openctemio/openctem/api/internal/app/sensor"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// PlatformStatsHandler handles platform stats API requests.
type PlatformStatsHandler struct {
	sensorService *sensor.SensorService
	logger        *logger.Logger
}

// NewPlatformStatsHandler creates a new PlatformStatsHandler.
func NewPlatformStatsHandler(sensorService *sensor.SensorService, log *logger.Logger) *PlatformStatsHandler {
	return &PlatformStatsHandler{
		sensorService: sensorService,
		logger:        log.With("handler", "platform_stats"),
	}
}

// TierStatsResponse represents statistics for a single platform sensor tier.
type TierStatsResponse struct {
	TotalSensors   int `json:"total_sensors"`
	OnlineSensors  int `json:"online_sensors"`
	OfflineSensors int `json:"offline_sensors"`
	TotalCapacity  int `json:"total_capacity"`
	CurrentLoad    int `json:"current_load"`
	AvailableSlots int `json:"available_slots"`
}

// PlatformStatsResponse represents the platform stats API response.
type PlatformStatsResponse struct {
	Enabled         bool                         `json:"enabled"`
	MaxTier         string                       `json:"max_tier"`
	AccessibleTiers []string                     `json:"accessible_tiers"`
	MaxConcurrent   int                          `json:"max_concurrent"`
	MaxQueued       int                          `json:"max_queued"`
	CurrentActive   int                          `json:"current_active"`
	CurrentQueued   int                          `json:"current_queued"`
	AvailableSlots  int                          `json:"available_slots"`
	TierStats       map[string]TierStatsResponse `json:"tier_stats"`
}

// GetStats returns platform sensor statistics for the current tenant.
func (h *PlatformStatsHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	tenantID, ok := middleware.GetTenantIDFromContext(ctx)
	if !ok {
		apierror.Unauthorized("tenant context required").WriteJSON(w)
		return
	}

	stats, err := h.sensorService.GetPlatformStats(ctx, tenantID)
	if err != nil {
		h.logger.Error("failed to get platform stats", "error", err, "tenant_id", tenantID)
		apierror.InternalServerError("failed to retrieve platform stats").WriteJSON(w)
		return
	}

	// Build tier stats response
	tierStats := make(map[string]TierStatsResponse)
	for tier, ts := range stats.TierStats {
		tierStats[tier] = TierStatsResponse{
			TotalSensors:   ts.TotalSensors,
			OnlineSensors:  ts.OnlineSensors,
			OfflineSensors: ts.OfflineSensors,
			TotalCapacity:  ts.TotalCapacity,
			CurrentLoad:    ts.CurrentLoad,
			AvailableSlots: ts.AvailableSlots,
		}
	}

	resp := PlatformStatsResponse{
		Enabled:         stats.Enabled,
		MaxTier:         stats.MaxTier,
		AccessibleTiers: stats.AccessibleTiers,
		MaxConcurrent:   stats.MaxConcurrent,
		MaxQueued:       stats.MaxQueued,
		CurrentActive:   stats.CurrentActive,
		CurrentQueued:   stats.CurrentQueued,
		AvailableSlots:  stats.AvailableSlots,
		TierStats:       tierStats,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		h.logger.Error("failed to encode platform stats response", "error", err)
	}
}
