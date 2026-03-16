package handler

import (
	"encoding/json"
	"net/http"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/logger"
)

// PlatformStatsHandler handles platform stats API requests.
type PlatformStatsHandler struct {
	agentService *app.AgentService
	logger       *logger.Logger
}

// NewPlatformStatsHandler creates a new PlatformStatsHandler.
func NewPlatformStatsHandler(agentService *app.AgentService, log *logger.Logger) *PlatformStatsHandler {
	return &PlatformStatsHandler{
		agentService: agentService,
		logger:       log.With("handler", "platform_stats"),
	}
}

// TierStatsResponse represents statistics for a single platform agent tier.
type TierStatsResponse struct {
	TotalAgents    int `json:"total_agents"`
	OnlineAgents   int `json:"online_agents"`
	OfflineAgents  int `json:"offline_agents"`
	TotalCapacity  int `json:"total_capacity"`
	CurrentLoad    int `json:"current_load"`
	AvailableSlots int `json:"available_slots"`
}

// PlatformStatsResponse represents the platform stats API response.
type PlatformStatsResponse struct {
	Enabled         bool                        `json:"enabled"`
	MaxTier         string                      `json:"max_tier"`
	AccessibleTiers []string                    `json:"accessible_tiers"`
	MaxConcurrent   int                         `json:"max_concurrent"`
	MaxQueued       int                         `json:"max_queued"`
	CurrentActive   int                         `json:"current_active"`
	CurrentQueued   int                         `json:"current_queued"`
	AvailableSlots  int                         `json:"available_slots"`
	TierStats       map[string]TierStatsResponse `json:"tier_stats"`
}

// GetStats returns platform agent statistics for the current tenant.
func (h *PlatformStatsHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	tenantID, ok := middleware.GetTenantIDFromContext(ctx)
	if !ok {
		apierror.Unauthorized("tenant context required").WriteJSON(w)
		return
	}

	stats, err := h.agentService.GetPlatformStats(ctx, tenantID)
	if err != nil {
		h.logger.Error("failed to get platform stats", "error", err, "tenant_id", tenantID)
		apierror.InternalServerError("failed to retrieve platform stats").WriteJSON(w)
		return
	}

	// Build tier stats response
	tierStats := make(map[string]TierStatsResponse)
	for tier, ts := range stats.TierStats {
		tierStats[tier] = TierStatsResponse{
			TotalAgents:    ts.TotalAgents,
			OnlineAgents:   ts.OnlineAgents,
			OfflineAgents:  ts.OfflineAgents,
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
