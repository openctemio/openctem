package handler

import (
	"encoding/json"
	"net/http"

	"github.com/openctemio/api/internal/app/attack"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// AttackSurfaceHandler handles attack surface related HTTP requests.
type AttackSurfaceHandler struct {
	service *attack.SurfaceService
	logger  *logger.Logger
}

// NewAttackSurfaceHandler creates a new AttackSurfaceHandler.
func NewAttackSurfaceHandler(service *attack.SurfaceService, log *logger.Logger) *AttackSurfaceHandler {
	return &AttackSurfaceHandler{
		service: service,
		logger:  log.With("handler", "attack_surface"),
	}
}

// AttackSurfaceStatsResponse represents the attack surface statistics response.
// @Description Attack surface statistics response
type AttackSurfaceStatsResponse struct {
	// Summary statistics
	TotalAssets       int     `json:"total_assets" example:"303"`
	ExposedServices   int     `json:"exposed_services" example:"47"`
	CriticalExposures int     `json:"critical_exposures" example:"12"`
	RiskScore         float64 `json:"risk_score" example:"72.5"`

	// Trends (week-over-week changes)
	TotalAssetsChange       int `json:"total_assets_change" example:"12"`
	ExposedServicesChange   int `json:"exposed_services_change" example:"-3"`
	CriticalExposuresChange int `json:"critical_exposures_change" example:"2"`

	// Asset breakdown by type
	AssetBreakdown []AssetTypeBreakdownResponse `json:"asset_breakdown"`

	// Top exposed services
	ExposedServicesList []ExposedServiceResponse `json:"exposed_services_list"`

	// Recent changes
	RecentChanges []AssetChangeResponse `json:"recent_changes"`
}

// AssetTypeBreakdownResponse represents asset breakdown by type.
type AssetTypeBreakdownResponse struct {
	Type    string `json:"type" example:"domain"`
	Total   int    `json:"total" example:"45"`
	Exposed int    `json:"exposed" example:"12"`
}

// ExposedServiceResponse represents an exposed service.
type ExposedServiceResponse struct {
	ID           string `json:"id" example:"550e8400-e29b-41d4-a716-446655440000"`
	Name         string `json:"name" example:"api.example.com"`
	Type         string `json:"type" example:"service"`
	Port         int    `json:"port,omitempty" example:"443"`
	Exposure     string `json:"exposure" example:"public"`
	Criticality  string `json:"criticality" example:"high"`
	FindingCount int    `json:"finding_count" example:"3"`
	LastSeen     string `json:"last_seen" example:"2024-01-15T10:30:00Z"`
}

// AssetChangeResponse represents a recent asset change.
type AssetChangeResponse struct {
	Type      string `json:"type" example:"added"`
	AssetName string `json:"asset_name" example:"new-api.example.com"`
	AssetType string `json:"asset_type" example:"service"`
	Timestamp string `json:"timestamp" example:"2024-01-15T10:30:00Z"`
}

// GetStats returns attack surface statistics for the current tenant.
// @Summary      Get attack surface statistics
// @Description  Returns attack surface statistics including total assets, exposed services, critical exposures, and risk score
// @Tags         Attack Surface
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  AttackSurfaceStatsResponse
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Router       /attack-surface/stats [get]
func (h *AttackSurfaceHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get tenant ID from JWT token
	tenantIDStr := middleware.MustGetTenantID(ctx)

	// Parse tenant ID to shared.ID
	tenantID, err := shared.IDFromString(tenantIDStr)
	if err != nil {
		apierror.BadRequest("Invalid tenant ID format").WriteJSON(w)
		return
	}

	// Get stats from service
	stats, err := h.service.GetStats(ctx, tenantID)
	if err != nil {
		h.logger.Error("failed to get attack surface stats", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	// Convert to response
	response := h.toStatsResponse(stats)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}

// AttackPathScoreResponse represents a single asset with its attack path score.
type AttackPathScoreResponse struct {
	AssetID       string  `json:"asset_id"`
	Name          string  `json:"name"`
	AssetType     string  `json:"asset_type"`
	Exposure      string  `json:"exposure"`
	Criticality   string  `json:"criticality"`
	RiskScore     int     `json:"risk_score"`
	IsCrownJewel  bool    `json:"is_crown_jewel"`
	FindingCount  int     `json:"finding_count"`
	ReachableFrom int     `json:"reachable_from"`
	PathScore     float64 `json:"path_score"`
	IsEntryPoint  bool    `json:"is_entry_point"`
	IsProtected   bool    `json:"is_protected"`
}

// AttackPathSummaryResponse holds aggregate attack path metrics.
type AttackPathSummaryResponse struct {
	TotalPaths          int  `json:"total_paths"`
	EntryPoints         int  `json:"entry_points"`
	ReachableAssets     int  `json:"reachable_assets"`
	MaxDepth            int  `json:"max_depth"`
	CriticalReachable   int  `json:"critical_reachable"`
	CrownJewelsAtRisk   int  `json:"crown_jewels_at_risk"`
	HasRelationshipData bool `json:"has_relationship_data"`
}

// AttackPathScoringResponse is the response for the attack path scoring endpoint.
type AttackPathScoringResponse struct {
	Summary   AttackPathSummaryResponse `json:"summary"`
	TopAssets []AttackPathScoreResponse `json:"top_assets"`
}

// GetAttackPaths computes attack path scoring for the current tenant.
// @Summary      Get attack path scoring
// @Description  Computes reachability-based attack path scores for all assets
// @Tags         Attack Surface
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  AttackPathScoringResponse
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Router       /attack-surface/attack-paths [get]
func (h *AttackSurfaceHandler) GetAttackPaths(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	tenantIDStr := middleware.MustGetTenantID(ctx)
	tenantID, err := shared.IDFromString(tenantIDStr)
	if err != nil {
		apierror.BadRequest("Invalid tenant ID format").WriteJSON(w)
		return
	}

	result, err := h.service.GetAttackPathScores(ctx, tenantID)
	if err != nil {
		h.logger.Error("failed to compute attack path scores", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	// Map to response
	topAssets := make([]AttackPathScoreResponse, len(result.TopAssets))
	for i, a := range result.TopAssets {
		topAssets[i] = AttackPathScoreResponse{
			AssetID:       a.AssetID,
			Name:          a.Name,
			AssetType:     a.AssetType,
			Exposure:      a.Exposure,
			Criticality:   a.Criticality,
			RiskScore:     a.RiskScore,
			IsCrownJewel:  a.IsCrownJewel,
			FindingCount:  a.FindingCount,
			ReachableFrom: a.ReachableFrom,
			PathScore:     a.PathScore,
			IsEntryPoint:  a.IsEntryPoint,
			IsProtected:   a.IsProtected,
		}
	}

	response := AttackPathScoringResponse{
		Summary: AttackPathSummaryResponse{
			TotalPaths:          result.Summary.TotalPaths,
			EntryPoints:         result.Summary.EntryPoints,
			ReachableAssets:     result.Summary.ReachableAssets,
			MaxDepth:            result.Summary.MaxDepth,
			CriticalReachable:   result.Summary.CriticalReachable,
			CrownJewelsAtRisk:   result.Summary.CrownJewelsAtRisk,
			HasRelationshipData: result.Summary.HasRelationshipData,
		},
		TopAssets: topAssets,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}

// toStatsResponse converts service stats to API response.
func (h *AttackSurfaceHandler) toStatsResponse(stats *attack.SurfaceStats) AttackSurfaceStatsResponse {
	// Convert asset breakdown
	breakdown := make([]AssetTypeBreakdownResponse, len(stats.AssetBreakdown))
	for i, b := range stats.AssetBreakdown {
		breakdown[i] = AssetTypeBreakdownResponse{
			Type:    b.Type,
			Total:   b.Total,
			Exposed: b.Exposed,
		}
	}

	// Convert exposed services list
	services := make([]ExposedServiceResponse, len(stats.ExposedServicesList))
	for i, s := range stats.ExposedServicesList {
		services[i] = ExposedServiceResponse{
			ID:           s.ID,
			Name:         s.Name,
			Type:         s.Type,
			Port:         s.Port,
			Exposure:     s.Exposure,
			Criticality:  s.Criticality,
			FindingCount: s.FindingCount,
			LastSeen:     s.LastSeen.Format("2006-01-02T15:04:05Z"),
		}
	}

	// Convert recent changes
	changes := make([]AssetChangeResponse, len(stats.RecentChanges))
	for i, c := range stats.RecentChanges {
		changes[i] = AssetChangeResponse{
			Type:      c.Type,
			AssetName: c.AssetName,
			AssetType: c.AssetType,
			Timestamp: c.Timestamp.Format("2006-01-02T15:04:05Z"),
		}
	}

	return AttackSurfaceStatsResponse{
		TotalAssets:             stats.TotalAssets,
		ExposedServices:         stats.ExposedServices,
		CriticalExposures:       stats.CriticalExposures,
		RiskScore:               stats.RiskScore,
		TotalAssetsChange:       stats.TotalAssetsChange,
		ExposedServicesChange:   stats.ExposedServicesChange,
		CriticalExposuresChange: stats.CriticalExposuresChange,
		AssetBreakdown:          breakdown,
		ExposedServicesList:     services,
		RecentChanges:           changes,
	}
}
