package handler

import (
	"encoding/json"
	"net/http"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// DashboardHandler handles dashboard-related HTTP requests.
type DashboardHandler struct {
	dashboardService *app.DashboardService
	logger           *logger.Logger
}

// NewDashboardHandler creates a new DashboardHandler.
func NewDashboardHandler(dashboardService *app.DashboardService, log *logger.Logger) *DashboardHandler {
	return &DashboardHandler{
		dashboardService: dashboardService,
		logger:           log,
	}
}

// DashboardStatsResponse represents the dashboard statistics response.
type DashboardStatsResponse struct {
	Assets         AssetStats      `json:"assets"`
	Findings       FindingStats    `json:"findings"`
	Repositories   RepositoryStats `json:"repositories"`
	RecentActivity []ActivityItem  `json:"recent_activity"`
}

// AssetStats represents asset statistics.
type AssetStats struct {
	Total     int            `json:"total"`
	ByType    map[string]int `json:"by_type"`
	ByStatus  map[string]int `json:"by_status"`
	RiskScore float64        `json:"risk_score"`
}

// FindingStats represents finding statistics.
type FindingStats struct {
	Total       int            `json:"total"`
	BySeverity  map[string]int `json:"by_severity"`
	ByStatus    map[string]int `json:"by_status"`
	Overdue     int            `json:"overdue"`
	AverageCVSS float64        `json:"average_cvss"`
}

// RepositoryStats represents repository statistics.
type RepositoryStats struct {
	Total        int `json:"total"`
	WithFindings int `json:"with_findings"`
}

// ActivityItem represents a recent activity item.
type ActivityItem struct {
	Type        string `json:"type"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Timestamp   string `json:"timestamp"`
}

// GetStats returns dashboard statistics for a tenant.
// @Summary      Get tenant dashboard stats
// @Description  Returns dashboard statistics for the current tenant
// @Tags         Dashboard
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  DashboardStatsResponse
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      500  {object}  map[string]string
// @Router       /dashboard/stats [get]
func (h *DashboardHandler) GetStats(w http.ResponseWriter, r *http.Request) {
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
	stats, err := h.dashboardService.GetStats(ctx, tenantID)
	if err != nil {
		h.logger.Error("failed to get dashboard stats", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	// Convert to response
	response := DashboardStatsResponse{
		Assets: AssetStats{
			Total:     stats.AssetCount,
			ByType:    stats.AssetsByType,
			ByStatus:  stats.AssetsByStatus,
			RiskScore: stats.AverageRiskScore,
		},
		Findings: FindingStats{
			Total:       stats.FindingCount,
			BySeverity:  stats.FindingsBySeverity,
			ByStatus:    stats.FindingsByStatus,
			Overdue:     stats.OverdueFindings,
			AverageCVSS: stats.AverageCVSS,
		},
		Repositories: RepositoryStats{
			Total:        stats.RepositoryCount,
			WithFindings: stats.RepositoriesWithFindings,
		},
		RecentActivity: convertActivityItems(stats.RecentActivity),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}

// GetGlobalStats returns dashboard statistics filtered by user's accessible tenants.
// @Summary      Get global dashboard stats
// @Description  Returns dashboard statistics filtered by user's accessible tenants
// @Tags         Dashboard
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  DashboardStatsResponse
// @Failure      401  {object}  map[string]string
// @Failure      500  {object}  map[string]string
// @Router       /dashboard/stats/global [get]
func (h *DashboardHandler) GetGlobalStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get accessible tenant IDs from JWT claims
	accessibleTenants := middleware.GetAccessibleTenants(ctx)

	// Log for debugging
	h.logger.Debug("fetching dashboard stats",
		"user_id", middleware.GetUserID(ctx),
		"accessible_tenants", accessibleTenants,
	)

	// Get stats filtered by accessible tenants
	stats, err := h.dashboardService.GetStatsForTenants(ctx, accessibleTenants)
	if err != nil {
		h.logger.Error("failed to get dashboard stats", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	// Convert to response
	response := DashboardStatsResponse{
		Assets: AssetStats{
			Total:     stats.AssetCount,
			ByType:    stats.AssetsByType,
			ByStatus:  stats.AssetsByStatus,
			RiskScore: stats.AverageRiskScore,
		},
		Findings: FindingStats{
			Total:       stats.FindingCount,
			BySeverity:  stats.FindingsBySeverity,
			ByStatus:    stats.FindingsByStatus,
			Overdue:     stats.OverdueFindings,
			AverageCVSS: stats.AverageCVSS,
		},
		Repositories: RepositoryStats{
			Total:        stats.RepositoryCount,
			WithFindings: stats.RepositoriesWithFindings,
		},
		RecentActivity: convertActivityItems(stats.RecentActivity),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}

func convertActivityItems(items []app.ActivityItem) []ActivityItem {
	result := make([]ActivityItem, len(items))
	for i, item := range items {
		result[i] = ActivityItem{
			Type:        item.Type,
			Title:       item.Title,
			Description: item.Description,
			Timestamp:   item.Timestamp.Format("2006-01-02T15:04:05Z"),
		}
	}
	return result
}

// Ensure DashboardHandler has no unused imports
var _ = shared.ID{}
