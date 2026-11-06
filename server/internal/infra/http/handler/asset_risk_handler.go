package handler

// Asset risk score explanation (docs/architecture/asset-risk-score.md).

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
)

// AssetRiskContributorResponse is one finding that drives the score.
type AssetRiskContributorResponse struct {
	FindingID        string   `json:"finding_id"`
	Title            string   `json:"title"`
	Severity         string   `json:"severity"`
	EPSSScore        *float64 `json:"epss_score,omitempty"`
	InKEV            bool     `json:"in_kev"`
	ExploitAvailable bool     `json:"exploit_available"`
}

// AssetRiskLevelsResponse holds the lower bounds of the level bands.
type AssetRiskLevelsResponse struct {
	CriticalMin int `json:"critical_min"`
	HighMin     int `json:"high_min"`
	MediumMin   int `json:"medium_min"`
	LowMin      int `json:"low_min"`
}

// AssetRiskResponse explains an asset's risk score.
type AssetRiskResponse struct {
	AssetID string `json:"asset_id"`
	// Score is the stored score; Breakdown.Score is the score the current
	// inputs give (they differ while a rescore is pending).
	Score        int                            `json:"score"`
	Level        string                         `json:"level"`
	ScoredAt     *time.Time                     `json:"scored_at,omitempty"`
	Pending      bool                           `json:"pending"`
	Breakdown    asset.RiskBreakdown            `json:"breakdown"`
	Contributors []AssetRiskContributorResponse `json:"contributors"`
	RiskLevels   AssetRiskLevelsResponse        `json:"risk_levels"`
}

// GetRisk handles GET /api/v1/assets/{id}/risk
// @Summary      Explain an asset's risk score
// @Description  The stored score, its level and freshness, the factors of the current model and the open findings that drive it.
// @Tags         Assets
// @Produce      json
// @Security     BearerAuth
// @Param        id   path      string  true  "Asset ID"
// @Success      200  {object}  AssetRiskResponse
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Failure      500  {object}  map[string]string
// @Router       /assets/{id}/risk [get]
func (h *AssetHandler) GetRisk(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	id := r.PathValue("id")
	if id == "" {
		apierror.BadRequest("Asset ID is required").WriteJSON(w)
		return
	}
	ex, err := h.service.ExplainRisk(r.Context(), tenantID, id, middleware.GetUserID(r.Context()), middleware.IsAdmin(r.Context()))
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	resp := AssetRiskResponse{
		AssetID:      ex.Asset.ID().String(),
		Score:        ex.Asset.RiskScore(),
		Level:        ex.Level,
		ScoredAt:     ex.Asset.RiskScoredAt(),
		Pending:      ex.Asset.RiskScorePending(),
		Breakdown:    ex.Breakdown,
		Contributors: make([]AssetRiskContributorResponse, 0, len(ex.Contributors)),
		RiskLevels: AssetRiskLevelsResponse{
			CriticalMin: ex.RiskLevels.CriticalMin, HighMin: ex.RiskLevels.HighMin,
			MediumMin: ex.RiskLevels.MediumMin, LowMin: ex.RiskLevels.LowMin,
		},
	}
	for _, c := range ex.Contributors {
		resp.Contributors = append(resp.Contributors, AssetRiskContributorResponse{
			FindingID: c.FindingID.String(), Title: c.Title, Severity: c.Severity,
			EPSSScore: c.EPSSScore, InKEV: c.InKEV, ExploitAvailable: c.ExploitAvailable,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}
