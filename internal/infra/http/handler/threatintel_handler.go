package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/domain/threatintel"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/validator"
)

// ThreatIntelHandler handles threat intelligence HTTP requests.
type ThreatIntelHandler struct {
	service   *app.ThreatIntelService
	validator *validator.Validator
	logger    *logger.Logger
}

// NewThreatIntelHandler creates a new ThreatIntelHandler.
func NewThreatIntelHandler(
	service *app.ThreatIntelService,
	v *validator.Validator,
	log *logger.Logger,
) *ThreatIntelHandler {
	return &ThreatIntelHandler{
		service:   service,
		validator: v,
		logger:    log.With("handler", "threat_intel"),
	}
}

// GetSyncStatuses returns all sync statuses.
// GET /api/v1/threat-intel/sync
func (h *ThreatIntelHandler) GetSyncStatuses(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	statuses, err := h.service.GetSyncStatuses(ctx)
	if err != nil {
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	response := make([]SyncStatusResponse, 0, len(statuses))
	for _, status := range statuses {
		response = append(response, toSyncStatusResponse(status))
	}

	writeJSONResponse(w, http.StatusOK, response)
}

// GetSyncStatus returns sync status for a specific source.
// GET /api/v1/threat-intel/sync/{source}
func (h *ThreatIntelHandler) GetSyncStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	source := chi.URLParam(r, "source")

	status, err := h.service.GetSyncStatus(ctx, source)
	if err != nil {
		if errors.Is(err, threatintel.ErrSyncStatusNotFound) {
			apierror.NotFound("sync status").WriteJSON(w)
			return
		}
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	writeJSONResponse(w, http.StatusOK, toSyncStatusResponse(status))
}

// TriggerSync triggers a sync for a specific source or all sources.
// POST /api/v1/threat-intel/sync
func (h *ThreatIntelHandler) TriggerSync(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req TriggerSyncRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// Empty body means sync all
		req.Source = ""
	}

	h.logger.Info("triggering threat intel sync", "source", req.Source)

	var results []app.ThreatIntelSyncResult
	if req.Source == "" || req.Source == "all" {
		results = h.service.SyncAll(ctx)
	} else {
		switch req.Source {
		case "epss":
			results = []app.ThreatIntelSyncResult{h.service.SyncEPSS(ctx)}
		case "kev":
			results = []app.ThreatIntelSyncResult{h.service.SyncKEV(ctx)}
		default:
			apierror.BadRequest("invalid source: " + req.Source).WriteJSON(w)
			return
		}
	}

	response := make([]SyncResultResponse, 0, len(results))
	hasError := false
	for _, result := range results {
		resp := SyncResultResponse{
			Source:        result.Source,
			RecordsSynced: result.RecordsSynced,
			DurationMs:    result.DurationMs,
			Success:       result.Error == nil,
		}
		if result.Error != nil {
			resp.Error = result.Error.Error()
			hasError = true
		}
		response = append(response, resp)
	}

	status := http.StatusOK
	if hasError {
		status = http.StatusPartialContent
	}

	writeJSONResponse(w, status, map[string]any{
		"results": response,
	})
}

// SetSyncEnabled enables or disables sync for a source.
// PATCH /api/v1/threat-intel/sync/{source}
func (h *ThreatIntelHandler) SetSyncEnabled(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	source := chi.URLParam(r, "source")

	var req SetSyncEnabledRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}

	if err := h.service.SetSyncEnabled(ctx, source, req.Enabled); err != nil {
		if errors.Is(err, threatintel.ErrSyncStatusNotFound) {
			apierror.NotFound("sync status").WriteJSON(w)
			return
		}
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	status, _ := h.service.GetSyncStatus(ctx, source)
	writeJSONResponse(w, http.StatusOK, toSyncStatusResponse(status))
}

// EnrichCVE enriches a single CVE with threat intel data.
// GET /api/v1/threat-intel/enrich/{cve_id}
func (h *ThreatIntelHandler) EnrichCVE(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	cveID := chi.URLParam(r, "cve_id")

	enrichment, err := h.service.EnrichCVE(ctx, cveID)
	if err != nil {
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	writeJSONResponse(w, http.StatusOK, toEnrichmentResponse(enrichment))
}

// EnrichCVEs enriches multiple CVEs with threat intel data.
// POST /api/v1/threat-intel/enrich
func (h *ThreatIntelHandler) EnrichCVEs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req EnrichCVEsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}

	if len(req.CVEIDs) == 0 {
		apierror.BadRequest("cve_ids is required").WriteJSON(w)
		return
	}

	if len(req.CVEIDs) > 1000 {
		apierror.BadRequest("maximum 1000 CVE IDs allowed").WriteJSON(w)
		return
	}

	enrichments, err := h.service.EnrichCVEs(ctx, req.CVEIDs)
	if err != nil {
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	response := make(map[string]EnrichmentResponse)
	for cveID, enrichment := range enrichments {
		response[cveID] = toEnrichmentResponse(enrichment)
	}

	writeJSONResponse(w, http.StatusOK, map[string]any{
		"enrichments": response,
	})
}

// GetEPSSScore retrieves an EPSS score by CVE ID.
// GET /api/v1/threat-intel/epss/{cve_id}
func (h *ThreatIntelHandler) GetEPSSScore(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	cveID := chi.URLParam(r, "cve_id")

	score, err := h.service.GetEPSSScore(ctx, cveID)
	if err != nil {
		if errors.Is(err, threatintel.ErrEPSSNotFound) {
			apierror.NotFound("EPSS score").WriteJSON(w)
			return
		}
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	writeJSONResponse(w, http.StatusOK, toEPSSScoreResponse(score))
}

// GetKEVEntry retrieves a KEV entry by CVE ID.
// GET /api/v1/threat-intel/kev/{cve_id}
func (h *ThreatIntelHandler) GetKEVEntry(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	cveID := chi.URLParam(r, "cve_id")

	entry, err := h.service.GetKEVEntry(ctx, cveID)
	if err != nil {
		if errors.Is(err, threatintel.ErrKEVNotFound) {
			apierror.NotFound("KEV entry").WriteJSON(w)
			return
		}
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	writeJSONResponse(w, http.StatusOK, toKEVEntryResponse(entry))
}

// GetKEVStats returns KEV statistics.
// GET /api/v1/threat-intel/kev/stats
func (h *ThreatIntelHandler) GetKEVStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	stats, err := h.service.GetKEVStats(ctx)
	if err != nil {
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	writeJSONResponse(w, http.StatusOK, stats)
}

// GetEPSSStats returns EPSS statistics.
// GET /api/v1/threat-intel/epss/stats
func (h *ThreatIntelHandler) GetEPSSStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	stats, err := h.service.GetEPSSStats(ctx)
	if err != nil {
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	writeJSONResponse(w, http.StatusOK, stats)
}

// GetThreatIntelStats returns unified threat intelligence statistics.
// GET /api/v1/threat-intel/stats
func (h *ThreatIntelHandler) GetThreatIntelStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	stats, err := h.service.GetThreatIntelStats(ctx)
	if err != nil {
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	writeJSONResponse(w, http.StatusOK, stats)
}

// Request/Response types

// TriggerSyncRequest is the request for triggering a sync.
type TriggerSyncRequest struct {
	Source string `json:"source,omitempty"` // empty or "all" for all sources
}

// SetSyncEnabledRequest is the request for enabling/disabling sync.
type SetSyncEnabledRequest struct {
	Enabled bool `json:"enabled"`
}

// EnrichCVEsRequest is the request for enriching multiple CVEs.
type EnrichCVEsRequest struct {
	CVEIDs []string `json:"cve_ids"`
}

// SyncStatusResponse is the response for sync status.
type SyncStatusResponse struct {
	Source         string  `json:"source"`
	Enabled        bool    `json:"enabled"`
	LastSyncAt     *string `json:"last_sync_at,omitempty"`
	LastSyncStatus string  `json:"last_sync_status"`
	LastError      string  `json:"last_error,omitempty"`
	RecordsSynced  int     `json:"records_synced"`
	NextSyncAt     *string `json:"next_sync_at,omitempty"`
}

// SyncResultResponse is the response for a sync result.
type SyncResultResponse struct {
	Source        string `json:"source"`
	RecordsSynced int    `json:"records_synced"`
	DurationMs    int64  `json:"duration_ms"`
	Success       bool   `json:"success"`
	Error         string `json:"error,omitempty"`
}

// EnrichmentResponse is the response for CVE enrichment.
type EnrichmentResponse struct {
	CVEID          string   `json:"cve_id"`
	EPSSScore      *float64 `json:"epss_score,omitempty"`
	EPSSPercentile *float64 `json:"epss_percentile,omitempty"`
	InKEV          bool     `json:"in_kev"`
	KEVDateAdded   *string  `json:"kev_date_added,omitempty"`
	KEVDueDate     *string  `json:"kev_due_date,omitempty"`
	KEVRansomware  *string  `json:"kev_ransomware,omitempty"`
	RiskLevel      string   `json:"risk_level"`
}

// EPSSScoreResponse is the response for an EPSS score.
type EPSSScoreResponse struct {
	CVEID        string  `json:"cve_id"`
	Score        float64 `json:"score"`
	Percentile   float64 `json:"percentile"`
	ModelVersion string  `json:"model_version,omitempty"`
	ScoreDate    string  `json:"score_date"`
	RiskLevel    string  `json:"risk_level"`
}

// KEVEntryResponse is the response for a KEV entry.
type KEVEntryResponse struct {
	CVEID             string   `json:"cve_id"`
	VendorProject     string   `json:"vendor_project"`
	Product           string   `json:"product"`
	VulnerabilityName string   `json:"vulnerability_name"`
	ShortDescription  string   `json:"short_description,omitempty"`
	DateAdded         string   `json:"date_added"`
	DueDate           string   `json:"due_date,omitempty"`
	DaysUntilDue      int      `json:"days_until_due"`
	IsPastDue         bool     `json:"is_past_due"`
	RansomwareUse     string   `json:"ransomware_use,omitempty"`
	Notes             string   `json:"notes,omitempty"`
	CWEs              []string `json:"cwes,omitempty"`
}

// Helper functions

func toSyncStatusResponse(status *threatintel.SyncStatus) SyncStatusResponse {
	resp := SyncStatusResponse{
		Source:         status.SourceName(),
		Enabled:        status.IsEnabled(),
		LastSyncStatus: status.LastSyncStatus().String(),
		LastError:      status.LastSyncError(),
		RecordsSynced:  status.RecordsSynced(),
	}

	if status.LastSyncAt() != nil {
		t := status.LastSyncAt().Format("2006-01-02T15:04:05Z")
		resp.LastSyncAt = &t
	}

	if status.NextSyncAt() != nil {
		t := status.NextSyncAt().Format("2006-01-02T15:04:05Z")
		resp.NextSyncAt = &t
	}

	return resp
}

func toEnrichmentResponse(enrichment *threatintel.ThreatIntelEnrichment) EnrichmentResponse {
	return EnrichmentResponse{
		CVEID:          enrichment.CVEID,
		EPSSScore:      enrichment.EPSSScore,
		EPSSPercentile: enrichment.EPSSPercentile,
		InKEV:          enrichment.InKEV,
		KEVDateAdded:   enrichment.KEVDateAdded,
		KEVDueDate:     enrichment.KEVDueDate,
		KEVRansomware:  enrichment.KEVRansomware,
		RiskLevel:      enrichment.RiskLevel(),
	}
}

func toEPSSScoreResponse(score *threatintel.EPSSScore) EPSSScoreResponse {
	return EPSSScoreResponse{
		CVEID:        score.CVEID(),
		Score:        score.Score(),
		Percentile:   score.Percentile(),
		ModelVersion: score.ModelVersion(),
		ScoreDate:    score.ScoreDate().Format("2006-01-02"),
		RiskLevel:    threatintel.EPSSRiskLevelFromScore(score.Score()).String(),
	}
}

func toKEVEntryResponse(entry *threatintel.KEVEntry) KEVEntryResponse {
	resp := KEVEntryResponse{
		CVEID:             entry.CVEID(),
		VendorProject:     entry.VendorProject(),
		Product:           entry.Product(),
		VulnerabilityName: entry.VulnerabilityName(),
		ShortDescription:  entry.ShortDescription(),
		DateAdded:         entry.DateAdded().Format("2006-01-02"),
		DaysUntilDue:      entry.DaysUntilDue(),
		IsPastDue:         entry.IsPastDue(),
		RansomwareUse:     entry.KnownRansomwareCampaignUse(),
		Notes:             entry.Notes(),
		CWEs:              entry.CWEs(),
	}

	if !entry.DueDate().IsZero() {
		resp.DueDate = entry.DueDate().Format("2006-01-02")
	}

	return resp
}

// writeJSONResponse writes a JSON response with the given status code.
func writeJSONResponse(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}
