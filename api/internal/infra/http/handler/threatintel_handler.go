package handler

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/openctemio/openctem/api/internal/app/datascope"
	"github.com/openctemio/openctem/api/internal/app/feedstatus"
	"github.com/openctemio/openctem/api/internal/app/feedsync"
	"github.com/openctemio/openctem/api/internal/app/threat"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/threatintel"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

// ThreatIntelHandler handles threat intelligence HTTP requests.
type ThreatIntelHandler struct {
	service   *threat.IntelService
	validator *validator.Validator
	logger    *logger.Logger
	dataScope *datascope.Enforcer
	runner    FeedRunner
	// bundlesConfigured: VULNFEED_ROOT_KEY_ID is set.
	bundlesConfigured bool
}

// FeedRunner starts a feed's sync in the background (*feedsync.Runner).
type FeedRunner interface {
	Has(source string) bool
	Trigger(source string) (feedsync.Outcome, error)
}

// SetFeedRunner wires the background runner behind the admin sync endpoint.
// bundlesConfigured says whether the vulnerability bundle import has a pinned
// root key (without one a manual sync would do nothing).
func (h *ThreatIntelHandler) SetFeedRunner(r FeedRunner, bundlesConfigured bool) *ThreatIntelHandler {
	h.runner, h.bundlesConfigured = r, bundlesConfigured
	return h
}

// SetDataScope wires the enforcer that narrows the tenant exposure counts
// (EPSS, KEV) to the caller's data scope.
func (h *ThreatIntelHandler) SetDataScope(e *datascope.Enforcer) *ThreatIntelHandler {
	h.dataScope = e
	return h
}

// NewThreatIntelHandler creates a new ThreatIntelHandler.
func NewThreatIntelHandler(
	service *threat.IntelService,
	v *validator.Validator,
	log *logger.Logger,
) *ThreatIntelHandler {
	return &ThreatIntelHandler{
		service:   service,
		validator: v,
		logger:    log.With("handler", "threat_intel"),
	}
}

// GetSyncStatuses returns the status of every feed (platform admin view).
// GET /api/v1/admin/threat-intel/sync
// @Summary      Threat-intelligence feed status (platform admin)
// @Description  State, error code, times and sizes of the platform-wide EPSS, CISA KEV and vulnerability bundle feeds.
// @Tags         Admin Threat Intelligence
// @Produce      json
// @Success      200  {array}  SyncStatusResponse
// @Security     BearerAuth
// @Router       /admin/threat-intel/sync [get]
func (h *ThreatIntelHandler) GetSyncStatuses(w http.ResponseWriter, r *http.Request) {
	h.getSyncStatuses(w, r, true)
}

func (h *ThreatIntelHandler) getSyncStatuses(w http.ResponseWriter, r *http.Request, admin bool) {
	views, err := h.service.FeedViews(r.Context())
	if err != nil {
		apierror.InternalError(err).WriteJSON(w)
		return
	}
	if admin {
		out := make([]SyncStatusResponse, 0, len(views))
		for _, v := range views {
			out = append(out, toSyncStatusResponse(v))
		}
		writeJSONResponse(w, http.StatusOK, out)
		return
	}
	out := make([]TenantSyncStatusResponse, 0, len(views))
	for _, v := range views {
		out = append(out, toTenantSyncStatusResponse(v))
	}
	writeJSONResponse(w, http.StatusOK, out)
}

// GetSyncStatusesTenant is the organization-facing list: state and freshness
// only, never the raw error text of a failed fetch (it can name hosts and
// paths) or the bundle internals.
// GET /api/v1/threat-intel/sync
func (h *ThreatIntelHandler) GetSyncStatusesTenant(w http.ResponseWriter, r *http.Request) {
	h.getSyncStatuses(w, r, false)
}

// GetSyncStatusTenant is GetSyncStatus without the admin detail.
// GET /api/v1/threat-intel/sync/{source}
func (h *ThreatIntelHandler) GetSyncStatusTenant(w http.ResponseWriter, r *http.Request) {
	h.getSyncStatus(w, r, false)
}

// GetSyncStatus returns the status of one feed (platform admin view).
// GET /api/v1/admin/threat-intel/sync/{source}
func (h *ThreatIntelHandler) GetSyncStatus(w http.ResponseWriter, r *http.Request) {
	h.getSyncStatus(w, r, true)
}

func (h *ThreatIntelHandler) getSyncStatus(w http.ResponseWriter, r *http.Request, admin bool) {
	v, err := h.service.FeedView(r.Context(), chi.URLParam(r, "source"))
	if err != nil {
		if errors.Is(err, threatintel.ErrSyncStatusNotFound) {
			apierror.NotFound("sync status").WriteJSON(w)
			return
		}
		apierror.InternalError(err).WriteJSON(w)
		return
	}
	if admin {
		writeJSONResponse(w, http.StatusOK, toSyncStatusResponse(v))
		return
	}
	writeJSONResponse(w, http.StatusOK, toTenantSyncStatusResponse(v))
}

// TriggerSync starts a sync of one feed or all feeds in the background.
// POST /api/v1/admin/threat-intel/sync
// @Summary      Start a threat-intelligence feed sync (platform admin)
// @Description  Queues a background sync of the EPSS, CISA KEV and/or vulnerability bundle feed and returns at once (202); the outcome shows in the feed status. One run per feed at a time; a feed that is switched off or not configured is not started. ops_admin or super_admin; audited.
// @Tags         Admin Threat Intelligence
// @Accept       json
// @Produce      json
// @Param        request  body      TriggerSyncRequest  false  "Feed (epss, kev, vulnfeed, all); empty = all"
// @Success      202  {object}  map[string]any
// @Failure      400  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Failure      429  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /admin/threat-intel/sync [post]
func (h *ThreatIntelHandler) TriggerSync(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req TriggerSyncRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// An empty body is allowed and means "sync all"; a malformed body is a
		// client error and must not be silently coerced into a full external
		// sync.
		if !errors.Is(err, io.EOF) {
			apierror.BadRequest("Invalid request body").WriteJSON(w)
			return
		}
		req.Source = ""
	}
	if h.runner == nil {
		apierror.ServiceUnavailable("feed sync is not available on this instance").WriteJSON(w)
		return
	}

	all := req.Source == "" || req.Source == "all"
	var sources []string
	if all {
		for _, s := range []string{feedstatus.SourceVulnfeed, feedstatus.SourceEPSS, feedstatus.SourceKEV} {
			if h.runner.Has(s) {
				sources = append(sources, s)
			}
		}
	} else {
		if !h.runner.Has(req.Source) {
			apierror.BadRequest("invalid source: " + req.Source).WriteJSON(w)
			return
		}
		sources = []string{req.Source}
	}
	h.logger.Info("triggering threat intel sync", "source", req.Source)

	results := make([]TriggerResult, 0, len(sources))
	var tooSoon *feedsync.TooSoonError
	started := 0
	for _, source := range sources {
		if reason := h.cannotRun(ctx, source); reason != "" {
			results = append(results, TriggerResult{Source: source, Status: "skipped", Reason: reason})
			continue
		}
		out, err := h.runner.Trigger(source)
		var ts *feedsync.TooSoonError
		switch {
		case errors.As(err, &ts):
			tooSoon = ts
			results = append(results, TriggerResult{Source: source, Status: "skipped", Reason: "rate_limited"})
		case err != nil:
			apierror.InternalError(err).WriteJSON(w)
			return
		default:
			started++
			results = append(results, TriggerResult{Source: source, Status: string(out)})
		}
	}

	if started == 0 {
		if tooSoon != nil {
			w.Header().Set("Retry-After", strconv.Itoa(int(tooSoon.RetryAfter.Seconds())+1))
			apierror.TooManyRequests("A sync of this feed was just started. Try again in a few seconds.").WriteJSON(w)
			return
		}
		if !all {
			apierror.Conflict("This feed cannot be synced now: " + results[0].Reason).WriteJSON(w)
			return
		}
	}
	writeJSONResponse(w, http.StatusAccepted, map[string]any{"results": results})
}

// cannotRun says why a feed is not started ("" when it can be): scheduled
// sync switched off, or the bundle import not configured.
func (h *ThreatIntelHandler) cannotRun(ctx context.Context, source string) string {
	if source == feedstatus.SourceVulnfeed && !h.bundlesConfigured {
		return feedstatus.CodeNotConfigured
	}
	enabled, err := h.service.FeedEnabled(ctx, source)
	if err != nil {
		return "unknown"
	}
	if !enabled {
		return feedstatus.CodeDisabled
	}
	return ""
}

// SetSyncEnabled enables or disables sync for a source.
// PATCH /api/v1/admin/threat-intel/sync/{source}
// @Summary      Enable or disable a threat-intelligence feed sync (platform admin)
// @Description  Turns the platform-wide sync of one feed on or off for every organization. ops_admin or super_admin; audited.
// @Tags         Admin Threat Intelligence
// @Accept       json
// @Produce      json
// @Param        source   path      string                 true  "Feed (epss, kev, vulnfeed)"
// @Param        request  body      SetSyncEnabledRequest  true  "Enabled"
// @Success      200  {object}  SyncStatusResponse
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /admin/threat-intel/sync/{source} [patch]
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

	v, err := h.service.FeedView(ctx, source)
	if err != nil {
		if errors.Is(err, threatintel.ErrSyncStatusNotFound) {
			apierror.NotFound("sync status").WriteJSON(w)
			return
		}
		apierror.InternalError(err).WriteJSON(w)
		return
	}
	writeJSONResponse(w, http.StatusOK, toSyncStatusResponse(v))
}

// EnrichCVE enriches a single CVE with threat intel data.
// GET /api/v1/threat-intel/enrich/{cve_id}
func (h *ThreatIntelHandler) EnrichCVE(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	cveID := chi.URLParam(r, "cveId")

	enrichment, err := h.service.EnrichCVE(ctx, cveID)
	if err != nil {
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	writeJSONResponse(w, http.StatusOK, toEnrichmentResponse(enrichment))
}

// EnrichCVEs enriches multiple CVEs with threat intel data.
// POST /api/v1/threat-intel/enrich
// @Summary      Enrich CVEs with threat intelligence
// @Description  EPSS and KEV data for up to 1000 CVE ids, keyed by CVE id.
// @Tags         Threat Intel
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body  body  EnrichCVEsRequest  true  "CVE ids"
// @Success      200  {object}  map[string]interface{}
// @Failure      400  {object}  apierror.Error
// @Router       /threat-intel/enrich [post]
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
	cveID := chi.URLParam(r, "cveId")

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
	cveID := chi.URLParam(r, "cveId")

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

	tenantID, ok := middleware.GetTenantIDFromContext(ctx)
	if !ok {
		apierror.Unauthorized("tenant context required").WriteJSON(w)
		return
	}

	// The exposure counts follow the viewer (D6): a restricted member counts
	// their own scope, dashboards:org:view and unrestricted callers the
	// organization.
	scope, _, err := h.dataScope.ViewerScope(ctx, tenantID)
	if err != nil {
		apierror.InternalError(err).WriteJSON(w)
		return
	}
	// The counts also follow the pentest member-visibility rule of the
	// findings list.
	stats, err := h.service.GetThreatIntelStats(h.dataScope.WithFindingViewer(ctx), tenantID, scope)
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

// SyncStatusResponse is the platform admin view of a feed. The server
// computes the state and the error code; the console only renders them.
type SyncStatusResponse struct {
	Source  string `json:"source"`
	Enabled bool   `json:"enabled"`
	// State: up_to_date, waiting_for_publisher, stale, failing, refused,
	// running or off.
	State string `json:"state"`
	// ErrorCode classifies the last failure (publisher_empty, unreachable,
	// http_status, signature_invalid, ...); ErrorParams fills its message.
	ErrorCode   string            `json:"error_code,omitempty"`
	ErrorParams map[string]string `json:"error_params,omitempty"`
	// LastError is the raw text of the last failure (admin route only).
	LastError     string  `json:"last_error,omitempty"`
	LastAttemptAt *string `json:"last_attempt_at,omitempty"`
	LastSuccessAt *string `json:"last_success_at,omitempty"`
	FailingSince  *string `json:"failing_since,omitempty"`
	NextRunAt     *string `json:"next_run_at,omitempty"`
	// CatalogRecords is the size of the stored catalog; RecordsChanged what
	// the last run wrote.
	CatalogRecords    int64   `json:"catalog_records"`
	RecordsChanged    int     `json:"records_changed"`
	DataAsOf          *string `json:"data_as_of,omitempty"`
	IntervalSeconds   int64   `json:"interval_seconds"`
	StaleAfterSeconds int64   `json:"stale_after_seconds"`
	// Detail is the bundle feed's own progress (vulnfeed only).
	Detail *BundleDetailResponse `json:"detail,omitempty"`
}

// BundleDetailResponse is the vulnerability bundle feed's progress.
type BundleDetailResponse struct {
	AppliedSequence uint64                 `json:"applied_sequence"`
	KeySetVersion   uint64                 `json:"keyset_version"`
	RootKeyID       string                 `json:"root_key_id,omitempty"`
	Kind            string                 `json:"kind,omitempty"`
	BundleCreatedAt *string                `json:"bundle_created_at,omitempty"`
	Sources         []BundleSourceResponse `json:"sources"`
}

// BundleSourceResponse is one upstream source named by the applied bundle.
type BundleSourceResponse struct {
	Name  string  `json:"name"`
	AsOf  *string `json:"as_of,omitempty"`
	Fresh bool    `json:"fresh"`
}

// TenantSyncStatusResponse is what an organization sees of a feed: its
// state and freshness, never an error text, a host or the bundle internals.
type TenantSyncStatusResponse struct {
	Source         string  `json:"source"`
	Enabled        bool    `json:"enabled"`
	State          string  `json:"state"`
	DataAsOf       *string `json:"data_as_of,omitempty"`
	LastSuccessAt  *string `json:"last_success_at,omitempty"`
	LastSyncAt     *string `json:"last_sync_at,omitempty"`
	LastSyncStatus string  `json:"last_sync_status"`
	RecordsSynced  int64   `json:"records_synced"`
	NextSyncAt     *string `json:"next_sync_at,omitempty"`
}

// TriggerResult is what a sync request did for one feed: status is
// queued, already_running or skipped (reason: disabled, not_configured,
// rate_limited).
type TriggerResult struct {
	Source string `json:"source"`
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
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

func fmtTime(t *time.Time) *string {
	if t == nil {
		return nil
	}
	f := t.UTC().Format("2006-01-02T15:04:05Z")
	return &f
}

func toSyncStatusResponse(v feedstatus.View) SyncStatusResponse {
	resp := SyncStatusResponse{
		Source: v.Source, Enabled: v.Enabled, State: string(v.State),
		ErrorCode: v.ErrorCode, ErrorParams: v.ErrorParams, LastError: v.LastError,
		LastAttemptAt: fmtTime(v.LastAttemptAt), LastSuccessAt: fmtTime(v.LastSuccessAt),
		FailingSince: fmtTime(v.FailingSince), NextRunAt: fmtTime(v.NextRunAt),
		CatalogRecords: v.CatalogRecords, RecordsChanged: v.RecordsChanged, DataAsOf: fmtTime(v.DataAsOf),
		IntervalSeconds: int64(v.Interval.Seconds()), StaleAfterSeconds: int64(v.StaleAfter.Seconds()),
	}
	if v.State == feedstatus.StateRunning || v.State == feedstatus.StateUpToDate {
		resp.LastError = ""
	}
	if b := v.Bundle; b != nil {
		d := &BundleDetailResponse{
			AppliedSequence: b.AppliedSequence, KeySetVersion: b.KeySetVersion, RootKeyID: b.RootKeyID,
			Kind: b.Kind, BundleCreatedAt: fmtTime(b.BundleCreatedAt), Sources: []BundleSourceResponse{},
		}
		for _, s := range b.Sources {
			d.Sources = append(d.Sources, BundleSourceResponse{Name: s.Name, AsOf: fmtTime(s.AsOf), Fresh: s.Fresh})
		}
		resp.Detail = d
	}
	return resp
}

func toTenantSyncStatusResponse(v feedstatus.View) TenantSyncStatusResponse {
	return TenantSyncStatusResponse{
		Source: v.Source, Enabled: v.Enabled, State: string(v.State),
		DataAsOf: fmtTime(v.DataAsOf), LastSuccessAt: fmtTime(v.LastSuccessAt),
		LastSyncAt: fmtTime(v.LastAttemptAt), LastSyncStatus: v.LastSyncStatus,
		RecordsSynced: v.CatalogRecords, NextSyncAt: fmtTime(v.NextRunAt),
	}
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
