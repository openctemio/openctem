package handler

import (
	"net/http"
	"time"

	"github.com/openctemio/openctem/server/internal/app/feedwatch"
	"github.com/openctemio/openctem/server/pkg/apierror"
)

// Freshness of the platform's vulnerability data (internal/app/feedwatch).

// SetFreshness wires the freshness watch (nil: the routes answer "not
// stale" with no dates, as before the watch existed).
func (h *ThreatIntelHandler) SetFreshness(w *feedwatch.Service) *ThreatIntelHandler {
	h.freshness = w
	return h
}

// FreshnessResponse is what every signed-in user's console reads to show
// the stale-data banner and the "data as of" line.
type FreshnessResponse struct {
	// Stale: vulnerability data is older than its limit, so new
	// vulnerabilities may be missing (the banner shows).
	Stale bool `json:"stale"`
	// Reasons are stable codes: data_stale, newest_record_old,
	// check_not_running.
	Reasons []string `json:"reasons"`
	// StaleSince is the date of the oldest out-of-date data (absent: never
	// loaded or unknown).
	StaleSince *string `json:"stale_since,omitempty"`
	// DataAsOf is when the vulnerability data held was published.
	DataAsOf *string `json:"data_as_of,omitempty"`
	// CheckedAt is when the platform last checked.
	CheckedAt *string `json:"checked_at,omitempty"`
}

// FreshnessConditionResponse is one open condition (platform admin route).
type FreshnessConditionResponse struct {
	Key    string  `json:"key"`
	Code   string  `json:"code"`
	Source string  `json:"source,omitempty"`
	Banner bool    `json:"banner"`
	AsOf   *string `json:"as_of,omitempty"`
	Since  string  `json:"since"`
	Detail string  `json:"detail"`
}

// AdminFreshnessResponse adds the open conditions with their details.
type AdminFreshnessResponse struct {
	FreshnessResponse
	Conditions []FreshnessConditionResponse `json:"conditions"`
}

// GetFreshness answers whether the platform's vulnerability data is current.
// GET /api/v1/threat-intel/freshness
// @Summary      Vulnerability data freshness (banner)
// @Description  Whether the platform-wide vulnerability data is older than its limit, since when, and when it was published. Any signed-in user: it carries no organization data, only the state of the platform's feeds, so every user can be told that new vulnerabilities may be missing.
// @Tags         Threat Intelligence
// @Produce      json
// @Success      200  {object}  FreshnessResponse
// @Security     BearerAuth
// @Router       /threat-intel/freshness [get]
func (h *ThreatIntelHandler) GetFreshness(w http.ResponseWriter, r *http.Request) {
	b, ok := h.readBanner(w, r)
	if !ok {
		return
	}
	writeJSONResponse(w, http.StatusOK, toFreshnessResponse(b))
}

// GetFreshnessAdmin is the same with the open conditions and their details.
// GET /api/v1/admin/threat-intel/freshness
// @Summary      Vulnerability data freshness with conditions (platform admin)
// @Description  The banner state and every open freshness condition (stale data, failing or refused imports, newest record age, daily CVE count) with a plain explanation. Any admin.
// @Tags         Admin Threat Intelligence
// @Produce      json
// @Success      200  {object}  AdminFreshnessResponse
// @Security     BearerAuth
// @Router       /admin/threat-intel/freshness [get]
func (h *ThreatIntelHandler) GetFreshnessAdmin(w http.ResponseWriter, r *http.Request) {
	b, ok := h.readBanner(w, r)
	if !ok {
		return
	}
	out := AdminFreshnessResponse{FreshnessResponse: toFreshnessResponse(b), Conditions: []FreshnessConditionResponse{}}
	if h.freshness != nil {
		open, err := h.freshness.Open(r.Context())
		if err != nil {
			h.logger.Error("feed freshness: read conditions", "error", err)
			apierror.InternalServerError("freshness not available").WriteJSON(w)
			return
		}
		for _, c := range open {
			since := c.Since.UTC().Format(time.RFC3339)
			out.Conditions = append(out.Conditions, FreshnessConditionResponse{Key: c.Key, Code: c.Code, Source: c.Source,
				Banner: c.Banner, AsOf: fmtTime(c.AsOf), Since: since, Detail: c.Detail})
		}
	}
	writeJSONResponse(w, http.StatusOK, out)
}

func (h *ThreatIntelHandler) readBanner(w http.ResponseWriter, r *http.Request) (feedwatch.Banner, bool) {
	if h.freshness == nil {
		return feedwatch.Banner{}, true
	}
	b, err := h.freshness.Banner(r.Context())
	if err != nil {
		h.logger.Error("feed freshness: read banner", "error", err)
		apierror.InternalServerError("freshness not available").WriteJSON(w)
		return feedwatch.Banner{}, false
	}
	return b, true
}

func toFreshnessResponse(b feedwatch.Banner) FreshnessResponse {
	reasons := b.Codes
	if reasons == nil {
		reasons = []string{}
	}
	return FreshnessResponse{Stale: b.Stale, Reasons: reasons, StaleSince: fmtTime(b.StaleSince),
		DataAsOf: fmtTime(b.DataAsOf), CheckedAt: fmtTime(b.CheckedAt)}
}
