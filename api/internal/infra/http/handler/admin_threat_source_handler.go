package handler

import (
	"context"
	"net/http"
	"time"

	"github.com/openctemio/openctem/api/internal/app/threat"
	"github.com/openctemio/openctem/api/internal/app/threatsource"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
)

// ThreatIntelReadiness reports the signed release's state per feed
// (*threat.IntelService).
type ThreatIntelReadiness interface {
	BundleReadiness(ctx context.Context) []threat.BundleReadiness
}

// ThreatSourceFeed is how the signed release is doing for one feed.
type ThreatSourceFeed struct {
	// Source: kev or epss.
	Source string `json:"source"`
	// DeliveredVia: bundle or direct, the path that stored the data held
	// (empty before any).
	DeliveredVia string `json:"delivered_via,omitempty"`
	// DataAsOf: the data date of the data held.
	DataAsOf string `json:"data_as_of,omitempty"`
	// BundleFetchedAt: when the collector last read the source, as the
	// release says (empty: no release carried the feed yet).
	BundleFetchedAt string `json:"bundle_fetched_at,omitempty"`
	// BundleFresh: the release's copy is within the feed's stale threshold
	// (KEV 6 hours, EPSS 48 hours).
	BundleFresh bool `json:"bundle_fresh"`
	// BundleError: a code-free reason the last release copy was refused.
	BundleError string `json:"bundle_error,omitempty"`
}

// ThreatSourceResponse is where KEV and EPSS come from.
type ThreatSourceResponse struct {
	// Source: direct (the platform's own fetch supplies the feeds, the
	// release is applied when newer) or bundle (the release supplies them,
	// the direct fetch is a fallback when the release's copy is stale).
	Source string `json:"source"`
	// DirectFetch: auto (the platform may call CISA and FIRST) or off
	// (strict egress: it never does).
	DirectFetch string             `json:"direct_fetch"`
	Stored      bool               `json:"stored"`
	Version     int                `json:"version"`
	Feeds       []ThreatSourceFeed `json:"feeds"`
	SettingChange
}

// UpdateThreatSourceRequest changes the setting.
type UpdateThreatSourceRequest struct {
	Source      string `json:"source"`
	DirectFetch string `json:"direct_fetch"`
	Version     int    `json:"version"`
}

func fmtFeedTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func (h *AdminPlatformSettingsHandler) threatSourceResponse(ctx context.Context, s threatsource.Settings) ThreatSourceResponse {
	out := ThreatSourceResponse{Source: s.Source, DirectFetch: s.DirectFetch, Stored: s.Stored, Version: s.Version,
		Feeds: []ThreatSourceFeed{}, SettingChange: h.change(ctx, s.UpdatedAt, s.UpdatedBy)}
	if h.ThreatReadiness != nil {
		for _, r := range h.ThreatReadiness.BundleReadiness(ctx) {
			out.Feeds = append(out.Feeds, ThreatSourceFeed{Source: r.Source, DeliveredVia: r.DeliveredVia, DataAsOf: fmtFeedTime(r.DataAsOf),
				BundleFetchedAt: fmtFeedTime(r.BundleFetchedAt), BundleFresh: r.Fresh, BundleError: r.BundleError})
		}
	}
	return out
}

// GetThreatSource returns where KEV and EPSS come from.
// @Summary      Get the threat intelligence source
// @Description  Whether the platform's own fetch or the signed vulnerability release supplies CISA KEV and EPSS, whether the platform may call CISA and FIRST at all, and per feed how the release's copy is doing (the check to make before switching to the release). Any administrator.
// @Tags         Admin System
// @Produce      json
// @Success      200  {object}  ThreatSourceResponse
// @Security     AdminAuth
// @Router       /admin/settings/threat-intel-source [get]
func (h *AdminPlatformSettingsHandler) GetThreatSource(w http.ResponseWriter, r *http.Request) {
	s, err := h.ThreatSource.Get(r.Context())
	if err != nil {
		h.writeSettingError(w, "threat intelligence source", err)
		return
	}
	writeJSON(w, http.StatusOK, h.threatSourceResponse(r.Context(), s))
}

// UpdateThreatSource changes where KEV and EPSS come from.
// @Summary      Change the threat intelligence source
// @Description  Super admin with a step-up. "bundle" makes the signed release the supplier and the platform's own fetch a fallback for a stale copy; "direct_fetch off" forbids calling CISA and FIRST (strict-egress installs). Applies within seconds on every replica. Audited.
// @Tags         Admin System
// @Accept       json
// @Produce      json
// @Param        request  body      UpdateThreatSourceRequest  true  "Source"
// @Success      200  {object}  ThreatSourceResponse
// @Security     AdminAuth
// @Router       /admin/settings/threat-intel-source [put]
func (h *AdminPlatformSettingsHandler) UpdateThreatSource(w http.ResponseWriter, r *http.Request) {
	actor := requireActor(w, r)
	if actor == nil {
		return
	}
	var req UpdateThreatSourceRequest
	if !decodeSetting(w, r, &req) {
		return
	}
	s, err := h.ThreatSource.Update(r.Context(), actor, req.Source, req.DirectFetch, req.Version, middleware.ClientIP(r), r.UserAgent())
	if err != nil {
		h.writeSettingError(w, "threat intelligence source", err)
		return
	}
	writeJSON(w, http.StatusOK, h.threatSourceResponse(r.Context(), s))
}
