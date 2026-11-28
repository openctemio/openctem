package handler

// Vulnerability feed address (console System > Threat intelligence): the
// release URL and the mirrors the signed vulnerability feed is fetched from.
// The pinned root key id and the bundle directory are shown, never changed
// here. Design: docs/architecture/feed-transfer.md ("Feed sources in the
// console").

import (
	"errors"
	"net/http"

	"github.com/openctemio/openctem/server/internal/app/vulnfeed"
	"github.com/openctemio/openctem/server/internal/app/vulnfeedsources"
	"github.com/openctemio/openctem/server/internal/infra/http/middleware"
	"github.com/openctemio/openctem/server/pkg/apierror"
)

// Error codes of the feed address test.
const (
	// CodeFeedTestUnavailable: the platform makes no outbound request for
	// the feed (relay mode or a bundle directory); details.reason says which.
	CodeFeedTestUnavailable apierror.Code = "FEED_TEST_UNAVAILABLE"
)

// VulnFeedSourcesResponse is the feed address setting.
type VulnFeedSourcesResponse struct {
	// BaseURL is the release base URL in force; Mirrors are tried after it
	// in direct mode only (relay sensors fetch the release URL).
	BaseURL string   `json:"base_url"`
	Mirrors []string `json:"mirrors"`
	// DefaultBaseURL and DefaultMirrors are the server's values (environment
	// or built-in), used while the console stores nothing.
	DefaultBaseURL string   `json:"default_base_url"`
	DefaultMirrors []string `json:"default_mirrors"`
	// Source: default, environment or console.
	Source              string   `json:"source"`
	LockedByEnvironment bool     `json:"locked_by_environment"`
	EnvVars             []string `json:"env_vars"`
	MaxMirrors          int      `json:"max_mirrors"`
	// RootOfficial: the pinned root is the official feed's; otherwise a
	// custom root set on the server. RootKeyID is its public fingerprint.
	// Never changed in the console.
	RootOfficial bool   `json:"root_official"`
	RootKeyID    string `json:"root_key_id"`
	// BundleDirSet: the server reads the feed from a local directory (its
	// path is never returned). Never changed in the console.
	BundleDirSet bool `json:"bundle_dir_set"`
	Version      int  `json:"version"`
	SettingChange
}

// UpdateVulnFeedSourcesRequest changes the feed address.
type UpdateVulnFeedSourcesRequest struct {
	BaseURL string   `json:"base_url"`
	Mirrors []string `json:"mirrors"`
	Reason  string   `json:"reason"`
	Version int      `json:"version"`
}

// TestVulnFeedSourcesRequest names the addresses to test (empty base_url:
// the addresses in force).
type TestVulnFeedSourcesRequest struct {
	BaseURL string   `json:"base_url,omitempty"`
	Mirrors []string `json:"mirrors,omitempty"`
}

// TestVulnFeedSourcesResponse is the outcome per address.
type TestVulnFeedSourcesResponse struct {
	Results []vulnfeed.ProbeResult `json:"results"`
}

func (h *AdminPlatformSettingsHandler) vulnFeedSourcesResponse(r *http.Request, s vulnfeedsources.Settings) VulnFeedSourcesResponse {
	return VulnFeedSourcesResponse{BaseURL: s.BaseURL, Mirrors: s.Mirrors, DefaultBaseURL: s.DefaultBaseURL,
		DefaultMirrors: s.DefaultMirrors, Source: s.Source, LockedByEnvironment: s.LockedByEnvironment,
		EnvVars: []string{vulnfeedsources.EnvBaseURL, vulnfeedsources.EnvMirrors}, MaxMirrors: vulnfeedsources.MaxMirrors,
		RootOfficial: s.RootOfficial, RootKeyID: s.RootKeyID, BundleDirSet: s.BundleDirSet, Version: s.Version,
		SettingChange: h.change(r.Context(), s.UpdatedAt, s.UpdatedBy)}
}

// GetVulnFeedSources returns the vulnerability feed address.
// @Summary      Get the vulnerability feed address
// @Description  The release URL and mirrors the signed vulnerability feed is fetched from, where they come from (default, environment or console), whether the server pins them, and, read only, whether the pinned root is the official one (with its key fingerprint) and whether a bundle directory is set (never its path). Any administrator.
// @Tags         Admin System
// @Produce      json
// @Success      200  {object}  VulnFeedSourcesResponse
// @Security     AdminAuth
// @Router       /admin/settings/vulnfeed-sources [get]
func (h *AdminPlatformSettingsHandler) GetVulnFeedSources(w http.ResponseWriter, r *http.Request) {
	s, err := h.VulnFeedSources.Get(r.Context())
	if err != nil {
		h.writeSettingError(w, "vulnerability feed address", err)
		return
	}
	writeJSON(w, http.StatusOK, h.vulnFeedSourcesResponse(r, s))
}

// UpdateVulnFeedSources changes the vulnerability feed address.
// @Summary      Change the vulnerability feed address
// @Description  Replaces the release URL and the mirrors (https only, no credentials, query or fragment, no internal address, at most 5 mirrors). Platform owner permission (platform.settings.feed_sources), a fresh step-up and a reason. Refused (409 SETTING_LOCKED_BY_ENVIRONMENT) while VULNFEED_BASE_URL or VULNFEED_MIRRORS is set on the server. Applies at the next import or relay round without a restart; every file is still verified against the pinned root. Audited critical with the old and new values; every administrator is told.
// @Tags         Admin System
// @Accept       json
// @Produce      json
// @Param        request  body      UpdateVulnFeedSourcesRequest  true  "Addresses"
// @Success      200  {object}  VulnFeedSourcesResponse
// @Failure      400  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Security     AdminAuth
// @Router       /admin/settings/vulnfeed-sources [put]
func (h *AdminPlatformSettingsHandler) UpdateVulnFeedSources(w http.ResponseWriter, r *http.Request) {
	actor := requireActor(w, r)
	if actor == nil {
		return
	}
	var req UpdateVulnFeedSourcesRequest
	if !decodeSetting(w, r, &req) {
		return
	}
	s, err := h.VulnFeedSources.Update(r.Context(), actor, vulnfeedsources.Input{BaseURL: req.BaseURL, Mirrors: req.Mirrors,
		Reason: req.Reason, Version: req.Version}, middleware.ClientIP(r), r.UserAgent())
	if err != nil {
		h.writeSettingError(w, "vulnerability feed address", err)
		return
	}
	writeJSON(w, http.StatusOK, h.vulnFeedSourcesResponse(r, s))
}

// TestVulnFeedSources fetches and verifies the newest signed pointer.
// @Summary      Test the vulnerability feed address
// @Description  Fetches the key set and the newest signed pointer from the release URL and each mirror (the ones given, else the ones in force) with the platform's guarded feed client, and verifies them against the pinned root. Imports nothing. Each address answers verified or one code (blocked_address, not_verified, not_configured): the precise cause is logged on the server, never returned. Every test is in the admin audit (platform.vulnfeed_sources_tested). Refused (409 FEED_TEST_UNAVAILABLE) in relay mode or with a bundle directory, where the platform makes no outbound request. Platform owner permission (platform.settings.feed_sources); a few per minute per administrator.
// @Tags         Admin System
// @Accept       json
// @Produce      json
// @Param        request  body      TestVulnFeedSourcesRequest  true  "Addresses"
// @Success      200  {object}  TestVulnFeedSourcesResponse
// @Failure      400  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error "FEED_TEST_UNAVAILABLE"
// @Failure      429  {object}  apierror.Error
// @Security     AdminAuth
// @Router       /admin/settings/vulnfeed-sources/test [post]
func (h *AdminPlatformSettingsHandler) TestVulnFeedSources(w http.ResponseWriter, r *http.Request) {
	actor := requireActor(w, r)
	if actor == nil {
		return
	}
	var req TestVulnFeedSourcesRequest
	if !decodeSetting(w, r, &req) {
		return
	}
	res, err := h.VulnFeedSources.Test(r.Context(), actor, req.BaseURL, req.Mirrors, middleware.ClientIP(r), r.UserAgent())
	switch {
	case errors.Is(err, vulnfeedsources.ErrRelayMode):
		apierror.New(http.StatusConflict, CodeFeedTestUnavailable, "Feeds come through the relay sensors, so the platform does not fetch them itself").
			WithDetails(map[string]any{formReason: "relay_mode"}).WriteJSON(w)
		return
	case errors.Is(err, vulnfeedsources.ErrBundleDir):
		apierror.New(http.StatusConflict, CodeFeedTestUnavailable, "The server reads the feed from a local bundle directory").
			WithDetails(map[string]any{formReason: "bundle_dir"}).WriteJSON(w)
		return
	case errors.Is(err, vulnfeedsources.ErrNotConfigured):
		apierror.New(http.StatusConflict, CodeFeedTestUnavailable, "The vulnerability feed import is not available on this server").
			WithDetails(map[string]any{formReason: "not_configured"}).WriteJSON(w)
		return
	case err != nil:
		h.writeSettingError(w, "vulnerability feed address", err)
		return
	}
	writeJSON(w, http.StatusOK, TestVulnFeedSourcesResponse{Results: res})
}
