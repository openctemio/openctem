package handler

import (
	"net/http"

	"github.com/openctemio/openctem/api/internal/app/scanidentity"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/scanident"
)

// ScanIdentificationHeader is one header of the platform layer.
type ScanIdentificationHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	// Enforced: no organization, bug-bounty program or sensor-local layer
	// replaces it.
	Enforced bool `json:"enforced"`
}

// ScanIdentificationResponse is the platform layer of the scan
// identification markers.
type ScanIdentificationResponse struct {
	UserAgent         string                     `json:"user_agent"`
	UserAgentEnforced bool                       `json:"user_agent_enforced"`
	Headers           []ScanIdentificationHeader `json:"headers"`
	MaxHeaders        int                        `json:"max_headers"`
	Stored            bool                       `json:"stored"`
	Version           int                        `json:"version"`
	SettingChange
}

// UpdateScanIdentificationRequest replaces the platform layer.
type UpdateScanIdentificationRequest struct {
	UserAgent         string                     `json:"user_agent"`
	UserAgentEnforced bool                       `json:"user_agent_enforced"`
	Headers           []ScanIdentificationHeader `json:"headers"`
	Reason            string                     `json:"reason"`
	Version           int                        `json:"version"`
}

func (h *AdminPlatformSettingsHandler) scanIdentificationResponse(r *http.Request, s scanidentity.Settings) ScanIdentificationResponse {
	out := ScanIdentificationResponse{UserAgent: s.Layer.UserAgent, UserAgentEnforced: s.Layer.UserAgentEnforced,
		Headers: make([]ScanIdentificationHeader, 0, len(s.Layer.Headers)), MaxHeaders: scanident.MaxPlatformHeaders,
		Stored: s.Stored, Version: s.Version, SettingChange: h.change(r.Context(), s.UpdatedAt, s.UpdatedBy)}
	for _, hd := range s.Layer.Headers {
		out.Headers = append(out.Headers, ScanIdentificationHeader{Name: hd.Name, Value: hd.Value, Enforced: hd.Enforced})
	}
	return out
}

// GetScanIdentification returns the platform layer of the scan
// identification markers.
// @Summary      Get the platform scan identification
// @Description  The User-Agent and request headers every organization's scan jobs carry, each optionally enforced; organizations add their own headers over them. Any administrator.
// @Tags         Admin System
// @Produce      json
// @Success      200  {object}  ScanIdentificationResponse
// @Security     AdminAuth
// @Router       /admin/settings/scan-identification [get]
func (h *AdminPlatformSettingsHandler) GetScanIdentification(w http.ResponseWriter, r *http.Request) {
	s, err := h.ScanIdentity.Get(r.Context())
	if err != nil {
		h.writeSettingError(w, "scan identification", err)
		return
	}
	writeJSON(w, http.StatusOK, h.scanIdentificationResponse(r, s))
}

// UpdateScanIdentification replaces the platform layer of the scan
// identification markers.
// @Summary      Change the platform scan identification
// @Description  Step-up and a reason. Header names are HTTP tokens (at most 64 characters, case-insensitive, no duplicates), values printable ASCII (at most 200 characters), at most 4 headers; connection, proxy and credential headers are refused. Applies to jobs delivered from then on, within seconds on every replica. Audited; every administrator is notified.
// @Tags         Admin System
// @Accept       json
// @Produce      json
// @Param        request  body      UpdateScanIdentificationRequest  true  "Layer"
// @Success      200  {object}  ScanIdentificationResponse
// @Security     AdminAuth
// @Router       /admin/settings/scan-identification [put]
func (h *AdminPlatformSettingsHandler) UpdateScanIdentification(w http.ResponseWriter, r *http.Request) {
	actor := requireActor(w, r)
	if actor == nil {
		return
	}
	var req UpdateScanIdentificationRequest
	if !decodeSetting(w, r, &req) {
		return
	}
	layer := scanident.PlatformLayer{UserAgent: req.UserAgent, UserAgentEnforced: req.UserAgentEnforced}
	for _, hd := range req.Headers {
		layer.Headers = append(layer.Headers, scanident.Header{Name: hd.Name, Value: hd.Value, Enforced: hd.Enforced})
	}
	s, err := h.ScanIdentity.Update(r.Context(), actor, layer, req.Reason, req.Version, middleware.ClientIP(r), r.UserAgent())
	if err != nil {
		h.writeSettingError(w, "scan identification", err)
		return
	}
	writeJSON(w, http.StatusOK, h.scanIdentificationResponse(r, s))
}
