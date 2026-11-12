package handler

import (
	"net/http"

	"github.com/openctemio/contract/identity"

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
	UserAgent string `json:"user_agent"`
	// UserAgents is a rotation list (instead of user_agent).
	UserAgents []string `json:"user_agents"`
	// UserAgentEnforced locks the User-Agent or the list.
	UserAgentEnforced bool                       `json:"user_agent_enforced"`
	Headers           []ScanIdentificationHeader `json:"headers"`
	Query             *scanident.Query           `json:"query,omitempty"`
	QueryEnforced     bool                       `json:"query_enforced"`
	// IdentificationRequired: every organization's scan requests must carry
	// a header or the query parameter.
	IdentificationRequired bool `json:"identification_required"`
	MaxHeaders             int  `json:"max_headers"`
	MaxUserAgents          int  `json:"max_user_agents"`
	Stored                 bool `json:"stored"`
	Version                int  `json:"version"`
	SettingChange
}

// UpdateScanIdentificationRequest replaces the platform layer.
type UpdateScanIdentificationRequest struct {
	UserAgent              string                     `json:"user_agent"`
	UserAgents             []string                   `json:"user_agents"`
	UserAgentEnforced      bool                       `json:"user_agent_enforced"`
	Headers                []ScanIdentificationHeader `json:"headers"`
	Query                  *scanident.Query           `json:"query"`
	QueryEnforced          bool                       `json:"query_enforced"`
	IdentificationRequired bool                       `json:"identification_required"`
	Reason                 string                     `json:"reason"`
	Version                int                        `json:"version"`
}

func (h *AdminPlatformSettingsHandler) scanIdentificationResponse(r *http.Request, s scanidentity.Settings) ScanIdentificationResponse {
	out := ScanIdentificationResponse{UserAgent: s.Layer.UserAgent, UserAgents: nonNilStrings(s.Layer.UserAgents),
		UserAgentEnforced: s.Layer.UserAgentEnforced, Query: s.Layer.Query, QueryEnforced: s.Layer.QueryEnforced,
		IdentificationRequired: s.Layer.IdentificationRequired,
		Headers:                make([]ScanIdentificationHeader, 0, len(s.Layer.Headers)), MaxHeaders: scanident.MaxPlatformHeaders,
		MaxUserAgents: identity.MaxUserAgents,
		Stored:        s.Stored, Version: s.Version, SettingChange: h.change(r.Context(), s.UpdatedAt, s.UpdatedBy)}
	for _, hd := range s.Layer.Headers {
		out.Headers = append(out.Headers, ScanIdentificationHeader{Name: hd.Name, Value: hd.Value, Enforced: hd.Enforced})
	}
	return out
}

// GetScanIdentification returns the platform layer of the scan
// identification markers.
// @Summary      Get the platform scan identification
// @Description  The User-Agent (one value or a rotation list), request headers and query parameter every organization's scan jobs carry, each optionally enforced, and whether identification is required; organizations add their own over them. Any administrator.
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
// @Description  Step-up and a reason. Header names are HTTP tokens (at most 64 characters, case-insensitive, no duplicates), values printable ASCII (at most 200 characters), at most 4 headers; connection, proxy and credential headers are refused. A User-Agent or a rotation list (at most 200 distinct values of 1-256 printable ASCII characters), never both. The query parameter's name and value are 1-64 of letters, digits and . _ ~ -. identification_required makes every organization's jobs carry a header or the query parameter on every request (a job without either fails with IDENTIFICATION_REQUIRED_MISSING; only sensors that report http.identity.required@1 get such jobs). Applies to jobs delivered from then on, within seconds on every replica. Audited with the previous and new values; every administrator is notified.
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
	layer := scanident.PlatformLayer{UserAgent: req.UserAgent, UserAgents: req.UserAgents, UserAgentEnforced: req.UserAgentEnforced,
		Query: req.Query, QueryEnforced: req.QueryEnforced, IdentificationRequired: req.IdentificationRequired}
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
