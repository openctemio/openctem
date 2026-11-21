package handler

// Private network destinations (console System > Private network
// destinations): the private ranges the platform's outbound requests may
// reach, beside the ranges set on the server. Design:
// docs/architecture/outbound-requests.md.

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/openctemio/openctem/server/internal/app/privatedestinations"
	"github.com/openctemio/openctem/server/internal/infra/http/middleware"
	"github.com/openctemio/openctem/server/pkg/apierror"
	"github.com/openctemio/openctem/server/pkg/httpsec"
)

// Error codes of the private destinations setting.
const (
	// CodePrivateRangeInvalid: one range of the list is refused; details
	// name its index (0-based), the range and the reason.
	CodePrivateRangeInvalid apierror.Code = "PRIVATE_RANGE_INVALID"
	// CodePrivateRangeOpenSignup: SIGNUP_MODE=open; no range can be opened.
	CodePrivateRangeOpenSignup apierror.Code = "PRIVATE_RANGE_OPEN_SIGNUP"
	// CodeDestinationNotHost: the test input is not a bare host name.
	CodeDestinationNotHost apierror.Code = "DESTINATION_NOT_A_HOST"
	// CodeDestinationNotFound: the test host has no address.
	CodeDestinationNotFound apierror.Code = "DESTINATION_NOT_FOUND"
)

// PrivateRange is one opened range.
type PrivateRange struct {
	CIDR string `json:"cidr"`
	Note string `json:"note,omitempty"`
	// Wide: wider than /24 (IPv4) or /64 (IPv6); the console asks for a
	// second look.
	Wide bool `json:"wide"`
}

// PrivateDestinationsResponse is the setting.
type PrivateDestinationsResponse struct {
	// ServerRanges are set on the server (OPENCTEM_HTTPSEC_ALLOW_PRIVATE_CIDRS)
	// and read only here.
	ServerRanges []PrivateRange `json:"server_ranges"`
	// Ranges are the console's.
	Ranges []PrivateRange `json:"ranges"`
	// InForce are the console ranges the answering server applies now (every
	// server applies a change within refresh_seconds).
	InForce        []string `json:"in_force"`
	RefreshSeconds int      `json:"refresh_seconds"`
	// AllPrivateOpen: the development-only switch opens every private range.
	AllPrivateOpen bool `json:"all_private_open"`
	// SignupOpen: SIGNUP_MODE=open lets anyone create an organization; no
	// range can be opened.
	SignupOpen bool `json:"signup_open"`
	MaxRanges  int  `json:"max_ranges"`
	Version    int  `json:"version"`
	SettingChange
}

// PrivateRangeInput is one range of a change.
type PrivateRangeInput struct {
	CIDR string `json:"cidr"`
	Note string `json:"note,omitempty"`
}

// UpdatePrivateDestinationsRequest replaces the console ranges.
type UpdatePrivateDestinationsRequest struct {
	Ranges  []PrivateRangeInput `json:"ranges"`
	Reason  string              `json:"reason"`
	Version int                 `json:"version"`
}

// TestDestinationRequest names the host to check.
type TestDestinationRequest struct {
	// Host is a host name or an IP address: no scheme, port or path.
	Host string `json:"host"`
}

// DestinationAddress is the decision for one resolved address.
type DestinationAddress struct {
	Address string `json:"address"`
	// Verdict: allowed (public), allowed_private (an opened range),
	// blocked_private (no range opens it), hard_blocked (never reachable).
	Verdict string `json:"verdict"`
	// OpenedBy and Source (server or console): the range that opens it.
	OpenedBy string `json:"opened_by,omitempty"`
	Source   string `json:"source,omitempty"`
	// AllPrivateOpen: opened by the development-only switch.
	AllPrivateOpen bool `json:"all_private_open,omitempty"`
	// Suggested: the /24 (or /64) that would open it (blocked_private).
	Suggested string `json:"suggested,omitempty"`
	// HardBlock: why it is never reachable (loopback, link_local,
	// cloud_metadata, shared_address_space, unspecified, multicast,
	// broadcast, reserved, embedded_ipv4).
	HardBlock string `json:"hard_block,omitempty"`
}

// TestDestinationResponse is how the platform treats one host.
type TestDestinationResponse struct {
	Host string `json:"host"`
	// NameBlocked: the name itself is never reachable (localhost, the cloud
	// metadata names); it was not resolved.
	NameBlocked bool                 `json:"name_blocked"`
	Addresses   []DestinationAddress `json:"addresses"`
}

func privateRanges(in []privatedestinations.RangeView) []PrivateRange {
	out := make([]PrivateRange, 0, len(in))
	for _, r := range in {
		out = append(out, PrivateRange{CIDR: r.CIDR, Note: r.Note, Wide: r.Wide})
	}
	return out
}

func (h *AdminPlatformSettingsHandler) privateDestinationsResponse(r *http.Request, v privatedestinations.View) PrivateDestinationsResponse {
	inForce := v.InForce
	if inForce == nil {
		inForce = []string{}
	}
	return PrivateDestinationsResponse{ServerRanges: privateRanges(v.Server), Ranges: privateRanges(v.Console),
		InForce: inForce, RefreshSeconds: int(privatedestinations.RefreshInterval.Seconds()),
		AllPrivateOpen: v.AllPrivateOpen, SignupOpen: v.SignupOpen, MaxRanges: httpsec.MaxConsolePrivateRanges, Version: v.Meta.Version,
		SettingChange: h.change(r.Context(), v.Meta.UpdatedAt, v.Meta.UpdatedBy)}
}

// GetPrivateDestinations returns the private network destinations.
// @Summary      Get the private network destinations
// @Description  The private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7) the platform's outbound requests (webhooks, integrations, CI issuers, mail relays) may reach: the ranges set on the server (read only) and the console's, with what the answering server applies now. Any administrator.
// @Tags         Admin System
// @Produce      json
// @Success      200  {object}  PrivateDestinationsResponse
// @Security     AdminAuth
// @Router       /admin/settings/private-destinations [get]
func (h *AdminPlatformSettingsHandler) GetPrivateDestinations(w http.ResponseWriter, r *http.Request) {
	v, err := h.PrivateDestinations.Get(r.Context())
	if err != nil {
		h.writeSettingError(w, "private network destinations", err)
		return
	}
	writeJSON(w, http.StatusOK, h.privateDestinationsResponse(r, v))
}

// UpdatePrivateDestinations replaces the console's private ranges.
// @Summary      Change the private network destinations
// @Description  Replaces the console's private ranges (at most 32, each inside a private range, IPv6 /48 or narrower; loopback, link-local and cloud metadata addresses stay blocked whatever is listed). Opens the platform's own network to every organization: platform owner permission (platform.settings.network), a fresh step-up and a reason. Applied at once on the answering server and within refresh_seconds on the others. Audited critical with the old and new lists; every administrator is told.
// @Tags         Admin System
// @Accept       json
// @Produce      json
// @Param        request  body      UpdatePrivateDestinationsRequest  true  "Ranges"
// @Success      200  {object}  PrivateDestinationsResponse
// @Failure      400  {object}  apierror.Error "PRIVATE_RANGE_INVALID (details: index, range, reason) or a missing reason"
// @Failure      409  {object}  apierror.Error "a stale version, or PRIVATE_RANGE_OPEN_SIGNUP (SIGNUP_MODE=open)"
// @Security     AdminAuth
// @Router       /admin/settings/private-destinations [put]
func (h *AdminPlatformSettingsHandler) UpdatePrivateDestinations(w http.ResponseWriter, r *http.Request) {
	actor := requireActor(w, r)
	if actor == nil {
		return
	}
	var req UpdatePrivateDestinationsRequest
	if !decodeSetting(w, r, &req) {
		return
	}
	entries := make([]privatedestinations.Entry, 0, len(req.Ranges))
	for _, e := range req.Ranges {
		entries = append(entries, privatedestinations.Entry{CIDR: e.CIDR, Note: e.Note})
	}
	v, err := h.PrivateDestinations.Update(r.Context(), actor, entries, req.Reason, req.Version, middleware.ClientIP(r), r.UserAgent())
	if err != nil {
		if writePrivateRangeError(w, err) {
			return
		}
		h.writeSettingError(w, "private network destinations", err)
		return
	}
	writeJSON(w, http.StatusOK, h.privateDestinationsResponse(r, v))
}

// privateRangeReasons are the reason codes of a refused range.
var privateRangeReasons = []struct {
	err     error
	code    string
	message string
}{
	{httpsec.ErrRangeNotCIDR, "not_cidr", "is not a CIDR range such as 10.20.0.0/16"},
	{httpsec.ErrRangeNotPrivate, "not_private", "is not inside a private range (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7)"},
	{httpsec.ErrRangeTooWide, "too_wide", "is wider than /48; list the IPv6 site or subnet the platform must reach"},
	{httpsec.ErrRangeHardBlocked, "never_reachable", "lies inside a range that is never reachable (cloud metadata)"},
	{httpsec.ErrRangeDuplicate, "duplicate", "is listed twice"},
	{httpsec.ErrRangeNoteTooLong, "note_too_long", "has a note longer than 100 characters"},
	{httpsec.ErrRangeNoteNotPlain, "note_not_plain", "has a note that is not plain text on one line"},
}

// writePrivateRangeError answers a refused range list; false when err is
// not one.
func writePrivateRangeError(w http.ResponseWriter, err error) bool {
	if errors.Is(err, privatedestinations.ErrOpenSignup) {
		apierror.New(http.StatusConflict, CodePrivateRangeOpenSignup,
			"Private ranges cannot be opened while anyone may create an organization (SIGNUP_MODE=open)").WriteJSON(w)
		return true
	}
	if errors.Is(err, httpsec.ErrTooManyRanges) {
		apierror.New(http.StatusBadRequest, CodePrivateRangeInvalid, "At most 32 ranges can be listed").
			WithDetails(map[string]any{formReason: "too_many"}).WriteJSON(w)
		return true
	}
	var re *httpsec.RangeError
	if !errors.As(err, &re) {
		return false
	}
	code, message := "invalid", "is refused"
	for _, p := range privateRangeReasons {
		if errors.Is(re.Err, p.err) {
			code, message = p.code, p.message
			break
		}
	}
	apierror.New(http.StatusBadRequest, CodePrivateRangeInvalid, "The range on line "+strconv.Itoa(re.Index+1)+" "+message).
		WithDetails(map[string]any{"index": re.Index, "range": re.Range, formReason: code}).WriteJSON(w)
	return true
}

// TestPrivateDestination reports how the platform treats one host.
// @Summary      Test a destination
// @Description  Resolves a host name (or reads an IP address) and reports, for each address, whether the platform's outbound requests may reach it: allowed, allowed by an opened private range (which, and where it is set), blocked as private (the range that would open it), or never reachable (and why). It only resolves: the platform never connects to the host. Platform owner permission (platform.settings.network); a few per minute per administrator.
// @Tags         Admin System
// @Accept       json
// @Produce      json
// @Param        request  body      TestDestinationRequest  true  "Host"
// @Success      200  {object}  TestDestinationResponse
// @Failure      400  {object}  apierror.Error "DESTINATION_NOT_A_HOST"
// @Failure      404  {object}  apierror.Error "DESTINATION_NOT_FOUND"
// @Failure      429  {object}  apierror.Error
// @Security     AdminAuth
// @Router       /admin/settings/private-destinations/test [post]
func (h *AdminPlatformSettingsHandler) TestPrivateDestination(w http.ResponseWriter, r *http.Request) {
	var req TestDestinationRequest
	if !decodeSetting(w, r, &req) {
		return
	}
	rep, err := h.PrivateDestinations.Inspect(r.Context(), req.Host)
	switch {
	case errors.Is(err, httpsec.ErrNotAHostName):
		apierror.New(http.StatusBadRequest, CodeDestinationNotHost,
			"Enter a host name or an IP address, without scheme, port or path").WriteJSON(w)
		return
	case errors.Is(err, httpsec.ErrHostNotFound):
		apierror.New(http.StatusNotFound, CodeDestinationNotFound, "The host name does not resolve from the platform").WriteJSON(w)
		return
	case err != nil:
		h.logger.Error("test private destination failed", "error", err)
		apierror.InternalServerError("could not test the destination").WriteJSON(w)
		return
	}
	out := TestDestinationResponse{Host: rep.Host, NameBlocked: rep.NameBlocked, Addresses: make([]DestinationAddress, 0, len(rep.Addresses))}
	for _, a := range rep.Addresses {
		out.Addresses = append(out.Addresses, DestinationAddress{Address: a.Address, Verdict: a.Verdict, OpenedBy: a.OpenedBy,
			Source: string(a.Source), AllPrivateOpen: a.AllPrivateOpen, Suggested: a.Suggested, HardBlock: string(a.HardBlock)})
	}
	writeJSON(w, http.StatusOK, out)
}
