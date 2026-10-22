package handler

// EASM monitoring settings and run-now (research/22 P0-11; owner decisions
// E3 and E8; docs/architecture/easm.md "Settings and run-now").

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	easmapp "github.com/openctemio/openctem/api/internal/app/easm"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/easmchange"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// EASMSettingsStore reads and writes the tenant's EASM settings
// (*tenant.TenantService).
type EASMSettingsStore interface {
	GetEASMSettings(ctx context.Context, tenantID string) (*tenant.EASMSettings, error)
	UpdateEASMSettings(ctx context.Context, tenantID string, es tenant.EASMSettings, actx auditapp.AuditContext) (*tenant.EASMSettings, error)
}

// EASMFreshness reports when the tenant's sweeps last ran and when run-now
// is allowed again (*postgres.EASMSweepRepository).
type EASMFreshness interface {
	Freshness(ctx context.Context, tenantID shared.ID) (lastCT, lastDNS *time.Time, err error)
	RunNowAvailableAt(ctx context.Context, tenantID shared.ID) (time.Time, error)
}

// EASMSweeper starts sweeps (*easm.SweepService).
type EASMSweeper interface {
	RunNow(ctx context.Context, tenantID shared.ID) (*easmapp.SweepTicket, time.Time, error)
}

// EASMPlatform is what the platform runs at all, and its default cadence.
type EASMPlatform struct {
	CTAvailable  bool
	DNSAvailable bool
	// EnrichmentAvailable: ASSET_ENRICHMENT_ENABLED.
	EnrichmentAvailable bool
	CTDefaultHrs        int
	DNSDefaultHrs       int
}

// EASMSettingsHandler serves /api/v1/easm/settings and /api/v1/easm/sweeps.
type EASMSettingsHandler struct {
	store     EASMSettingsStore
	freshness EASMFreshness
	sweeper   EASMSweeper
	platform  EASMPlatform
	audit     AttributionAuditor
	digests   EASMDigestHistory
	logger    *logger.Logger
}

// EASMDigestHistory says when the organization's last weekly digest went out.
type EASMDigestHistory interface {
	LastDigestAt(ctx context.Context, tenantID shared.ID) (*time.Time, error)
}

// SetDigests wires the weekly digest history (RFC-080).
func (h *EASMSettingsHandler) SetDigests(d EASMDigestHistory) *EASMSettingsHandler {
	h.digests = d
	return h
}

// NewEASMSettingsHandler creates the handler.
func NewEASMSettingsHandler(store EASMSettingsStore, freshness EASMFreshness, sweeper EASMSweeper,
	platform EASMPlatform, audit AttributionAuditor, log *logger.Logger,
) *EASMSettingsHandler {
	return &EASMSettingsHandler{store: store, freshness: freshness, sweeper: sweeper, platform: platform,
		audit: audit, logger: log.With("handler", "easm-settings")}
}

// EASMSettingsResponse is the organization's attack-surface monitoring.
type EASMSettingsResponse struct {
	// CTEnabled: the Certificate Transparency monitor runs for the
	// organization (its domain names are sent to crt.sh and Cert Spotter).
	CTEnabled bool `json:"ct_enabled"`
	// DNSChecksEnabled: dangling CNAME/NS, lame delegation and email posture.
	DNSChecksEnabled bool `json:"dns_checks_enabled"`
	// EnrichmentEnabled: new assets are enriched passively at once (DNS,
	// registration, network owner); nothing is sent to the hosts.
	EnrichmentEnabled bool `json:"enrichment_enabled"`
	// EnrichmentAvailable: false when the operator turned automatic
	// enrichment off for the whole platform.
	EnrichmentAvailable bool `json:"enrichment_available"`
	// CTIntervalHours / DNSIntervalHours: 0 = the platform default.
	CTIntervalHours  int `json:"ct_interval_hours"`
	DNSIntervalHours int `json:"dns_interval_hours"`
	// Effective cadence, platform defaults and floors.
	CTEffectiveIntervalHours  int `json:"ct_effective_interval_hours"`
	DNSEffectiveIntervalHours int `json:"dns_effective_interval_hours"`
	MinIntervalHours          int `json:"min_interval_hours"`
	MaxIntervalHours          int `json:"max_interval_hours"`
	// CTAvailable / DNSAvailable: false when the operator turned the part
	// off for the whole platform; the switch then has no effect.
	CTAvailable  bool `json:"ct_available"`
	DNSAvailable bool `json:"dns_available"`
	// Freshness.
	LastCTSweepAt     *time.Time `json:"last_ct_sweep_at,omitempty"`
	LastDNSCheckAt    *time.Time `json:"last_dns_check_at,omitempty"`
	RunNowAvailableAt *time.Time `json:"run_now_available_at,omitempty"`
	// LookalikeCTEnabled: lookalike candidates are looked up in crt.sh.
	LookalikeCTEnabled bool `json:"lookalike_ct_enabled"`
	// NetworkLookupsEnabled: network seeds are looked up in RIPEstat.
	NetworkLookupsEnabled bool `json:"network_lookups_enabled"`
	// WebScreenshotsEnabled: screenshots sent with web evidence are kept
	// (30 days); off by default.
	WebScreenshotsEnabled bool `json:"web_screenshots_enabled"`
	// WeeklyDigestEnabled: the weekly "what changed" digest goes out.
	WeeklyDigestEnabled bool `json:"weekly_digest_enabled"`
	// DigestWeekday is the UTC weekday of the digest, 1..7 = Monday..Sunday.
	DigestWeekday int `json:"digest_weekday"`
	// DigestHourUTC is the hour (UTC) the digest goes out.
	DigestHourUTC int `json:"digest_hour_utc"`
	// LastDigestAt is when the latest digest was recorded.
	LastDigestAt *time.Time `json:"last_digest_at,omitempty"`
}

// EASMSettingsUpdateRequest replaces the settings.
type EASMSettingsUpdateRequest struct {
	CTEnabled        bool `json:"ct_enabled"`
	DNSChecksEnabled bool `json:"dns_checks_enabled"`
	// EnrichmentEnabled: omitted keeps the stored value.
	EnrichmentEnabled *bool `json:"enrichment_enabled,omitempty"`
	// 0 = platform default; otherwise 6..168.
	CTIntervalHours  int `json:"ct_interval_hours"`
	DNSIntervalHours int `json:"dns_interval_hours"`
	// LookalikeCTEnabled omitted keeps it as it is.
	LookalikeCTEnabled *bool `json:"lookalike_ct_enabled,omitempty"`
	// NetworkLookupsEnabled omitted keeps it as it is.
	NetworkLookupsEnabled *bool `json:"network_lookups_enabled,omitempty"`
	// WebScreenshotsEnabled omitted keeps it as it is.
	WebScreenshotsEnabled *bool `json:"web_screenshots_enabled,omitempty"`
	// WeeklyDigestEnabled omitted keeps it as it is.
	WeeklyDigestEnabled *bool `json:"weekly_digest_enabled,omitempty"`
	// DigestWeekday omitted keeps it; 1..7 = Monday..Sunday.
	DigestWeekday *int `json:"digest_weekday,omitempty"`
}

func (h *EASMSettingsHandler) tenant(w http.ResponseWriter, r *http.Request) (shared.ID, bool) {
	id, err := shared.IDFromString(middleware.MustGetTenantID(r.Context()))
	if err != nil {
		apierror.Unauthorized("Invalid tenant ID").WriteJSON(w)
		return shared.ID{}, false
	}
	return id, true
}

func (h *EASMSettingsHandler) actx(r *http.Request) auditapp.AuditContext {
	ctx := r.Context()
	return auditapp.AuditContext{
		TenantID: middleware.MustGetTenantID(ctx), ActorID: middleware.GetUserID(ctx), ActorEmail: auditActorEmail(ctx),
		ActorIP: getClientIP(r), UserAgent: r.UserAgent(), RequestID: middleware.GetRequestID(r.Context()),
	}
}

func effective(hours, def int) int {
	if hours > 0 {
		return hours
	}
	return def
}

func (h *EASMSettingsHandler) respond(ctx context.Context, tenantID shared.ID, es tenant.EASMSettings) EASMSettingsResponse {
	out := EASMSettingsResponse{
		CTEnabled: !es.CTDisabled, DNSChecksEnabled: !es.DNSChecksDisabled,
		EnrichmentEnabled: !es.EnrichmentDisabled, EnrichmentAvailable: h.platform.EnrichmentAvailable,
		CTIntervalHours: es.CTIntervalHours, DNSIntervalHours: es.DNSIntervalHours,
		CTEffectiveIntervalHours:  effective(es.CTIntervalHours, h.platform.CTDefaultHrs),
		DNSEffectiveIntervalHours: effective(es.DNSIntervalHours, h.platform.DNSDefaultHrs),
		MinIntervalHours:          tenant.MinEASMIntervalHours, MaxIntervalHours: tenant.MaxEASMIntervalHours,
		CTAvailable: h.platform.CTAvailable, DNSAvailable: h.platform.DNSAvailable,
		LookalikeCTEnabled:    !es.LookalikeCTDisabled,
		WeeklyDigestEnabled:   !es.WeeklyDigestDisabled,
		DigestWeekday:         isoWeekday(easmchange.Weekday(es.DigestWeekday)),
		DigestHourUTC:         easmchange.DigestHourUTC,
		NetworkLookupsEnabled: !es.NetworkLookupsDisabled,
		WebScreenshotsEnabled: es.WebScreenshotsEnabled,
	}
	if h.digests != nil {
		if last, err := h.digests.LastDigestAt(ctx, tenantID); err == nil {
			out.LastDigestAt = last
		} else {
			h.logger.Warn("easm digest history unreadable", "error", logger.SanitizeError(err))
		}
	}
	if h.freshness != nil {
		if ct, dns, err := h.freshness.Freshness(ctx, tenantID); err == nil {
			out.LastCTSweepAt, out.LastDNSCheckAt = ct, dns
		} else {
			h.logger.Warn("easm freshness unreadable", "error", logger.SanitizeError(err))
		}
		if until, err := h.freshness.RunNowAvailableAt(ctx, tenantID); err == nil && !until.IsZero() {
			out.RunNowAvailableAt = &until
		}
	}
	return out
}

// Get handles GET /api/v1/easm/settings
// @Summary      Attack-surface monitoring settings
// @Description  Whether the Certificate Transparency monitor and the DNS-only checks run for the organization, their cadence (platform floor 6 h), and when each last ran.
// @Tags         Attack Surface
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  EASMSettingsResponse
// @Failure      401  {object}  apierror.Error
// @Router       /easm/settings [get]
func (h *EASMSettingsHandler) Get(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(w, r)
	if !ok {
		return
	}
	es, err := h.store.GetEASMSettings(r.Context(), tenantID.String())
	if err != nil {
		h.logger.Error("easm settings: read", "error", logger.SanitizeError(err))
		apierror.InternalServerError("failed to read the settings").WriteJSON(w)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(h.respond(r.Context(), tenantID, *es))
}

// Update handles PUT /api/v1/easm/settings
// @Summary      Change attack-surface monitoring settings
// @Description  Turn the Certificate Transparency monitor (sends the organization's domain names to crt.sh and Cert Spotter), the DNS-only checks or automatic passive enrichment of new assets off or on (enrichment_enabled omitted keeps it as it is), turn Certificate Transparency queries of lookalike candidates off or on (lookalike_ct_enabled, omitted keeps it), and set their interval in hours: 0 for the platform default, otherwise 6 to 168. Audited.
// @Description  Turn the Certificate Transparency monitor (sends the organization's domain names to crt.sh and Cert Spotter), the DNS-only checks or automatic passive enrichment of new assets off or on (enrichment_enabled omitted keeps it as it is), turn lookups of network seeds in RIPEstat off or on (network_lookups_enabled, omitted keeps it), and set their interval in hours: 0 for the platform default, otherwise 6 to 168. Audited.
// @Tags         Attack Surface
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body body EASMSettingsUpdateRequest true "Settings"
// @Success      200  {object}  EASMSettingsResponse
// @Failure      400  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Router       /easm/settings [put]
func (h *EASMSettingsHandler) Update(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(w, r)
	if !ok {
		return
	}
	limitBody(w, r)
	var req EASMSettingsUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	current, err := h.store.GetEASMSettings(r.Context(), tenantID.String())
	if err != nil {
		h.logger.Error("easm settings: read", "error", logger.SanitizeError(err))
		apierror.InternalServerError("failed to read the settings").WriteJSON(w)
		return
	}
	// Optional fields left out keep their current value.
	es := *current
	es.CTDisabled, es.DNSChecksDisabled = !req.CTEnabled, !req.DNSChecksEnabled
	es.CTIntervalHours, es.DNSIntervalHours = req.CTIntervalHours, req.DNSIntervalHours
	if req.EnrichmentEnabled != nil {
		es.EnrichmentDisabled = !*req.EnrichmentEnabled
	}
	if req.LookalikeCTEnabled != nil {
		es.LookalikeCTDisabled = !*req.LookalikeCTEnabled
	}
	if req.NetworkLookupsEnabled != nil {
		es.NetworkLookupsDisabled = !*req.NetworkLookupsEnabled
	}
	if req.WebScreenshotsEnabled != nil {
		es.WebScreenshotsEnabled = *req.WebScreenshotsEnabled
	}
	if req.WeeklyDigestEnabled != nil {
		es.WeeklyDigestDisabled = !*req.WeeklyDigestEnabled
	}
	if req.DigestWeekday != nil {
		if *req.DigestWeekday < 1 || *req.DigestWeekday > 7 {
			apierror.BadRequest("digest_weekday must be between 1 (Monday) and 7 (Sunday)").WriteJSON(w)
			return
		}
		es.DigestWeekday = *req.DigestWeekday
	}
	if err := es.Validate(); err != nil {
		apierror.BadRequest(easmValidationMessage(err)).WriteJSON(w)
		return
	}
	saved, err := h.store.UpdateEASMSettings(r.Context(), tenantID.String(), es, h.actx(r))
	if err != nil {
		switch {
		case errors.Is(err, shared.ErrValidation):
			apierror.BadRequest(easmValidationMessage(err)).WriteJSON(w)
		case errors.Is(err, shared.ErrConflict):
			apierror.Conflict("The settings changed meanwhile; reload and try again").WriteJSON(w)
		default:
			h.logger.Error("easm settings: write", "error", logger.SanitizeError(err))
			apierror.InternalServerError("failed to save the settings").WriteJSON(w)
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(h.respond(r.Context(), tenantID, *saved))
}

// RunNow handles POST /api/v1/easm/sweeps
// @Summary      Run discovery and DNS checks now
// @Description  Starts the Certificate Transparency monitor and then the DNS-only checks for the organization in the background (each only if it is on). At most once per 15 minutes per organization (429 with Retry-After). Audited.
// @Tags         Attack Surface
// @Produce      json
// @Security     BearerAuth
// @Success      202  {object}  easmapp.SweepTicket
// @Failure      429  {object}  apierror.Error
// @Router       /easm/sweeps [post]
func (h *EASMSettingsHandler) RunNow(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(w, r)
	if !ok {
		return
	}
	if h.sweeper == nil {
		apierror.NotFound("Sweep").WriteJSON(w)
		return
	}
	ticket, until, err := h.sweeper.RunNow(r.Context(), tenantID)
	if err != nil {
		if errors.Is(err, easmapp.ErrSweepTooSoon) {
			secs := int(time.Until(until).Seconds()) + 1
			if secs < 1 || until.IsZero() {
				secs = int(easmapp.RunNowInterval.Seconds())
			}
			w.Header().Set("Retry-After", strconv.Itoa(secs))
			apierror.TooManyRequests("A sweep ran less than 15 minutes ago; try again later").WriteJSON(w)
			return
		}
		h.logger.Error("easm sweep: run now", "error", logger.SanitizeError(err))
		apierror.InternalServerError("failed to start the sweep").WriteJSON(w)
		return
	}
	if h.audit != nil {
		_ = h.audit.LogEvent(r.Context(), h.actx(r),
			auditapp.NewSuccessEvent(auditdom.ActionEASMSweepRequested, auditdom.ResourceTypeTenant, tenantID.String()).
				WithMessage("Attack-surface sweep requested").
				WithMetadata("ct_included", ticket.CTIncluded).
				WithMetadata("dns_included", ticket.DNSIncluded))
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(ticket)
}

// isoWeekday maps a time.Weekday to ISO 8601 (1 = Monday .. 7 = Sunday).
func isoWeekday(d time.Weekday) int {
	if d == time.Sunday {
		return 7
	}
	return int(d)
}
