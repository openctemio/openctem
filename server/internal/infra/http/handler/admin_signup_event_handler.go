package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	signupeventapp "github.com/openctemio/openctem/api/internal/app/signupevent"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	dom "github.com/openctemio/openctem/api/pkg/domain/signupevent"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

const stepUpPurposeSignupAlerts = "sign-up burst thresholds change"

// AdminSignupEventHandler serves Console > Customers > Sign-ups: the sign-up
// feed (accounts, organizations and access requests, as email domain and
// network prefix only), its daily counts and the burst alert thresholds
// (docs/architecture/signup-activity.md).
type AdminSignupEventHandler struct {
	svc    *signupeventapp.Service
	stepUp StepUpVerifier
	logger *logger.Logger
}

// NewAdminSignupEventHandler creates the handler.
func NewAdminSignupEventHandler(svc *signupeventapp.Service, stepUp StepUpVerifier, log *logger.Logger) *AdminSignupEventHandler {
	return &AdminSignupEventHandler{svc: svc, stepUp: stepUp, logger: log.With("handler", "admin_signup_events")}
}

// SignupEventResponse is one event of the feed. It names an email domain and
// a client network prefix, never a person.
type SignupEventResponse struct {
	ID          int64   `json:"id"`
	Kind        string  `json:"kind"`
	Source      string  `json:"source"`
	EmailDomain string  `json:"email_domain,omitempty"`
	IPPrefix    string  `json:"ip_prefix,omitempty"`
	TenantID    *string `json:"tenant_id,omitempty"`
	OccurredAt  string  `json:"occurred_at"`
}

// SignupEventListResponse is a page of the feed, newest first.
type SignupEventListResponse struct {
	Data       []SignupEventResponse `json:"data"`
	Total      int64                 `json:"total"`
	Page       int                   `json:"page"`
	PerPage    int                   `json:"per_page"`
	TotalPages int                   `json:"total_pages"`
}

// SignupDailyCountResponse is the number of events of one kind on one UTC day.
type SignupDailyCountResponse struct {
	Day   string `json:"day"`
	Kind  string `json:"kind"`
	Count int64  `json:"count"`
}

// SignupBurstThresholdsResponse are the burst alert thresholds.
type SignupBurstThresholdsResponse struct {
	PerIPPrefix    int      `json:"per_ip_prefix"`
	PerEmailDomain int      `json:"per_email_domain"`
	WindowMinutes  int      `json:"window_minutes"`
	IgnoredDomains []string `json:"ignored_domains"`
	// Version to send back on PUT (0: nothing stored, the defaults apply).
	Version int `json:"version"`
}

// UpdateSignupBurstThresholdsRequest changes the thresholds.
type UpdateSignupBurstThresholdsRequest struct {
	PerIPPrefix    int      `json:"per_ip_prefix"`
	PerEmailDomain int      `json:"per_email_domain"`
	WindowMinutes  int      `json:"window_minutes"`
	IgnoredDomains []string `json:"ignored_domains"`
	Version        int      `json:"version"`
	Reason         string   `json:"reason"`
	// TOTPCode is a fresh code from the administrator's authenticator.
	TOTPCode string `json:"totp_code"`
}

func toSignupEventResponse(r dom.Record) SignupEventResponse {
	out := SignupEventResponse{ID: r.ID, Kind: string(r.Kind), Source: string(r.Source),
		EmailDomain: r.EmailDomain, IPPrefix: r.IPPrefix, OccurredAt: r.OccurredAt.UTC().Format(time.RFC3339)}
	if r.TenantID != nil {
		id := r.TenantID.String()
		out.TenantID = &id
	}
	return out
}

// List returns the sign-up feed.
// @Summary      List sign-up events
// @Description  The sign-up feed, newest first: accounts created, organizations created and access requests submitted, as email domain and client network prefix only. Kept 90 days. Any administrator.
// @Tags         Admin System
// @Produce      json
// @Param        kind      query     string  false  "account_created, organization_created or access_requested"
// @Param        page      query     int     false  "Page"
// @Param        per_page  query     int     false  "Per page (max 100)"
// @Success      200  {object}  SignupEventListResponse
// @Router       /admin/signup-events [get]
func (h *AdminSignupEventHandler) List(w http.ResponseWriter, r *http.Request) {
	kind := dom.Kind(strings.TrimSpace(r.URL.Query().Get("kind")))
	if kind != "" && !kind.Valid() {
		apierror.BadRequest("kind must be account_created, organization_created or access_requested").WriteJSON(w)
		return
	}
	page, ok := listPageMax(w, r, 50, signupeventapp.MaxListLimit)
	if !ok {
		return
	}
	items, total, err := h.svc.List(r.Context(), dom.Filter{Kind: kind, Limit: page.Limit(), Offset: page.Offset()})
	if err != nil {
		h.logger.Error("list sign-up events", "error", logger.SanitizeError(err))
		apierror.InternalServerError("could not list sign-up events").WriteJSON(w)
		return
	}
	result := pagination.NewResult(items, total, page)
	resp := SignupEventListResponse{Data: make([]SignupEventResponse, 0, len(items)),
		Total: result.Total, Page: result.Page, PerPage: result.PerPage, TotalPages: result.TotalPages}
	for _, e := range items {
		resp.Data = append(resp.Data, toSignupEventResponse(e))
	}
	writeJSON(w, http.StatusOK, resp)
}

// Daily returns the events per kind per UTC day.
// @Summary      Daily sign-up counts
// @Description  Events per kind per UTC day for the last `days` days (1-90, default 30). Any administrator.
// @Tags         Admin System
// @Produce      json
// @Param        days  query     int  false  "Days (1-90)"
// @Success      200  {array}  SignupDailyCountResponse
// @Router       /admin/signup-events/daily [get]
func (h *AdminSignupEventHandler) Daily(w http.ResponseWriter, r *http.Request) {
	days := 30
	if v := strings.TrimSpace(r.URL.Query().Get("days")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > signupeventapp.MaxDays {
			apierror.BadRequest("days must be between 1 and 90").WriteJSON(w)
			return
		}
		days = n
	}
	counts, err := h.svc.Daily(r.Context(), days)
	if err != nil {
		h.logger.Error("daily sign-up counts", "error", logger.SanitizeError(err))
		apierror.InternalServerError("could not count sign-up events").WriteJSON(w)
		return
	}
	out := make([]SignupDailyCountResponse, 0, len(counts))
	for _, c := range counts {
		out = append(out, SignupDailyCountResponse{Day: c.Day.UTC().Format("2006-01-02"), Kind: string(c.Kind), Count: c.Count})
	}
	writeJSON(w, http.StatusOK, out)
}

func toThresholdsResponse(t dom.BurstThresholds, version int) SignupBurstThresholdsResponse {
	ignored := t.IgnoredDomains
	if ignored == nil {
		ignored = []string{}
	}
	return SignupBurstThresholdsResponse{PerIPPrefix: t.PerIPPrefix, PerEmailDomain: t.PerEmailDomain,
		WindowMinutes: t.WindowMinutes, IgnoredDomains: ignored, Version: version}
}

// GetThresholds returns the burst alert thresholds.
// @Summary      Get the sign-up burst thresholds
// @Description  How many events of one kind from one network prefix or one email domain within the window raise an alert (0: off). Any administrator.
// @Tags         Admin System
// @Produce      json
// @Success      200  {object}  SignupBurstThresholdsResponse
// @Router       /admin/settings/signup-alerts [get]
func (h *AdminSignupEventHandler) GetThresholds(w http.ResponseWriter, r *http.Request) {
	t, v, err := h.svc.Thresholds(r.Context())
	if err != nil {
		h.logger.Error("read sign-up burst thresholds", "error", logger.SanitizeError(err))
		apierror.InternalServerError("could not read the sign-up alert thresholds").WriteJSON(w)
		return
	}
	writeJSON(w, http.StatusOK, toThresholdsResponse(t, v))
}

// UpdateThresholds changes the burst alert thresholds. Super admin, a reason
// and a fresh authenticator code; audited (critical), administrators emailed.
// @Summary      Change the sign-up burst thresholds
// @Description  Super admin with a reason and a fresh authenticator code. Sends the version read (409 when it moved on). Audited; administrators are emailed.
// @Tags         Admin System
// @Accept       json
// @Produce      json
// @Param        request  body      UpdateSignupBurstThresholdsRequest  true  "Thresholds"
// @Success      200  {object}  SignupBurstThresholdsResponse
// @Router       /admin/settings/signup-alerts [put]
func (h *AdminSignupEventHandler) UpdateThresholds(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetAdminUser(r.Context())
	if actor == nil {
		apierror.Unauthorized("administrator session required").WriteJSON(w)
		return
	}
	var req UpdateSignupBurstThresholdsRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	t := dom.BurstThresholds{PerIPPrefix: req.PerIPPrefix, PerEmailDomain: req.PerEmailDomain,
		WindowMinutes: req.WindowMinutes, IgnoredDomains: req.IgnoredDomains}.Normalize()
	// Refused before the authenticator code is spent.
	if err := t.Validate(); err != nil {
		apierror.BadRequest(strings.TrimPrefix(err.Error(), shared.ErrValidation.Error()+": ")).WriteJSON(w)
		return
	}
	if strings.TrimSpace(req.Reason) == "" {
		apierror.BadRequest("a reason is required").WriteJSON(w)
		return
	}
	if !confirmAdminStepUp(w, r, h.stepUp, req.TOTPCode, stepUpPurposeSignupAlerts, h.logger) {
		return
	}
	saved, v, err := h.svc.UpdateThresholds(r.Context(), t, req.Version, signupeventapp.Change{
		Actor: actor, Reason: req.Reason, IP: middleware.ClientIP(r), UserAgent: r.UserAgent()})
	if err != nil {
		switch {
		case errors.Is(err, dom.ErrVersionConflict):
			apierror.Conflict("The thresholds were changed by someone else; reload and try again").WriteJSON(w)
		case errors.Is(err, shared.ErrValidation):
			apierror.BadRequest(strings.TrimPrefix(err.Error(), shared.ErrValidation.Error()+": ")).WriteJSON(w)
		default:
			h.logger.Error("update sign-up burst thresholds", "error", logger.SanitizeError(err))
			apierror.InternalServerError("could not save the sign-up alert thresholds").WriteJSON(w)
		}
		return
	}
	writeJSON(w, http.StatusOK, toThresholdsResponse(saved, v))
}
