package handler

// Web page monitoring (docs/rfcs/RFC-138-web-page-monitoring.md).

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	pagemonapp "github.com/openctemio/openctem/api/internal/app/pagemon"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/pagemon"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// PageMonitor is the page monitoring service as the handler needs it.
type PageMonitor interface {
	ListWatches(ctx context.Context, tenantID shared.ID) ([]pagemon.Watch, error)
	CreateWatch(ctx context.Context, tenantID shared.ID, actor *shared.ID, in pagemonapp.WatchInput) (*pagemon.Watch, error)
	UpdateWatch(ctx context.Context, tenantID shared.ID, id string, in pagemonapp.WatchUpdate) (*pagemon.Watch, error)
	DeleteWatch(ctx context.Context, tenantID shared.ID, id string) (*pagemon.Watch, error)
	Suggestions(ctx context.Context, tenantID shared.ID) ([]pagemon.Suggestion, error)
	ListChanges(ctx context.Context, tenantID shared.ID, f pagemon.ChangeFilter) ([]pagemon.Change, int, error)
	GetChange(ctx context.Context, tenantID shared.ID, id string) (*pagemon.Change, error)
}

// PageMonitorHandler serves /api/v1/easm/page-monitoring.
type PageMonitorHandler struct {
	svc    PageMonitor
	audit  AttributionAuditor
	logger *logger.Logger
}

// NewPageMonitorHandler creates the handler.
func NewPageMonitorHandler(svc PageMonitor, audit AttributionAuditor, log *logger.Logger) *PageMonitorHandler {
	return &PageMonitorHandler{svc: svc, audit: audit, logger: log.With("handler", "page-monitoring")}
}

// PageWatchList lists the watches.
type PageWatchList struct {
	Items []pagemon.Watch `json:"items"`
	Max   int             `json:"max"`
}

// PageWatchRequest creates or changes a watch.
type PageWatchRequest struct {
	URL            string   `json:"url,omitempty"`    // create only
	Source         string   `json:"source,omitempty"` // create only: manual or suggested
	Enabled        *bool    `json:"enabled,omitempty"`
	Mode           string   `json:"mode,omitempty"`
	CadenceHours   int      `json:"cadence_hours,omitempty"`
	IgnorePatterns []string `json:"ignore_patterns"`
}

// PageSuggestionList lists suggested URLs.
type PageSuggestionList struct {
	Items []pagemon.Suggestion `json:"items"`
}

// PageChangeList lists changes.
type PageChangeList struct {
	Items []pagemon.Change `json:"items"`
	Total int              `json:"total"`
}

func (h *PageMonitorHandler) tenant(w http.ResponseWriter, r *http.Request) (shared.ID, bool) {
	id, err := shared.IDFromString(middleware.MustGetTenantID(r.Context()))
	if err != nil {
		apierror.Unauthorized("Invalid tenant ID").WriteJSON(w)
		return shared.ID{}, false
	}
	return id, true
}

func (h *PageMonitorHandler) auditEvent(r *http.Request, action auditdom.Action, wt *pagemon.Watch, msg string) {
	if h.audit == nil || wt == nil {
		return
	}
	ctx := r.Context()
	ev := auditapp.NewSuccessEvent(action, auditdom.ResourceTypeWebWatch, wt.ID.String()).WithResourceName(wt.URL).WithMessage(msg).
		WithMetadata("mode", string(wt.Mode)).WithMetadata("asset_id", wt.AssetID.String())
	auditapp.RecordOrWarn(ctx, h.logger, h.audit, auditapp.AuditContext{
		TenantID: middleware.MustGetTenantID(ctx), ActorID: middleware.GetUserID(ctx), ActorEmail: auditActorEmail(ctx),
		ActorIP: getClientIP(r), UserAgent: r.UserAgent(), RequestID: middleware.GetRequestID(ctx),
	}, ev)
}

func (h *PageMonitorHandler) writeErr(w http.ResponseWriter, err error, what string) {
	switch {
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(easmValidationMessage(err)).WriteJSON(w)
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Watch").WriteJSON(w)
	case errors.Is(err, shared.ErrConflict):
		apierror.Conflict("The URL is watched already, or the organization watches the maximum number of URLs").WriteJSON(w)
	default:
		h.logger.Error("page monitoring: "+what, "error", logger.SanitizeError(err))
		apierror.InternalServerError("failed to " + what).WriteJSON(w)
	}
}

// ListWatches handles GET /api/v1/easm/page-monitoring/watches
// @Summary      Monitored web pages and scripts
// @Description  The organization's watched URLs whose web service is in the caller's data scope: mode (js = the scripts a page loads; full = also its visible text), cadence, state of the last fetch, and the page's first-party scripts the platform watches with it (source derived, parent_id set).
// @Tags         Attack Surface
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  PageWatchList
// @Router       /easm/page-monitoring/watches [get]
func (h *PageMonitorHandler) ListWatches(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(w, r)
	if !ok {
		return
	}
	items, err := h.svc.ListWatches(r.Context(), tenantID)
	if err != nil {
		h.writeErr(w, err, "list watches")
		return
	}
	writeJSON(w, http.StatusOK, PageWatchList{Items: items, Max: pagemon.MaxWatchesPerTenant})
}

// CreateWatch handles POST /api/v1/easm/page-monitoring/watches
// @Summary      Watch a web page or script
// @Description  The URL's origin must be a web service (http_service asset) of the organization in the caller's data scope. mode js (default) or full; cadence_hours 6 to 168 (default 24); at most 10 ignore patterns (RE2, 200 bytes each). Every fetch passes the scope and active-scan gates. At most 200 watches. Audited.
// @Tags         Attack Surface
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body body PageWatchRequest true "Watch"
// @Success      201  {object}  pagemon.Watch
// @Failure      400  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Router       /easm/page-monitoring/watches [post]
func (h *PageMonitorHandler) CreateWatch(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(w, r)
	if !ok {
		return
	}
	limitBody(w, r)
	var req PageWatchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	var actor *shared.ID
	if uid, err := shared.IDFromString(middleware.GetUserID(r.Context())); err == nil {
		actor = &uid
	}
	wt, err := h.svc.CreateWatch(r.Context(), tenantID, actor, pagemonapp.WatchInput{
		URL: req.URL, Mode: req.Mode, CadenceHours: req.CadenceHours, IgnorePatterns: req.IgnorePatterns, Source: req.Source,
	})
	if err != nil {
		h.writeErr(w, err, "add the watch")
		return
	}
	h.auditEvent(r, auditdom.ActionWebWatchAdded, wt, "Page monitoring watch added")
	writeJSON(w, http.StatusCreated, wt)
}

// UpdateWatch handles PUT /api/v1/easm/page-monitoring/watches/{id}
// @Summary      Change a page monitoring watch
// @Description  Turn the watch off or on, change its mode, cadence or ignore patterns. Clears the dynamic mark and makes the watch due now. A derived script watch is changed through its page. Audited.
// @Tags         Attack Surface
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        id   path  string  true  "Watch ID"
// @Param        body body PageWatchRequest true "Settings"
// @Success      200  {object}  pagemon.Watch
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Router       /easm/page-monitoring/watches/{id} [put]
func (h *PageMonitorHandler) UpdateWatch(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(w, r)
	if !ok {
		return
	}
	limitBody(w, r)
	var req PageWatchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	wt, err := h.svc.UpdateWatch(r.Context(), tenantID, r.PathValue("id"), pagemonapp.WatchUpdate{
		Enabled: req.Enabled, Mode: req.Mode, CadenceHours: req.CadenceHours, IgnorePatterns: req.IgnorePatterns,
	})
	if err != nil {
		h.writeErr(w, err, "change the watch")
		return
	}
	h.auditEvent(r, auditdom.ActionWebWatchUpdated, wt, "Page monitoring watch changed")
	writeJSON(w, http.StatusOK, wt)
}

// DeleteWatch handles DELETE /api/v1/easm/page-monitoring/watches/{id}
// @Summary      Stop watching a URL
// @Description  Deletes the watch with its derived script watches, snapshots and changes. Audited.
// @Tags         Attack Surface
// @Security     BearerAuth
// @Param        id   path  string  true  "Watch ID"
// @Success      204
// @Failure      404  {object}  apierror.Error
// @Router       /easm/page-monitoring/watches/{id} [delete]
func (h *PageMonitorHandler) DeleteWatch(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(w, r)
	if !ok {
		return
	}
	wt, err := h.svc.DeleteWatch(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		h.writeErr(w, err, "remove the watch")
		return
	}
	h.auditEvent(r, auditdom.ActionWebWatchDeleted, wt, "Page monitoring watch removed")
	w.WriteHeader(http.StatusNoContent)
}

// Suggestions handles GET /api/v1/easm/page-monitoring/suggestions
// @Summary      URLs worth watching
// @Description  Unwatched URLs of web services in the caller's data scope: each service's root page, login pages, admin pages and JS files the crawl found (at most 100).
// @Tags         Attack Surface
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  PageSuggestionList
// @Router       /easm/page-monitoring/suggestions [get]
func (h *PageMonitorHandler) Suggestions(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(w, r)
	if !ok {
		return
	}
	items, err := h.svc.Suggestions(r.Context(), tenantID)
	if err != nil {
		h.writeErr(w, err, "list suggestions")
		return
	}
	writeJSON(w, http.StatusOK, PageSuggestionList{Items: items})
}

// ListChanges handles GET /api/v1/easm/page-monitoring/changes
// @Summary      Page changes
// @Description  Detected changes of watched URLs in the caller's data scope, newest first: scripts added and removed, new third-party script hosts, changed JS files, new URLs in JS, text lines (full mode). Muted changes (a dynamic watch) only with muted=true.
// @Tags         Attack Surface
// @Produce      json
// @Security     BearerAuth
// @Param        watch_id     query  string  false  "Only this watch and its derived scripts"
// @Param        min_severity query  string  false  "info, low, medium or high"
// @Param        muted        query  bool    false  "Include muted changes"
// @Param        page         query  int     false  "Page (from 1)"
// @Param        per_page     query  int     false  "1 to 100 (default 50)"
// @Success      200  {object}  PageChangeList
// @Failure      400  {object}  apierror.Error
// @Router       /easm/page-monitoring/changes [get]
func (h *PageMonitorHandler) ListChanges(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	f := pagemon.ChangeFilter{MinSeverity: pagemon.Severity(q.Get("min_severity")), IncludeMute: q.Get("muted") == "true"}
	if v := q.Get("watch_id"); v != "" {
		id, err := shared.IDFromString(v)
		if err != nil {
			apierror.BadRequest("invalid watch_id").WriteJSON(w)
			return
		}
		f.WatchID = &id
	}
	page, ok := listPageMax(w, r, 50, 100)
	if !ok {
		return
	}
	f.Limit, f.Offset = page.Limit(), page.Offset()
	items, total, err := h.svc.ListChanges(r.Context(), tenantID, f)
	if err != nil {
		h.writeErr(w, err, "list changes")
		return
	}
	writeJSON(w, http.StatusOK, PageChangeList{Items: items, Total: total})
}

// GetChange handles GET /api/v1/easm/page-monitoring/changes/{id}
// @Summary      One page change with its diff
// @Description  The change's diff (each list at most 100 items, text at most 200 lines each way). Values come from the fetched page: render them as text. 404 outside the caller's data scope.
// @Tags         Attack Surface
// @Produce      json
// @Security     BearerAuth
// @Param        id   path  string  true  "Change ID"
// @Success      200  {object}  pagemon.Change
// @Failure      404  {object}  apierror.Error
// @Router       /easm/page-monitoring/changes/{id} [get]
func (h *PageMonitorHandler) GetChange(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(w, r)
	if !ok {
		return
	}
	c, err := h.svc.GetChange(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			apierror.NotFound("Change").WriteJSON(w)
			return
		}
		h.writeErr(w, err, "read the change")
		return
	}
	writeJSON(w, http.StatusOK, c)
}
