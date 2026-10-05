package handler

// The fleet read model (docs/rfcs/RFC-051-ci-runner-identity-and-gate.md,
// "Pipelines in the fleet"): one list of everything that scans for the
// tenant, by mode.
//
//   - daemon: sensors (one row in sensors; heartbeat liveness, can be
//     offline). Needs sensors:read.
//   - runner: CI pipelines (one workflow file of one repository; freshness
//     against its cadence, never offline, never dispatched). Needs
//     scans:ci:read and the scans module, and follows the caller's data
//     scope.
//
// Each mode is filtered by its own permission: a caller with one of them
// sees that mode only. Rows are tenant-scoped by their sources; this handler
// adds no query of its own.

import (
	"context"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Fleet modes, kinds and roles.
const (
	FleetModeDaemon     = "daemon"
	FleetModeRunner     = "runner"
	FleetModeAll        = "all"
	FleetKindSensor     = "sensor"
	FleetKindCIPipeline = "ci_pipeline"
	fleetRoleScanner    = "scanner"
	fleetRoleCollector  = "collector"
)

// FleetLinks point to the row's own resource.
type FleetLinks struct {
	Self string `json:"self"`
}

// FleetItem is one row of the fleet: the same shape for every mode.
type FleetItem struct {
	ID          string `json:"id"`
	Mode        string `json:"mode" enums:"daemon,runner"`
	Kind        string `json:"kind" enums:"sensor,ci_pipeline"`
	Role        string `json:"role" enums:"scanner,collector"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	// Status is the mode's own status: a sensor state for a daemon
	// (online, degraded, late, stale, offline, idle, never_connected,
	// disabled, revoked), a pipeline status for a runner (failing, degraded,
	// stale, running, fresh, never, archived, revoked). A runner is never
	// offline.
	Status string `json:"status"`
	// Attention: the row needs someone to look (offline/degraded/stale
	// daemon; failing/degraded/stale pipeline).
	Attention bool `json:"attention"`
	// Inactive rows (revoked or disabled daemons; archived, revoked or
	// never-run pipelines) are hidden unless include_inactive=true.
	Inactive   bool       `json:"inactive"`
	LastSeenAt *time.Time `json:"last_seen_at,omitempty"`
	Version    string     `json:"version,omitempty"`
	// Runner-only fields.
	Provider          string     `json:"provider,omitempty"`
	Repository        string     `json:"repository,omitempty"`
	RepositoryAssetID string     `json:"repository_asset_id,omitempty"`
	Workflow          string     `json:"workflow,omitempty"`
	Gate              string     `json:"gate,omitempty"`
	Freshness         string     `json:"freshness,omitempty"`
	Health            string     `json:"health,omitempty"`
	Links             FleetLinks `json:"links"`
}

// FleetModeCounts summarizes one mode (header counts; filters ignored).
type FleetModeCounts struct {
	Total     int            `json:"total"`
	Attention int            `json:"attention"`
	Inactive  int            `json:"inactive"`
	ByStatus  map[string]int `json:"by_status"`
}

// FleetListResponse is a page of the fleet. Modes lists the modes the
// caller may see; Counts has one entry per visible mode.
type FleetListResponse struct {
	ListResponse[FleetItem]
	Modes  []string                   `json:"modes"`
	Counts map[string]FleetModeCounts `json:"counts"`
}

// FleetDaemonSource lists the tenant's sensors as fleet rows.
type FleetDaemonSource interface {
	FleetDaemons(ctx context.Context, tenantID string) ([]FleetItem, error)
}

// FleetRunnerSource lists the tenant's CI pipelines as fleet rows, within
// the caller's data scope.
type FleetRunnerSource interface {
	FleetRunners(ctx context.Context, tenantID shared.ID) ([]FleetItem, error)
}

// FleetModuleCheck reports whether a module is enabled for the tenant.
type FleetModuleCheck func(ctx context.Context, tenantID, moduleID string) bool

// FleetHandler serves GET /api/v1/fleet.
type FleetHandler struct {
	daemons FleetDaemonSource
	runners FleetRunnerSource
	module  FleetModuleCheck
	logger  *logger.Logger
}

// NewFleetHandler creates the handler. A nil source leaves its mode empty;
// a nil module check treats every module as enabled.
func NewFleetHandler(d FleetDaemonSource, r FleetRunnerSource, module FleetModuleCheck, log *logger.Logger) *FleetHandler {
	return &FleetHandler{daemons: d, runners: r, module: module, logger: log.With("handler", "fleet")}
}

// MaxFleetPerPage bounds a fleet page.
const MaxFleetPerPage = 200

// List handles GET /api/v1/fleet
// @Summary      List the fleet
// @Description  Everything that scans for the organization in one list: sensors in daemon mode (heartbeat; can be offline; needs sensors:read) and CI pipelines in runner mode (freshness against their cadence; never offline, never dispatched; needs scans:ci:read and follows the data scope). Each mode is filtered by its own permission. Inactive rows are hidden unless include_inactive=true.
// @Tags         Sensors
// @Produce      json
// @Security     BearerAuth
// @Param        mode query string false "all (default), daemon or runner"
// @Param        role query string false "scanner or collector"
// @Param        status query string false "Comma-separated statuses of the modes listed"
// @Param        attention query bool false "Only rows that need attention"
// @Param        include_inactive query bool false "Also list inactive rows"
// @Param        search query string false "Name, repository or workflow"
// @Param        page query int false "Page (default 1)"
// @Param        per_page query int false "Per page (default 25, max 200)"
// @Success      200  {object}  FleetListResponse
// @Failure      400  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Router       /fleet [get]
func (h *FleetHandler) List(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenant := middleware.GetTenantID(ctx)
	tenantID, err := shared.IDFromString(tenant)
	if err != nil {
		apierror.Unauthorized("Invalid tenant ID").WriteJSON(w)
		return
	}
	q := r.URL.Query()
	mode := strings.TrimSpace(q.Get("mode"))
	if mode == "" {
		mode = FleetModeAll
	}
	if mode != FleetModeAll && mode != FleetModeDaemon && mode != FleetModeRunner {
		apierror.BadRequest("mode must be all, daemon or runner").WriteJSON(w)
		return
	}
	role := strings.TrimSpace(q.Get("role"))
	if role != "" && role != fleetRoleScanner && role != fleetRoleCollector {
		apierror.BadRequest("role must be scanner or collector").WriteJSON(w)
		return
	}

	canDaemon := h.daemons != nil && middleware.HasPermission(ctx, permission.SensorsRead.String())
	canRunner := h.runners != nil && middleware.HasPermission(ctx, permission.CIRead.String()) &&
		(h.module == nil || h.module(ctx, tenant, "scans"))
	switch {
	case mode == FleetModeDaemon && !canDaemon, mode == FleetModeRunner && !canRunner, !canDaemon && !canRunner:
		apierror.Forbidden("Insufficient permissions").WriteJSON(w)
		return
	}

	resp := FleetListResponse{Modes: []string{}, Counts: map[string]FleetModeCounts{}}
	var all []FleetItem
	if canDaemon {
		items, err := h.daemons.FleetDaemons(ctx, tenant)
		if err != nil {
			h.listFailed(w, "daemons", err)
			return
		}
		all = resp.addMode(FleetModeDaemon, items, mode != FleetModeRunner, all)
	}
	if canRunner {
		items, err := h.runners.FleetRunners(ctx, tenantID)
		if err != nil {
			h.listFailed(w, "runners", err)
			return
		}
		all = resp.addMode(FleetModeRunner, items, mode != FleetModeDaemon, all)
	}
	rows := newFleetFilter(q, role).apply(all)
	sortFleet(rows)

	page, _ := strconv.Atoi(q.Get("page"))
	perPage, _ := strconv.Atoi(q.Get("per_page"))
	if page < 1 {
		page = 1
	}
	if perPage < 1 || perPage > MaxFleetPerPage {
		perPage = 25
	}
	start := min((page-1)*perPage, len(rows))
	end := min(start+perPage, len(rows))
	pages := (len(rows) + perPage - 1) / perPage
	resp.ListResponse = ListResponse[FleetItem]{Data: append([]FleetItem{}, rows[start:end]...), Total: int64(len(rows)),
		Page: page, PerPage: perPage, TotalPages: pages, Links: NewPaginationLinks(r, page, perPage, pages)}
	w.Header().Set("Cache-Control", "no-store")
	ciWriteJSON(w, http.StatusOK, resp)
}

func (h *FleetHandler) listFailed(w http.ResponseWriter, what string, err error) {
	h.logger.Error("fleet: list "+what, "error", logger.SanitizeError(err))
	apierror.InternalServerError("failed to list the fleet").WriteJSON(w)
}

// addMode records a visible mode and its counts, and adds its rows when the
// requested mode lists them.
func (resp *FleetListResponse) addMode(mode string, items []FleetItem, listed bool, all []FleetItem) []FleetItem {
	resp.Modes = append(resp.Modes, mode)
	resp.Counts[mode] = countFleet(items)
	if listed {
		return append(all, items...)
	}
	return all
}

type fleetFilter struct {
	role            string
	statuses        map[string]bool
	search          string
	includeInactive bool
	attentionOnly   bool
}

func newFleetFilter(q url.Values, role string) fleetFilter {
	f := fleetFilter{role: role, statuses: map[string]bool{}, search: strings.ToLower(truncateQuery(q.Get("search"), 255)),
		includeInactive: q.Get("include_inactive") == queryParamTrue, attentionOnly: q.Get("attention") == queryParamTrue}
	for _, s := range strings.Split(q.Get("status"), ",") {
		if s = strings.TrimSpace(s); s != "" {
			f.statuses[s] = true
		}
	}
	return f
}

func (f fleetFilter) apply(all []FleetItem) []FleetItem {
	rows := make([]FleetItem, 0, len(all))
	for _, it := range all {
		switch {
		case f.role != "" && it.Role != f.role,
			len(f.statuses) > 0 && !f.statuses[it.Status],
			len(f.statuses) == 0 && !f.includeInactive && it.Inactive,
			f.attentionOnly && !it.Attention,
			f.search != "" && !strings.Contains(strings.ToLower(it.Name+" "+it.Repository+" "+it.Workflow+" "+it.Description), f.search):
			continue
		}
		rows = append(rows, it)
	}
	return rows
}

// sortFleet puts rows that need attention first and inactive rows last,
// then orders by name.
func sortFleet(rows []FleetItem) {
	slices.SortStableFunc(rows, func(a, b FleetItem) int {
		if a.Attention != b.Attention {
			if a.Attention {
				return -1
			}
			return 1
		}
		if a.Inactive != b.Inactive {
			if b.Inactive {
				return -1
			}
			return 1
		}
		if c := strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name)); c != 0 {
			return c
		}
		return strings.Compare(a.ID, b.ID)
	})
}

func countFleet(items []FleetItem) FleetModeCounts {
	c := FleetModeCounts{Total: len(items), ByStatus: map[string]int{}}
	for _, it := range items {
		c.ByStatus[it.Status]++
		if it.Attention {
			c.Attention++
		}
		if it.Inactive {
			c.Inactive++
		}
	}
	return c
}

// truncateQuery trims a free-text query parameter and caps it (rune-safe).
func truncateQuery(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) <= max {
		return s
	}
	s = s[:max]
	for !utf8.ValidString(s) && s != "" {
		s = s[:len(s)-1]
	}
	return s
}
