package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"

	"github.com/openctemio/openctem/api/pkg/logger"
)

// DashboardOverviewParts are the reads the CTEM dashboard shows, by the exact
// URL the web asks for each one. The overview answers them in one response
// (research/81: the dashboard sent twelve requests on every load).
var DashboardOverviewParts = []string{ //nolint:gochecknoglobals // fixed allowlist
	"/api/v1/me/dashboards",
	"/api/v1/dashboard/risk-trend?days=90",
	"/api/v1/dashboard/executive-summary",
	"/api/v1/dashboard/stats",
	"/api/v1/threat-intel/stats",
	"/api/v1/attack-surface/exposure-chains",
	"/api/v1/attack-surface/attack-paths",
	"/api/v1/scans/coverage",
	"/api/v1/validation/coverage",
	"/api/v1/scoping/summary",
	"/api/v1/ctem-cycles/metrics/trend",
	"/api/v1/assets/stats",
}

// DashboardOverviewPart is one read of the overview: its status and, on
// success, its JSON body exactly as the endpoint itself returns it.
type DashboardOverviewPart struct {
	Status int             `json:"status"`
	Body   json.RawMessage `json:"body,omitempty"`
}

// DashboardOverviewResponse maps each part's URL to its answer.
type DashboardOverviewResponse struct {
	Parts map[string]DashboardOverviewPart `json:"parts"`
}

// DashboardOverviewHandler serves GET /dashboard/overview: the dashboard's
// reads in one response.
//
// Each part is answered by sending its GET through the API's own router with
// the caller's credentials (the Cookie and Authorization headers of this
// request), so every part goes through exactly the gates of its endpoint:
// authentication, tenant, permission, module and data scope. A part the
// caller may not read comes back with its 401/403/404 and no body, as the
// endpoint would answer. Only the fixed DashboardOverviewParts are ever
// dispatched; nothing in the request chooses a path.
type DashboardOverviewHandler struct {
	router func() http.Handler
	logger *logger.Logger
}

// NewDashboardOverviewHandler creates the handler. router returns the API's
// root router (read at request time, when every route is registered).
func NewDashboardOverviewHandler(router func() http.Handler, log *logger.Logger) *DashboardOverviewHandler {
	return &DashboardOverviewHandler{router: router, logger: log}
}

// Overview handles GET /api/v1/dashboard/overview
// @Summary      Dashboard overview
// @Description  The CTEM dashboard's reads in one response: each part keyed by the URL of its endpoint, with that
// @Description  endpoint's status and JSON body. Every part goes through its own endpoint's permission, module and
// @Description  data-scope gates; a part the caller may not read has its error status and no body.
// @Tags         Dashboard
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  DashboardOverviewResponse
// @Failure      401  {object}  apierror.Error
// @Router       /dashboard/overview [get]
func (h *DashboardOverviewHandler) Overview(w http.ResponseWriter, r *http.Request) {
	root := h.router()
	resp := DashboardOverviewResponse{Parts: make(map[string]DashboardOverviewPart, len(DashboardOverviewParts))}
	var (
		mu sync.Mutex
		wg sync.WaitGroup
	)
	for _, part := range DashboardOverviewParts {
		wg.Add(1)
		go func(target string) {
			defer wg.Done()
			p := h.dispatch(root, r, target)
			mu.Lock()
			resp.Parts[target] = p
			mu.Unlock()
		}(part)
	}
	wg.Wait()

	// Per-user, per-request data: never stored by a shared cache.
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// dispatch sends one GET through the router with only the caller's
// credentials, and returns its status and JSON body.
func (h *DashboardOverviewHandler) dispatch(root http.Handler, r *http.Request, target string) DashboardOverviewPart {
	// A fresh context: none of the identity this request's middleware put in
	// its context reaches the part, which authenticates from the credentials
	// alone. It is still cancelled with this request.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stop := context.AfterFunc(r.Context(), cancel)
	defer stop()

	sub, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return DashboardOverviewPart{Status: http.StatusInternalServerError}
	}
	for _, header := range []string{"Authorization", "Cookie", "Accept-Language"} {
		if v := r.Header.Get(header); v != "" {
			sub.Header.Set(header, v)
		}
	}
	sub.Header.Set("Accept", "application/json")
	sub.RemoteAddr = r.RemoteAddr

	rec := httptest.NewRecorder()
	root.ServeHTTP(rec, sub)

	part := DashboardOverviewPart{Status: rec.Code}
	if rec.Code == http.StatusOK && strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") {
		body := bytes.TrimSpace(rec.Body.Bytes())
		if json.Valid(body) {
			part.Body = body
		}
	}
	if rec.Code >= http.StatusInternalServerError {
		h.logger.Warn("dashboard overview: part failed", "part", target, "status", rec.Code)
	}
	return part
}
