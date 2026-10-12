package handler

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/logger"
)

const (
	// overviewCacheTTL is how long one caller's computed overview is served
	// again. The dashboard reloads it on every visit; its aggregates scan a
	// tenant's findings and assets, seconds of database time at scale.
	overviewCacheTTL = 15 * time.Second
	// overviewCacheMax bounds the cached overviews (one per caller session).
	overviewCacheMax = 1000
	// overviewTenantParts caps the parts one tenant's overviews run at the
	// same time, across all its callers, so a burst of dashboard loads in one
	// tenant cannot take every database connection.
	overviewTenantParts = 4
	// overviewComputeTimeout bounds a computation shared by several callers;
	// it is detached from any single caller's cancellation.
	overviewComputeTimeout = 25 * time.Second
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

	// Identical concurrent calls (same tenant, user, language and
	// credentials) share one computation, and its result is served again for
	// overviewCacheTTL. Nothing is shared between different credentials, so
	// every caller still only sees what its own gates allowed.
	flight singleflight.Group
	mu     sync.Mutex
	cache  map[string]overviewEntry
	slots  map[string]chan struct{}
}

type overviewEntry struct {
	body []byte
	at   time.Time
}

// NewDashboardOverviewHandler creates the handler. router returns the API's
// root router (read at request time, when every route is registered).
func NewDashboardOverviewHandler(router func() http.Handler, log *logger.Logger) *DashboardOverviewHandler {
	return &DashboardOverviewHandler{router: router, logger: log,
		cache: map[string]overviewEntry{}, slots: map[string]chan struct{}{}}
}

// Overview handles GET /api/v1/dashboard/overview
// @Summary      Dashboard overview
// @Description  The CTEM dashboard's reads in one response: each part keyed by the URL of its endpoint, with that
// @Description  endpoint's status and JSON body. Every part goes through its own endpoint's permission, module and
// @Description  data-scope gates; a part the caller may not read has its error status and no body.
// @Description  A caller's overview is reused for a few seconds, and one tenant runs only a few parts at a time.
// @Tags         Dashboard
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  DashboardOverviewResponse
// @Router       /dashboard/overview [get]
func (h *DashboardOverviewHandler) Overview(w http.ResponseWriter, r *http.Request) {
	tenant := middleware.GetTenantID(r.Context())
	key := overviewKey(tenant, r)
	var body []byte
	if key == "" {
		body = h.compute(r, tenant)
	} else if cached, ok := h.cached(key); ok {
		body = cached
	} else {
		v, _, _ := h.flight.Do(key, func() (any, error) {
			ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), overviewComputeTimeout)
			defer cancel()
			b := h.compute(r.WithContext(ctx), tenant)
			h.store(key, b)
			return b, nil
		})
		body, _ = v.([]byte)
	}

	// Per-user, per-request data: never stored by a shared cache.
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}

// overviewKey identifies one caller session: tenant, user, language and a
// hash of the credentials the parts authenticate with. Empty (no reuse) when
// the tenant or user is unknown.
func overviewKey(tenant string, r *http.Request) string {
	user := middleware.GetUserID(r.Context())
	if tenant == "" || user == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(r.Header.Get("Authorization") + "\x00" + r.Header.Get("Cookie")))
	return tenant + "|" + user + "|" + r.Header.Get("Accept-Language") + "|" + hex.EncodeToString(sum[:])
}

func (h *DashboardOverviewHandler) cached(key string) ([]byte, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	e, ok := h.cache[key]
	if !ok || time.Since(e.at) > overviewCacheTTL {
		return nil, false
	}
	return e.body, true
}

func (h *DashboardOverviewHandler) store(key string, body []byte) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.cache) >= overviewCacheMax {
		for k, e := range h.cache {
			if time.Since(e.at) > overviewCacheTTL {
				delete(h.cache, k)
			}
		}
		if len(h.cache) >= overviewCacheMax {
			return
		}
	}
	h.cache[key] = overviewEntry{body: body, at: time.Now()}
}

// tenantSlots is the tenant's part semaphore.
func (h *DashboardOverviewHandler) tenantSlots(tenant string) chan struct{} {
	h.mu.Lock()
	defer h.mu.Unlock()
	s, ok := h.slots[tenant]
	if !ok {
		s = make(chan struct{}, overviewTenantParts)
		h.slots[tenant] = s
	}
	return s
}

// compute dispatches every part, at most overviewTenantParts at a time for
// the tenant, and returns the encoded response.
func (h *DashboardOverviewHandler) compute(r *http.Request, tenant string) []byte {
	root := h.router()
	slots := h.tenantSlots(tenant)
	resp := DashboardOverviewResponse{Parts: make(map[string]DashboardOverviewPart, len(DashboardOverviewParts))}
	var (
		mu sync.Mutex
		wg sync.WaitGroup
	)
	for _, part := range DashboardOverviewParts {
		wg.Add(1)
		go func(target string) {
			defer wg.Done()
			var p DashboardOverviewPart
			select {
			case slots <- struct{}{}:
				p = h.dispatch(root, r, target)
				<-slots
			case <-r.Context().Done():
				p = DashboardOverviewPart{Status: http.StatusServiceUnavailable}
			}
			mu.Lock()
			resp.Parts[target] = p
			mu.Unlock()
		}(part)
	}
	wg.Wait()
	b, err := json.Marshal(resp)
	if err != nil {
		return []byte(`{"parts":{}}`)
	}
	return b
}

// dispatch sends one GET through the router with only the caller's
// credentials, and returns its status and JSON body.
func (h *DashboardOverviewHandler) dispatch(root http.Handler, r *http.Request, target string) DashboardOverviewPart {
	// A fresh context: none of the identity this request's middleware put in
	// its context reaches the part, which authenticates from the credentials
	// alone. It is still canceled with this request.
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
