package handler

// One response for the reads a page shows on load (research/335). A view
// answers each of its parts by sending the part's GET through the API's own
// router with the caller's credentials, so every part passes exactly the
// gates of its endpoint (authentication, tenant, permission, module, data
// scope and the per-user read limit). The parts are fixed by the server;
// nothing in the request chooses a path.

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
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/logger"
)

const (
	// viewCacheMax bounds the cached views (one per caller session and view).
	viewCacheMax = 1000
	// viewComputeTimeout bounds a computation shared by several callers; it
	// is detached from any single caller's cancellation.
	viewComputeTimeout = 25 * time.Second
)

// ViewPart is one read of a view: its status and its JSON body exactly as the
// endpoint itself returns it to this caller.
type ViewPart struct {
	Status int             `json:"status"`
	Body   json.RawMessage `json:"body,omitempty"`
}

// ViewResponse maps each part's URL (path and query, as the web asks for it)
// to its answer.
type ViewResponse struct {
	Parts map[string]ViewPart `json:"parts"`
}

// viewOptions are the settings of one kind of view.
type viewOptions struct {
	// name labels the view in logs.
	name string
	// cacheTTL is how long one caller's computed view is served again; zero
	// computes every request (identical concurrent requests still share one
	// computation).
	cacheTTL time.Duration
	// tenantParts caps the parts one tenant's views of this kind run at the
	// same time, across all its callers.
	tenantParts int
	// passErrors keeps a refused part's JSON error body (its code), so the
	// client can tell a missing permission from a module that is off. The
	// body is what the endpoint itself answers this caller.
	passErrors bool
	// readCost is what one view takes from the caller's per-user read
	// budget, its own request included. Its parts take nothing more: the
	// view is one fixed, server-chosen set of reads, priced as a few.
	readCost int
}

// viewParts computes views: it dispatches parts, bounds them per tenant and
// shares identical concurrent computations.
type viewParts struct {
	router func() http.Handler
	logger *logger.Logger
	opts   viewOptions

	// Identical concurrent calls (same tenant, user, language, credentials
	// and view) share one computation. Nothing is shared between different
	// credentials, so every caller only sees what its own gates allowed.
	flight singleflight.Group
	mu     sync.Mutex
	cache  map[string]viewEntry
	slots  map[string]chan struct{}
}

type viewEntry struct {
	body []byte
	at   time.Time
}

func newViewParts(router func() http.Handler, log *logger.Logger, opts viewOptions) *viewParts {
	if opts.tenantParts <= 0 {
		opts.tenantParts = 4
	}
	return &viewParts{router: router, logger: log, opts: opts,
		cache: map[string]viewEntry{}, slots: map[string]chan struct{}{}}
}

// serve answers r with the view of parts. When gate is set, it is dispatched
// first and alone: unless it answers 200, the view holds only that part (a
// missing or refused object costs one read, not every part's).
func (v *viewParts) serve(w http.ResponseWriter, r *http.Request, gate string, parts []string) {
	// The view's own request took one token on the read limiter; the rest of
	// its price is taken here, before any part runs.
	if v.opts.readCost > 1 && !middleware.ChargeReadCost(r.Context(), v.opts.readCost-1) {
		w.Header().Set("Retry-After", "1")
		apierror.RateLimitExceeded().WriteJSON(w)
		return
	}
	tenant := middleware.GetTenantID(r.Context())
	key := viewKey(tenant, r)
	var body []byte
	switch {
	case key == "":
		body = v.compute(r, tenant, gate, parts)
	default:
		if cached, ok := v.cached(key); ok {
			body = cached
			break
		}
		res, _, _ := v.flight.Do(key, func() (any, error) {
			ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), viewComputeTimeout)
			defer cancel()
			b := v.compute(r.WithContext(ctx), tenant, gate, parts)
			v.store(key, b)
			return b, nil
		})
		body, _ = res.([]byte)
	}

	// Per-user, per-request data: never stored by a shared cache.
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}

// viewKey identifies one caller session and view: tenant, user, language, a
// hash of the credentials the parts authenticate with, and the view's own
// path. Empty (no reuse) when the tenant or user is unknown.
func viewKey(tenant string, r *http.Request) string {
	user := middleware.GetUserID(r.Context())
	if tenant == "" || user == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(r.Header.Get("Authorization") + "\x00" + r.Header.Get("Cookie")))
	return tenant + "|" + user + "|" + r.Header.Get("Accept-Language") + "|" + hex.EncodeToString(sum[:]) + "|" + r.URL.Path
}

func (v *viewParts) cached(key string) ([]byte, bool) {
	if v.opts.cacheTTL <= 0 {
		return nil, false
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	e, ok := v.cache[key]
	if !ok || time.Since(e.at) > v.opts.cacheTTL {
		return nil, false
	}
	return e.body, true
}

func (v *viewParts) store(key string, body []byte) {
	if v.opts.cacheTTL <= 0 {
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if len(v.cache) >= viewCacheMax {
		for k, e := range v.cache {
			if time.Since(e.at) > v.opts.cacheTTL {
				delete(v.cache, k)
			}
		}
		if len(v.cache) >= viewCacheMax {
			return
		}
	}
	v.cache[key] = viewEntry{body: body, at: time.Now()}
}

// tenantSlots is the tenant's part semaphore for this kind of view.
func (v *viewParts) tenantSlots(tenant string) chan struct{} {
	v.mu.Lock()
	defer v.mu.Unlock()
	s, ok := v.slots[tenant]
	if !ok {
		s = make(chan struct{}, v.opts.tenantParts)
		v.slots[tenant] = s
	}
	return s
}

// compute dispatches the gate part, then every other part, at most
// tenantParts at a time for the tenant, and returns the encoded response.
func (v *viewParts) compute(r *http.Request, tenant, gate string, parts []string) []byte {
	root := v.router()
	slots := v.tenantSlots(tenant)
	resp := ViewResponse{Parts: make(map[string]ViewPart, len(parts)+1)}
	run := func(target string) ViewPart {
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
			return v.dispatch(root, r, target)
		case <-r.Context().Done():
			return ViewPart{Status: http.StatusServiceUnavailable}
		}
	}
	if gate != "" {
		g := run(gate)
		resp.Parts[gate] = g
		if g.Status != http.StatusOK {
			return encodeView(resp)
		}
	}
	var (
		mu sync.Mutex
		wg sync.WaitGroup
	)
	for _, part := range parts {
		wg.Add(1)
		go func(target string) {
			defer wg.Done()
			p := run(target)
			mu.Lock()
			resp.Parts[target] = p
			mu.Unlock()
		}(part)
	}
	wg.Wait()
	return encodeView(resp)
}

func encodeView(resp ViewResponse) []byte {
	b, err := json.Marshal(resp)
	if err != nil {
		return []byte(`{"parts":{}}`)
	}
	return b
}

// dispatch sends one GET through the router with only the caller's
// credentials, and returns its status and JSON body.
func (v *viewParts) dispatch(root http.Handler, r *http.Request, target string) (part ViewPart) {
	// A part runs in its own goroutine: a panic in its handler must fail that
	// part (500), never the view or the process.
	defer func() {
		if rec := recover(); rec != nil {
			v.log(r).Error(v.opts.name+": part panicked", "part", RedactViewPart(target))
			part = ViewPart{Status: http.StatusInternalServerError}
		}
	}()
	// A fresh context: none of the identity this request's middleware put in
	// its context reaches the part, which authenticates from the credentials
	// alone. It carries only the view-part mark (the view paid the part's
	// read token) and is still canceled with this request.
	ctx, cancel := context.WithCancel(middleware.WithViewPart(context.Background()))
	defer cancel()
	stop := context.AfterFunc(r.Context(), cancel)
	defer stop()

	sub, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return ViewPart{Status: http.StatusInternalServerError}
	}
	for _, header := range []string{"Authorization", "Cookie", "Accept-Language"} {
		if val := r.Header.Get(header); val != "" {
			sub.Header.Set(header, val)
		}
	}
	sub.Header.Set("Accept", "application/json")
	sub.RemoteAddr = r.RemoteAddr

	rec := httptest.NewRecorder()
	root.ServeHTTP(rec, sub)

	part = ViewPart{Status: rec.Code}
	keep := rec.Code == http.StatusOK ||
		(v.opts.passErrors && rec.Code >= http.StatusBadRequest && rec.Code < http.StatusInternalServerError)
	if keep && strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") {
		body := bytes.TrimSpace(rec.Body.Bytes())
		if json.Valid(body) {
			part.Body = body
		}
	}
	if rec.Code >= http.StatusInternalServerError {
		v.log(r).Warn(v.opts.name+": part failed", "part", RedactViewPart(target), "status", rec.Code)
	}
	return part
}

// log is the view's logger, else the request's.
func (v *viewParts) log(r *http.Request) *logger.Logger {
	if v.logger != nil {
		return v.logger
	}
	return logger.FromContext(r.Context())
}

// RedactViewPart drops ids from a part URL for logs.
func RedactViewPart(target string) string {
	path, _, _ := strings.Cut(target, "?")
	return middleware.RedactPath(path)
}
