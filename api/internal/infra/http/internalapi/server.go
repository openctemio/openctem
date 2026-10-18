package internalapi

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/signupevent"

	"golang.org/x/time/rate"

	"github.com/openctemio/openctem/api/internal/app/entitlement"
	"github.com/openctemio/openctem/api/internal/app/lifecycle"
	tenantapp "github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/limits"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

const (
	maxBody          = 64 << 10
	defaultPageLimit = 100
	maxPageLimit     = 500
	// Per calling service: a control plane talks to the core in bursts
	// (metering pages, provisioning), never at user-request rates.
	ratePerSecond = 20
	rateBurst     = 40
)

// Entitlements is what the API needs from the entitlement service.
type Entitlements interface {
	ApplyControlPlane(ctx context.Context, tenantID shared.ID, lims limits.Limits, denied []string, call entitlement.ControlPlaneCall) error
	ApplySelfServiceDefaultsFromControlPlane(ctx context.Context, d limits.Limits, call entitlement.ControlPlaneCall) error
	Usage(ctx context.Context, tenantID shared.ID, withFindings bool) (map[limits.Key]int, error)
}

// IdlePolicy turns the idle policy on or off.
type IdlePolicy interface {
	ChangePolicyByControlPlane(ctx context.Context, tenantID shared.ID, enabled bool, reason, subject, ip string) error
}

// OrganizationRef is one organization in the usage pages: its id and when it
// was created, nothing else.
type OrganizationRef struct {
	ID        shared.ID
	CreatedAt time.Time
}

// Organizations lists organizations by id (the platform system organization
// excluded).
type Organizations interface {
	Exists(ctx context.Context, id shared.ID) (bool, error)
	Page(ctx context.Context, after *shared.ID, limit int) ([]OrganizationRef, error)
}

// Provisioner creates an organization with its owner.
type Provisioner interface {
	Create(ctx context.Context, in tenantapp.CreateOrganizationInput) (*tenantapp.CreatedOrganization, error)
}

// AuditWriter writes one platform audit row.
type AuditWriter interface {
	Create(ctx context.Context, log *admin.AuditLog) error
}

// Deps are the API's collaborators. Provisioner and Audit may be nil (the
// provisioning endpoint then answers 503).
type Deps struct {
	Verifier      *Verifier
	Entitlements  Entitlements
	IdlePolicy    IdlePolicy
	Organizations Organizations
	Provisioner   Provisioner
	Audit         AuditWriter
	Log           *logger.Logger
}

// Handler serves the API.
type Handler struct {
	d   Deps
	mux *http.ServeMux

	mu       sync.Mutex
	limiters map[string]*rate.Limiter
}

// NewHandler builds the router.
func NewHandler(d Deps) *Handler {
	if d.Log == nil {
		d.Log = logger.NewNop()
	}
	d.Log = d.Log.With("component", "internal-api")
	h := &Handler{d: d, mux: http.NewServeMux(), limiters: map[string]*rate.Limiter{}}
	h.route("GET /internal/v1/catalog", "", h.catalog)
	h.route("PUT /internal/v1/organizations/{id}/entitlements", ScopeLimitsWrite, h.putEntitlements)
	h.route("PUT /internal/v1/organizations/{id}/idle-policy", ScopeLimitsWrite, h.putIdlePolicy)
	h.route("PUT /internal/v1/self-service-limits", ScopeLimitsWrite, h.putSelfServiceLimits)
	h.route("POST /internal/v1/organizations", ScopeOrgsProvision, h.provision)
	h.route("GET /internal/v1/organizations/{id}/usage", ScopeUsageRead, h.orgUsage)
	h.route("GET /internal/v1/usage", ScopeUsageRead, h.usagePage)
	return h
}

// ServeHTTP implements http.Handler; unknown paths answer 404.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) { h.mux.ServeHTTP(w, r) }

type ctxKey struct{}

func claimsFrom(r *http.Request) Claims {
	c, _ := r.Context().Value(ctxKey{}).(Claims)
	return c
}

// route wraps an endpoint: client certificate, bearer token, scope (empty:
// any valid token), rate limit, body limit, access log.
func (h *Handler) route(pattern, scope string, fn http.HandlerFunc) {
	h.mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		subject := ""
		defer func() {
			h.d.Log.Info("internal api call", "method", r.Method, "route", pattern, "status", rec.status,
				"subject", subject, "duration_ms", time.Since(start).Milliseconds())
		}()
		// The TLS handshake already required a certificate from the pinned
		// CA; refuse a plain or unverified connection here too.
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
			writeError(rec, http.StatusUnauthorized, "UNAUTHENTICATED", "")
			return
		}
		raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || raw == "" {
			writeError(rec, http.StatusUnauthorized, "UNAUTHENTICATED", "")
			return
		}
		claims, detail, err := h.d.Verifier.Verify(r.Context(), strings.TrimSpace(raw))
		if err != nil {
			h.d.Log.Warn("internal api token refused", "reason", detail, "route", pattern)
			writeError(rec, http.StatusUnauthorized, "UNAUTHENTICATED", "")
			return
		}
		subject = claims.Subject
		if !h.limiter(claims.Subject).Allow() {
			writeError(rec, http.StatusTooManyRequests, "RATE_LIMITED", "")
			return
		}
		if scope != "" && !claims.Has(scope) {
			writeError(rec, http.StatusForbidden, "INSUFFICIENT_SCOPE", "")
			return
		}
		if scope == "" && !(claims.Has(ScopeLimitsWrite) || claims.Has(ScopeOrgsProvision) || claims.Has(ScopeUsageRead)) {
			writeError(rec, http.StatusForbidden, "INSUFFICIENT_SCOPE", "")
			return
		}
		r.Body = http.MaxBytesReader(rec, r.Body, maxBody)
		fn(rec, r.WithContext(context.WithValue(r.Context(), ctxKey{}, claims)))
	})
}

func (h *Handler) limiter(subject string) *rate.Limiter {
	h.mu.Lock()
	defer h.mu.Unlock()
	l, ok := h.limiters[subject]
	if !ok {
		if len(h.limiters) > 1000 {
			h.limiters = map[string]*rate.Limiter{}
		}
		l = rate.NewLimiter(ratePerSecond, rateBurst)
		h.limiters[subject] = l
	}
	return l
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	body := map[string]string{"code": code}
	if message != "" {
		body["message"] = message
	}
	writeJSON(w, status, body)
}

func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return ""
	}
	return host
}

func (h *Handler) call(r *http.Request, reason string) entitlement.ControlPlaneCall {
	c := claimsFrom(r)
	return entitlement.ControlPlaneCall{Subject: c.Subject, TokenID: c.TokenID, IP: remoteIP(r), Reason: reason}
}

// tenantFromPath reads {id} and checks that the organization exists.
func (h *Handler) tenantFromPath(w http.ResponseWriter, r *http.Request) (shared.ID, bool) {
	id, err := shared.IDFromString(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "VALIDATION", "invalid organization id")
		return shared.ID{}, false
	}
	ok, err := h.d.Organizations.Exists(r.Context(), id)
	if err != nil {
		h.d.Log.Error("internal api organization lookup", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL", "")
		return shared.ID{}, false
	}
	if !ok {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "")
		return shared.ID{}, false
	}
	return id, true
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "VALIDATION", "invalid request body")
		return false
	}
	return true
}

// CatalogResponse lists what the control plane may set.
type CatalogResponse struct {
	LimitKeys []string `json:"limit_keys"`
	Features  []string `json:"features"`
}

func (h *Handler) catalog(w http.ResponseWriter, _ *http.Request) {
	resp := CatalogResponse{LimitKeys: []string{}, Features: limits.Features()}
	for _, k := range limits.Keys {
		resp.LimitKeys = append(resp.LimitKeys, string(k))
	}
	writeJSON(w, http.StatusOK, resp)
}

// EntitlementsRequest replaces the control plane's limits and denies of one
// organization.
type EntitlementsRequest struct {
	Limits         map[string]int `json:"limits"`
	DeniedFeatures []string       `json:"denied_features"`
	Reason         string         `json:"reason"`
}

func toLimits(in map[string]int, perOrganization bool) (limits.Limits, bool) {
	out := limits.Limits{}
	for k, v := range in {
		key := limits.Key(k)
		if v < 0 || !key.IsValid() || (perOrganization && !key.PerOrganization()) {
			return nil, false
		}
		out[key] = v
	}
	return out, true
}

func validFeatures(fs []string) bool {
	for _, f := range fs {
		if !limits.IsFeature(f) {
			return false
		}
	}
	return true
}

func (h *Handler) putEntitlements(w http.ResponseWriter, r *http.Request) {
	id, ok := h.tenantFromPath(w, r)
	if !ok {
		return
	}
	var req EntitlementsRequest
	if !decode(w, r, &req) {
		return
	}
	lims, ok := toLimits(req.Limits, true)
	if !ok || !validFeatures(req.DeniedFeatures) || !entitlement.ValidReason(req.Reason) {
		writeError(w, http.StatusBadRequest, "VALIDATION", "known per-organization limit keys with values >= 0, known features and a reason (up to 500 characters)")
		return
	}
	if err := h.d.Entitlements.ApplyControlPlane(r.Context(), id, lims, req.DeniedFeatures, h.call(r, req.Reason)); err != nil {
		h.fail(w, "apply entitlements", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"organization_id": id.String(), "applied_at": time.Now().UTC().Format(time.RFC3339)})
}

// SelfServiceLimitsRequest replaces the limits every self-service
// organization starts with (and the per-person cap, orgs_per_user).
type SelfServiceLimitsRequest struct {
	Limits map[string]int `json:"limits"`
	Reason string         `json:"reason"`
}

func (h *Handler) putSelfServiceLimits(w http.ResponseWriter, r *http.Request) {
	var req SelfServiceLimitsRequest
	if !decode(w, r, &req) {
		return
	}
	lims, ok := toLimits(req.Limits, false)
	if !ok || !entitlement.ValidReason(req.Reason) {
		writeError(w, http.StatusBadRequest, "VALIDATION", "known limit keys with values >= 0 and a reason (up to 500 characters)")
		return
	}
	if err := h.d.Entitlements.ApplySelfServiceDefaultsFromControlPlane(r.Context(), lims, h.call(r, req.Reason)); err != nil {
		h.fail(w, "apply self-service limits", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"applied_at": time.Now().UTC().Format(time.RFC3339)})
}

// IdlePolicyRequest turns the idle policy on or off.
type IdlePolicyRequest struct {
	Enabled bool   `json:"enabled"`
	Reason  string `json:"reason"`
}

func (h *Handler) putIdlePolicy(w http.ResponseWriter, r *http.Request) {
	id, ok := h.tenantFromPath(w, r)
	if !ok {
		return
	}
	var req IdlePolicyRequest
	if !decode(w, r, &req) {
		return
	}
	if err := h.d.IdlePolicy.ChangePolicyByControlPlane(r.Context(), id, req.Enabled, req.Reason, claimsFrom(r).Subject, remoteIP(r)); err != nil {
		if errors.Is(err, lifecycle.ErrInvalidPolicyReason) {
			writeError(w, http.StatusBadRequest, "VALIDATION", err.Error())
			return
		}
		h.fail(w, "change idle policy", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"organization_id": id.String(), "enabled": req.Enabled})
}

// ProvisionRequest creates an organization with its owner, limits, denies
// and idle policy.
type ProvisionRequest struct {
	Name           string         `json:"name"`
	Slug           string         `json:"slug"`
	OwnerEmail     string         `json:"owner_email"`
	OwnerName      string         `json:"owner_name"`
	Limits         map[string]int `json:"limits"`
	DeniedFeatures []string       `json:"denied_features"`
	IdlePolicy     bool           `json:"idle_policy"`
	Reason         string         `json:"reason"`
}

// ProvisionResponse carries ids and the owner's state only; never a setup
// link or token. An owner email that already has an account is refused
// (409 OWNER_ACCOUNT_EXISTS): that person creates the organization after
// signing in, so nobody becomes an owner without consenting.
type ProvisionResponse struct {
	OrganizationID string `json:"organization_id"`
	// OwnerAccount is "created": the new account gets its set-password email
	// from the core.
	OwnerAccount   string `json:"owner_account"`
	SetupEmailSent bool   `json:"setup_email_sent"`
}

func (h *Handler) provision(w http.ResponseWriter, r *http.Request) {
	if h.d.Provisioner == nil {
		writeError(w, http.StatusServiceUnavailable, "UNAVAILABLE", "")
		return
	}
	var req ProvisionRequest
	if !decode(w, r, &req) {
		return
	}
	lims, ok := toLimits(req.Limits, true)
	if !ok || !validFeatures(req.DeniedFeatures) || !entitlement.ValidReason(req.Reason) {
		writeError(w, http.StatusBadRequest, "VALIDATION", "known per-organization limit keys with values >= 0, known features and a reason (up to 500 characters)")
		return
	}
	call := h.call(r, req.Reason)
	created, err := h.d.Provisioner.Create(r.Context(), tenantapp.CreateOrganizationInput{
		Name: strings.TrimSpace(req.Name), Slug: strings.ToLower(strings.TrimSpace(req.Slug)),
		OwnerEmail: req.OwnerEmail, OwnerName: req.OwnerName, NewOwnerOnly: true,
		SignupSource: signupevent.SourceControlPlane,
		Provisioned: &tenantapp.ProvisionedEntitlements{
			Limits: lims, DeniedFeatures: req.DeniedFeatures, IdlePolicy: req.IdlePolicy, Reason: strings.TrimSpace(req.Reason),
		},
	})
	if err != nil {
		switch {
		case errors.Is(err, tenantapp.ErrOwnerAccountExists):
			writeError(w, http.StatusConflict, "OWNER_ACCOUNT_EXISTS", "")
		case shared.IsValidation(err):
			if strings.Contains(err.Error(), "already taken") {
				writeError(w, http.StatusConflict, "CONFLICT", "")
				return
			}
			writeError(w, http.StatusBadRequest, "VALIDATION", err.Error())
		case errors.Is(err, shared.ErrConflict), errors.Is(err, tenantapp.ErrAccountExists):
			writeError(w, http.StatusConflict, "CONFLICT", "")
		default:
			h.fail(w, "provision organization", err)
		}
		return
	}
	tid := created.Tenant.ID()
	resp := ProvisionResponse{OrganizationID: tid.String(), OwnerAccount: "existing"}
	if created.OwnerCreated {
		resp.OwnerAccount = "created"
		resp.SetupEmailSent = created.OwnerSetup != nil && created.OwnerSetup.EmailSent
	}
	if h.d.Audit != nil {
		body := map[string]any{"slug": created.Tenant.Slug(), "reason": call.Reason, "subject": call.Subject, "token_id": call.TokenID,
			"denied_features": req.DeniedFeatures, "idle_policy": req.IdlePolicy, "owner_account": resp.OwnerAccount}
		for k, v := range lims {
			body["limit."+string(k)] = v
		}
		entry := admin.NewAuditLogBuilder(nil, "organization.provisioned").
			Resource("tenant", &tid, created.Tenant.Name()).
			Context(call.IP, "").
			Request("POST", "", body).
			High().
			Build()
		entry.AdminEmail = entitlement.ControlPlaneActor
		if aerr := h.d.Audit.Create(r.Context(), entry); aerr != nil {
			h.d.Log.Error("audit provisioned organization", "error", aerr)
		}
	}
	writeJSON(w, http.StatusCreated, resp)
}

// UsageResponse is one organization's aggregate counts.
type UsageResponse struct {
	OrganizationID string         `json:"organization_id"`
	CreatedAt      string         `json:"created_at,omitempty"`
	CountedAt      string         `json:"counted_at"`
	Usage          map[string]int `json:"usage"`
}

func (h *Handler) usageOf(r *http.Request, id shared.ID) (map[string]int, error) {
	u, err := h.d.Entitlements.Usage(r.Context(), id, r.URL.Query().Get("include") == "findings")
	if err != nil {
		return nil, err
	}
	out := map[string]int{}
	for k, v := range u {
		out[string(k)] = v
	}
	return out, nil
}

func (h *Handler) orgUsage(w http.ResponseWriter, r *http.Request) {
	id, ok := h.tenantFromPath(w, r)
	if !ok {
		return
	}
	u, err := h.usageOf(r, id)
	if err != nil {
		h.fail(w, "count usage", err)
		return
	}
	writeJSON(w, http.StatusOK, UsageResponse{OrganizationID: id.String(), CountedAt: time.Now().UTC().Format(time.RFC3339), Usage: u})
}

// UsagePageResponse is one page of organizations with their usage.
type UsagePageResponse struct {
	Items []UsageResponse `json:"items"`
	Next  string          `json:"next"`
}

func (h *Handler) usagePage(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit := defaultPageLimit
	if s := q.Get("limit"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 || n > maxPageLimit {
			writeError(w, http.StatusBadRequest, "VALIDATION", fmt.Sprintf("limit must be 1 to %d", maxPageLimit))
			return
		}
		limit = n
	}
	var after *shared.ID
	if s := q.Get("after"); s != "" {
		id, err := shared.IDFromString(s)
		if err != nil {
			writeError(w, http.StatusBadRequest, "VALIDATION", "invalid after")
			return
		}
		after = &id
	}
	refs, err := h.d.Organizations.Page(r.Context(), after, limit)
	if err != nil {
		h.fail(w, "list organizations", err)
		return
	}
	resp := UsagePageResponse{Items: make([]UsageResponse, 0, len(refs))}
	now := time.Now().UTC().Format(time.RFC3339)
	for _, o := range refs {
		u, err := h.usageOf(r, o.ID)
		if err != nil {
			h.fail(w, "count usage", err)
			return
		}
		resp.Items = append(resp.Items, UsageResponse{OrganizationID: o.ID.String(), CreatedAt: o.CreatedAt.UTC().Format(time.RFC3339), CountedAt: now, Usage: u})
	}
	if len(refs) == limit {
		resp.Next = refs[len(refs)-1].ID.String()
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) fail(w http.ResponseWriter, what string, err error) {
	if errors.Is(err, limits.ErrInvalid) || shared.IsValidation(err) {
		writeError(w, http.StatusBadRequest, "VALIDATION", "")
		return
	}
	if shared.IsNotFound(err) {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "")
		return
	}
	h.d.Log.Error("internal api: "+what, "error", err)
	writeError(w, http.StatusInternalServerError, "INTERNAL", "")
}

// TLSConfig is the listener's TLS: 1.3 only, a client certificate from the
// pinned CA required in the handshake.
func TLSConfig(certFile, keyFile, clientCAFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("internal API: server certificate: %w", err)
	}
	caPEM, err := os.ReadFile(clientCAFile) //nolint:gosec // operator-configured path
	if err != nil {
		return nil, fmt.Errorf("internal API: client CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("internal API: no certificate in the client CA file")
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}, nil
}

// NewServer creates the listener's server (TLS from TLSConfig).
func NewServer(addr string, tlsCfg *tls.Config, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
}
