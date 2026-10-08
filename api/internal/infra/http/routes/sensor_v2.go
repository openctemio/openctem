package routes

import (
	"context"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	moduledom "github.com/openctemio/openctem/api/pkg/domain/module"
	"github.com/openctemio/openctem/api/pkg/logger"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

// Sensor self-renewal budget, per sensor: a burst of 5, then one every 2 minutes.
const (
	renewRatePerSecond = 1.0 / 120.0
	renewBurst         = 5
)

// Per-sensor budgets of the v2 results routes, on top of the per-tenant
// ingest rate. Writes: 10/s, burst 20 (a segmented report sends at most 4
// segments in flight). Reads (status polls every Retry-After: 2 s, hello):
// 5/s, burst 20. Variables so a test can lift them.
var (
	v2WriteRatePerSensor  = 10.0
	v2WriteBurstPerSensor = 20
	v2ReadRatePerSensor   = 5.0
	v2ReadBurstPerSensor  = 20
	// The control plane (heartbeats, polls, claims, transitions, logs,
	// manifests, fingerprint queries) per tenant, on top of the per-sensor
	// budgets: an organization with many sensors cannot multiply the
	// per-sensor budget without bound. Sized for large fleets (1000 sensors
	// heartbeating every 30 s and polling every 5 s stay well inside).
	v2ControlRatePerTenant  = 500.0
	v2ControlBurstPerTenant = 1000
)

// sensorV2Budgets are the rate and concurrency budgets of the sensor
// routes. One set serves both protocol v2 and protocol v3 (which runs every
// call through the same routes, RFC-059), so a sensor cannot double its
// budget by using both.
type sensorV2Budgets struct {
	// tenant is the per-tenant ingest budget shared with v1 (nil when rate
	// limiting is off).
	tenant      *middleware.TelemetryRateLimiter
	write       *middleware.TelemetryRateLimiter
	read        *middleware.TelemetryRateLimiter
	renew       *middleware.TelemetryRateLimiter
	concurrency *middleware.TenantConcurrencyLimiter
	// control is the per-tenant control-plane budget.
	control *middleware.TelemetryRateLimiter
}

func newSensorV2Budgets(tenantRateLimiter *middleware.TelemetryRateLimiter, log *logger.Logger) *sensorV2Budgets {
	return &sensorV2Budgets{
		tenant:      tenantRateLimiter,
		write:       middleware.NewTelemetryRateLimiter(v2WriteRatePerSensor, v2WriteBurstPerSensor, 10*time.Minute, log),
		read:        middleware.NewTelemetryRateLimiter(v2ReadRatePerSensor, v2ReadBurstPerSensor, 10*time.Minute, log),
		renew:       middleware.NewTelemetryRateLimiter(renewRatePerSecond, renewBurst, time.Hour, log),
		concurrency: middleware.NewTenantConcurrencyLimiter(IngestMaxConcurrentPerTenant),
		control:     middleware.NewTelemetryRateLimiter(v2ControlRatePerTenant, v2ControlBurstPerTenant, 10*time.Minute, log),
	}
}

// registerSensorV2Routes mounts sensor protocol v2 results (RFC-026,
// docs/rfcs/RFC-026-sensor-results-ingest.md) under /api/v2/sensor.
//
// Only the sensor authenticator runs on this group (RFC-023 C-2): user JWTs,
// session cookies and oct_ API keys are refused, as sensor keys are refused
// on every user route. Every write goes through the v2 edge chain, which
// rate-limits, checks the headers, verifies Content-Digest and decodes with a
// bound before the handler sees a byte (middleware/ingest_v2.go).
//
// The control plane of RFC-029 (heartbeat, commands, suppressions,
// fingerprint queries, key renewal) is mounted in the same group when ctl is
// not nil; its handlers call the services protocol v1 uses.
//
// tenantRateLimiter is the per-tenant ingest budget shared with v1 (nil when
// rate limiting is off).
func registerSensorV2Routes(router Router, h *handler.SensorResultsV2Handler, ctl *handler.SensorControlV2Handler,
	tenantRateLimiter *middleware.TelemetryRateLimiter, log *logger.Logger,
) {
	mountSensorV2(router, h, ctl, newSensorV2Budgets(tenantRateLimiter, log), h.Authenticate)
}

// sensorV2InProcess is the v2 route group protocol v3 serves its calls
// through (RFC-059 T2): the same routes, edge chain and budgets, behind
// handler.AuthenticateInProcess, which only accepts an identity the v3
// server put in the context. It is never mounted on a listener.
func sensorV2InProcess(h *handler.SensorResultsV2Handler, ctl *handler.SensorControlV2Handler, b *sensorV2Budgets) http.Handler {
	r := infrahttp.NewChiRouter()
	mountSensorV2(r, h, ctl, b, handler.AuthenticateInProcess)
	return r.Handler()
}

// mountSensorV2 mounts the v2 routes on router behind the route metrics and
// authenticate (h.Authenticate on the listener, handler.AuthenticateInProcess
// for protocol v3, whose calls are counted per v2 route too).
//
//nolint:cyclop // route registration
func mountSensorV2(router Router, h *handler.SensorResultsV2Handler, ctl *handler.SensorControlV2Handler,
	b *sensorV2Budgets, authenticate Middleware,
) {
	limits := h.Limits()
	throttleWrite := middleware.V2Throttle(b.tenant, b.write, b.concurrency, handler.SensorKey)
	throttleRead := middleware.V2Throttle(nil, b.read, nil, handler.SensorKey)
	// The content chain of a PUT, in the RFC-026 §3.3 order. BodyLimit
	// replaces the global 10 MB limit with the v2 request limit.
	content := []Middleware{
		throttleWrite,
		middleware.V2ContentType(),
		middleware.V2ContentEncoding(),
		middleware.BodyLimit(limits.MaxContentBytes),
		middleware.V2ReadVerified(limits),
	}
	commit := []Middleware{throttleWrite, middleware.BodyLimit(1 << 20)}

	// Control plane (RFC-029): per-sensor budgets only (the per-tenant ingest
	// budget is for report writes). Key renewal also takes a per-sensor renewal
	// budget (a burst of 5, then one every 2 minutes): it mints a credential each
	// time, and a stolen key must not mint an unbounded set of fresh ones.
	controlWrite := []Middleware{middleware.V2Throttle(b.control, b.write, nil, handler.SensorKey)}
	controlRead := []Middleware{middleware.V2Throttle(b.control, b.read, nil, handler.SensorKey)}
	keys := []Middleware{middleware.V2Throttle(nil, b.renew, nil, handler.SensorKey), controlWrite[0]}
	if ctl != nil {
		h.SetControlFeatures(ctl.Features())
	}

	router.Group(protov2.PathPrefix, func(r Router) {
		r.GET("/hello", h.Hello, throttleRead)

		r.PUT("/results/{report_id}", h.PutReport, content...)
		r.PUT("/results/{report_id}/segments/{seq}", h.PutSegment, content...)
		r.POST("/results/{report_id}/commit", h.Commit, commit...)
		r.GET("/results/{report_id}", h.Status, throttleRead)
		r.DELETE("/results/{report_id}", h.Abandon, throttleRead)

		r.PUT("/commands/{command_id}/results/{report_id}", h.PutReport, content...)
		r.PUT("/commands/{command_id}/results/{report_id}/segments/{seq}", h.PutSegment, content...)
		r.POST("/commands/{command_id}/results/{report_id}/commit", h.Commit, commit...)

		if ctl == nil {
			return
		}
		if ctl.HasIngest() {
			r.POST(protov2.HeartbeatPath, ctl.Heartbeat, controlWrite...)
			r.POST(protov2.FingerprintsCheckPath, ctl.CheckFingerprints, controlWrite...)
			r.POST(protov2.BaselineDiffPath, ctl.BaselineDiff, controlWrite...)
			r.POST(protov2.KeysPath, ctl.RenewKey, keys...)
			r.PUT(protov2.ManifestPath, ctl.PutManifest, controlWrite...)
			r.GET(protov2.ManifestPath, ctl.GetManifest, controlRead...)
			r.PUT(protov2.ConfigReportPath, ctl.PutConfigReport, controlWrite...)
		}
		if ctl.HasCommands() {
			r.GET(protov2.CommandsPath, ctl.PollCommands, controlRead...)
			r.POST("/commands/{command_id}/claim", ctl.ClaimCommand, controlWrite...)
			r.POST("/commands/{command_id}/start", ctl.StartCommand, controlWrite...)
			r.POST("/commands/{command_id}/complete", ctl.CompleteCommand, controlWrite...)
			r.POST("/commands/{command_id}/fail", ctl.FailCommand, controlWrite...)
			r.POST("/commands/{command_id}/release", ctl.ReleaseCommand, controlWrite...)
		}
		if ctl.HasLogs() {
			// Per-task logs (RFC-029 §4.4.1): the control write budget, a
			// 256 KiB body (decoded with that bound by the handler).
			r.POST("/commands/{command_id}/logs", ctl.CommandLogs, controlWrite...)
		}
		if ctl.HasSuppressions() {
			r.GET(protov2.SuppressionsPath, ctl.Suppressions, controlRead...)
		}
	}, middleware.V2Observe(v2RouteName), authenticate)
}

// v2RouteNames maps the matched route pattern to the metric label.
var v2RouteNames = map[string]string{
	protov2.PathPrefix + "/hello":                                                    "hello",
	protov2.PathPrefix + "/results/{report_id}":                                      "report",
	protov2.PathPrefix + "/results/{report_id}/segments/{seq}":                       "segment",
	protov2.PathPrefix + "/results/{report_id}/commit":                               "commit",
	protov2.PathPrefix + "/commands/{command_id}/results/{report_id}":                "report",
	protov2.PathPrefix + "/commands/{command_id}/results/{report_id}/segments/{seq}": "segment",
	protov2.PathPrefix + "/commands/{command_id}/results/{report_id}/commit":         "commit",

	protov2.PathPrefix + protov2.HeartbeatPath:             "heartbeat",
	protov2.PathPrefix + protov2.CommandsPath:              "commands",
	protov2.PathPrefix + "/commands/{command_id}/claim":    "claim",
	protov2.PathPrefix + "/commands/{command_id}/start":    "start",
	protov2.PathPrefix + "/commands/{command_id}/complete": "complete",
	protov2.PathPrefix + "/commands/{command_id}/fail":     "fail",
	protov2.PathPrefix + "/commands/{command_id}/logs":     "logs",
	protov2.PathPrefix + protov2.SuppressionsPath:          "suppressions",
	protov2.PathPrefix + protov2.FingerprintsCheckPath:     "fingerprints_check",
	protov2.PathPrefix + protov2.BaselineDiffPath:          "baseline_diff",
	protov2.PathPrefix + protov2.KeysPath:                  "keys",
	protov2.PathPrefix + protov2.ManifestPath:              "manifest",
	protov2.PathPrefix + protov2.ConfigReportPath:          "config_report",
}

// v2RouteName is the closed-set route label of a v2 request ("other" for no
// match). Read after the request was routed, when chi knows the pattern.
func v2RouteName(r *http.Request) string {
	if rc := chi.RouteContext(r.Context()); rc != nil {
		if name, ok := v2RouteNames[rc.RoutePattern()]; ok {
			return name
		}
	}
	return "other"
}

// sensorControlV2Handler builds the RFC-029 control-plane handler from the
// protocol v1 handlers, so both protocols share every service. Nil when
// neither the ingest nor the command handler is wired.
func sensorControlV2Handler(h Handlers, log *logger.Logger) *handler.SensorControlV2Handler {
	if h.Ingest == nil && h.Command == nil {
		return nil
	}
	var suppressionsEnabled func(ctx context.Context, tenantID string) bool
	if h.ModuleGate != nil {
		suppressionsEnabled = func(ctx context.Context, tenantID string) bool {
			return h.ModuleGate.IsEnabled(ctx, tenantID, moduledom.ModuleSuppressions)
		}
	}
	return handler.NewSensorControlV2Handler(h.Ingest, h.Command, h.Suppression, suppressionsEnabled, log)
}
