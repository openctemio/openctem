package routes

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/api/internal/infra/http/handler"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/logger"
	protov2 "github.com/openctemio/api/pkg/sensorproto/v2"
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
)

// registerSensorV2Routes mounts sensor protocol v2 results (RFC-026,
// docs/rfcs/RFC-026-sensor-results-ingest.md) under /api/v2/sensor.
//
// Only the sensor authenticator runs on this group (RFC-023 C-2): user JWTs,
// session cookies and oct_ API keys are refused, as sensor keys are refused
// on every user route. Every write goes through the v2 edge chain, which
// rate-limits, checks the headers, verifies Content-Digest and decodes with a
// bound before the handler sees a byte (middleware/ingest_v2.go).
//
// tenantRateLimiter is the per-tenant ingest budget shared with v1 (nil when
// rate limiting is off).
func registerSensorV2Routes(router Router, h *handler.SensorResultsV2Handler, tenantRateLimiter *middleware.TelemetryRateLimiter, log *logger.Logger) {
	limits := h.Limits()
	writeLimiter := middleware.NewTelemetryRateLimiter(v2WriteRatePerSensor, v2WriteBurstPerSensor, 10*time.Minute, log)
	readLimiter := middleware.NewTelemetryRateLimiter(v2ReadRatePerSensor, v2ReadBurstPerSensor, 10*time.Minute, log)
	concurrency := middleware.NewTenantConcurrencyLimiter(IngestMaxConcurrentPerTenant)

	throttleWrite := middleware.V2Throttle(tenantRateLimiter, writeLimiter, concurrency, handler.SensorKey)
	throttleRead := middleware.V2Throttle(nil, readLimiter, nil, handler.SensorKey)
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
	}, middleware.V2Observe(v2RouteName), h.Authenticate)
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
