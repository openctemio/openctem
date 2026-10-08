package routes

import (
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/logger"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

// Pairing caps (docs/rfcs/RFC-052-sensor-pairing-and-authorization.md §4.4).
// Variables so a test can lift them.
var (
	// Start requests per source address: 10 per hour, burst 3.
	pairingStartPerIPRate  = 10.0 / 3600
	pairingStartPerIPBurst = 3
	// Start requests platform-wide: 600 per hour, burst 50. The open-request
	// cap (sensorpairing.DefaultMaxOpen) is the hard limit across replicas.
	pairingStartGlobalRate  = 600.0 / 3600
	pairingStartGlobalBurst = 50
	// Reveal, poll and confirm per pairing: 1 per second, burst 5.
	pairingPerRequestRate  = 1.0
	pairingPerRequestBurst = 5
	// User-plane lookups and approvals per user: 10 per minute.
	pairingPerUserRate  = 10.0 / 60
	pairingPerUserBurst = 10
)

// registerSensorPairingRoutes mounts pairing: the sensor plane under
// /api/v2/sensor/pairings (no bearer key; every request signed by the key
// being paired, verified in the handler) and the user plane under
// /api/v1/sensor-pairings.
func registerSensorPairingRoutes(router Router, h *handler.SensorPairingHandler, authMiddleware, userSyncMiddleware Middleware, log *logger.Logger) {
	perIP := middleware.NewTelemetryRateLimiter(pairingStartPerIPRate, pairingStartPerIPBurst, 2*time.Hour, log)
	global := middleware.NewTelemetryRateLimiter(pairingStartGlobalRate, pairingStartGlobalBurst, 2*time.Hour, log)
	perRequest := middleware.NewTelemetryRateLimiter(pairingPerRequestRate, pairingPerRequestBurst, 30*time.Minute, log)
	perUser := middleware.NewTelemetryRateLimiter(pairingPerUserRate, pairingPerUserBurst, time.Hour, log)

	start := []Middleware{
		pairingLimit(perIP, pairingSourceKey),
		pairingLimit(global, func(*http.Request) string { return "global" }),
	}
	perPairing := perPairingChain(perRequest)

	// Sensor plane. V2Observe labels the metrics; the handler authenticates
	// every request by its signature (no sensor-key authenticator: the key
	// is not registered yet).
	router.Group("/api/v2/sensor/pairings", func(r Router) {
		r.POST("/", h.Start, start...)
		r.PUT("/{pairing_id}/nonce", h.Reveal, perPairing...)
		r.GET("/{pairing_id}", h.Status, perPairing...)
		r.POST("/{pairing_id}/complete", h.Confirm, perPairing...)
	}, middleware.V2Observe(pairingRouteName))

	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)
	userLimit := perUser.MiddlewareKeyed(handler.UserKey, "Too many pairing requests; try again later")
	router.Group("/api/v1/sensor-pairings", func(r Router) {
		r.POST("/lookup", h.Lookup, middleware.Require(permission.SensorsPair), userLimit)
		r.POST("/expectations", h.Expect, middleware.Require(permission.SensorsPair), userLimit)
		r.GET("/expectations/{id}", h.GetExpectation, middleware.Require(permission.SensorsPair))
		r.POST("/{id}/approve", h.Approve, middleware.Require(permission.SensorsApprove), userLimit)
		r.POST("/{id}/reject", h.Deny, middleware.Require(permission.SensorsPair), userLimit)
	}, tenantMiddlewares...)
}

// pairingSourceKey is the per-source key of the pairing start budget: the
// client address, an IPv6 address grouped by its /64. One IPv6 host
// usually holds a whole /64, so a per-address budget would give a single
// caller 2^64 budgets to exhaust the platform-wide open-pairing cap with.
func pairingSourceKey(r *http.Request) string {
	ip := middleware.ClientIP(r)
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	a = a.Unmap()
	if a.Is4() {
		return a.String()
	}
	p, err := a.Prefix(64)
	if err != nil {
		return ip
	}
	return p.String()
}

// perPairingChain guards the routes of one pairing: a path id that is not
// a pairing id is the pairing-not-found answer every mismatch gets, before
// the per-pairing limiter can store it as a key.
func perPairingChain(rl *middleware.TelemetryRateLimiter) []Middleware {
	requireID := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if handler.PairingKey(r) == "" {
				protov2.NewProblem(protov2.ProblemPairingNotFound).Write(w)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
	return []Middleware{requireID, pairingLimit(rl, handler.PairingKey)}
}

// pairingLimit refuses a request over the key's budget with the v2
// rate-limited problem and a Retry-After.
func pairingLimit(rl *middleware.TelemetryRateLimiter, key func(*http.Request) string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if k := key(r); k != "" && !rl.Allow(k) {
				w.Header().Set("Retry-After", strconv.Itoa(60))
				protov2.NewProblem(protov2.ProblemRateLimited).Write(w)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// pairingRouteName labels the pairing routes in the v2 metrics.
func pairingRouteName(r *http.Request) string {
	if r.Method == http.MethodPost && r.URL.Path == protov2.PathPrefix+"/pairings" {
		return "pairing_start"
	}
	return "pairing"
}
