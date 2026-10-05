package routes

// CI runner identity and the CI gate (docs/rfcs/RFC-051-ci-runner-identity-and-gate.md).
//
// Three kinds of caller share /api/v1/ci, each with its own chain on each
// route (one chi mount, no group middleware):
//
//   - POST /oidc/exchange: public. A CI job's OIDC token is the credential;
//     shared per-IP token-exchange rate limit, 32 KB body.
//   - /runs/{id}/{results,baseline-diff,evaluate}: a run upload token
//     (octci_..., 15 minutes, one run on one repository). Per-run rate
//     limit; results add the ingest per-tenant limit and concurrency cap.
//   - everything else: the console session (token-tenant chain), the scans
//     module and scans:ci:* permissions.

import (
	"net/http"
	"time"

	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Budgets. A run uploads a handful of reports and evaluates once. Hosted CI
// runners share egress addresses, so the per-IP budgets are wider than a
// person's sign-in budget.
const (
	ciRunRatePerSecond  = 2.0
	ciRunBurst          = 30
	ciIPRatePerSecond   = 10.0
	ciIPBurst           = 100
	ciExchangePerMinute = 60
)

func registerCIRoutes(
	router Router,
	admin *handler.CIAdminHandler,
	runner *handler.CIRunnerHandler,
	authMiddleware, userSyncMiddleware, moduleGate Middleware,
	ingestRateLimiter *middleware.TelemetryRateLimiter,
	log *logger.Logger,
) {
	var exchangeRL, runRL Middleware
	var runChain, resultsChain []Middleware
	if runner != nil {
		cfg := middleware.DefaultAuthRateLimitConfig()
		cfg.TokenExchangeRatePerMin = ciExchangePerMinute
		exchangeRL = middleware.NewDistributedAuthRateLimiter(cfg, nil, authRateLimitBackend, "ci-oidc").TokenExchangeMiddleware()
		// Before the token lookup: a client guessing tokens is throttled by
		// address before it reaches the database.
		ipRL := middleware.NewTelemetryRateLimiter(ciIPRatePerSecond, ciIPBurst, time.Hour, log).
			MiddlewareKeyed(middleware.ClientIPKey, "CI rate limit exceeded")
		runLimiter := middleware.NewTelemetryRateLimiter(ciRunRatePerSecond, ciRunBurst, time.Hour, log)
		runRL = runLimiter.MiddlewareKeyed(func(r *http.Request) string {
			if run := handler.CIRunFromContext(r.Context()); run != nil {
				return run.ID.String()
			}
			return ""
		}, "CI run rate limit exceeded")
		runChain = []Middleware{ipRL, runner.AuthenticateRun, runRL}
		resultsChain = append(append([]Middleware{}, runChain...), ingestMiddlewareChain(ingestRateLimiter,
			middleware.NewTenantConcurrencyLimiter(IngestMaxConcurrentPerTenant),
			middleware.BodyLimit(middleware.IngestMaxBodySize), middleware.DecompressForIngest())...)
	}

	// Pipeline routes: their own authentication, mounted on the root router
	// (the console group below carries the session chain).
	if runner != nil {
		router.POST("/api/v1/ci/oidc/exchange", runner.Exchange, exchangeRL)
		router.POST("/api/v1/ci/runs/{id}/results", runner.UploadResults, resultsChain...)
		router.POST("/api/v1/ci/runs/{id}/baseline-diff", runner.BaselineDiff, runChain...)
		router.POST("/api/v1/ci/runs/{id}/evaluate", runner.Evaluate, runChain...)
	}
	if admin == nil {
		return
	}
	router.Group("/api/v1/ci", func(r Router) {
		r.GET("/trust-configs", admin.ListTrustConfigs, middleware.Require(permission.CIRead))
		r.POST("/trust-configs", admin.CreateTrustConfig, middleware.Require(permission.CIWrite))
		r.GET("/trust-configs/{id}", admin.GetTrustConfig, middleware.Require(permission.CIRead))
		r.PUT("/trust-configs/{id}", admin.UpdateTrustConfig, middleware.Require(permission.CIWrite))
		r.DELETE("/trust-configs/{id}", admin.DeleteTrustConfig, middleware.Require(permission.CIWrite))

		r.GET("/pipelines", admin.ListPipelines, middleware.Require(permission.CIRead))
		r.GET("/pipelines/{id}", admin.GetPipeline, middleware.Require(permission.CIRead))
		r.POST("/pipelines/{id}/retire", admin.RetirePipeline, middleware.Require(permission.CIWrite))

		r.GET("/coverage", admin.GetCoverage, middleware.Require(permission.CIRead))
		r.PUT("/coverage/expectations/{id}", admin.SetCoverageExpectation, middleware.Require(permission.CIWrite))
		r.DELETE("/coverage/expectations/{id}", admin.DeleteCoverageExpectation, middleware.Require(permission.CIWrite))

		r.GET("/runs", admin.ListRuns, middleware.Require(permission.CIRead))
		r.GET("/runs/{id}", admin.GetRun, middleware.Require(permission.CIRead))

		r.GET("/gate-policies", admin.ListGatePolicies, middleware.Require(permission.CIRead))
		r.POST("/gate-policies", admin.CreateGatePolicy, middleware.Require(permission.CIWrite))
		r.PATCH("/gate-policies/{id}", admin.UpdateGatePolicy, middleware.Require(permission.CIWrite))
		r.DELETE("/gate-policies/{id}", admin.DeleteGatePolicy, middleware.Require(permission.CIWrite))

		r.GET("/gate-overrides", admin.ListOverrides, middleware.Require(permission.CIRead))
		r.POST("/gate-overrides", admin.CreateOverride, middleware.Require(permission.CIOverride), requireStepUp())
		r.POST("/gate-overrides/{id}/revoke", admin.RevokeOverride, middleware.Require(permission.CIOverride))
	}, append(buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware), moduleGate)...)
}
