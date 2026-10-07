package routes

import (
	"time"

	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Reveal rate limit per user: a burst of 30, refilled at one every 2 s.
const (
	evidenceRevealBurst = 30
	evidenceRevealRPS   = 0.5
)

// registerFindingEvidenceItemRoutes wires a finding's typed evidence
// (docs/architecture/finding-evidence.md) on the token-tenant chain, which
// ends with DataScopeGuard: a finding outside the caller's data scope (or
// another tenant's) is 404 on both routes.
//
// Reading returns masked items (findings:read). Revealing a masked value
// needs findings:evidence:reveal, a per-user rate limit and a recent sign-in
// (step-up; an API key cannot step up, so it can never reveal).
func registerFindingEvidenceItemRoutes(router Router, h *handler.FindingEvidenceItemsHandler, authMiddleware, userSyncMiddleware Middleware, log *logger.Logger) {
	if h == nil {
		return
	}
	limiter := middleware.NewRateLimiter(&config.RateLimitConfig{
		Enabled: true, RequestsPerSec: evidenceRevealRPS, Burst: evidenceRevealBurst, CleanupInterval: time.Minute,
	}, log)
	router.Group("/api/v1/findings/{id}/evidence-items", func(r Router) {
		r.GET("/", h.List, middleware.Require(permission.FindingsRead))
		r.POST("/{item_id}/reveal", h.Reveal, middleware.Require(permission.EvidenceReveal), limiter.UserMiddleware(), requireStepUp())
	}, buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)...)
}

// registerEvidenceSettingsRoutes wires the organization's evidence settings
// under the token singleton /api/v1/organization. Owner/admin only; audited.
func registerEvidenceSettingsRoutes(router Router, h *handler.TenantHandler, authMiddleware, userSyncMiddleware Middleware) {
	if h == nil {
		return
	}
	router.Group("/api/v1/organization/settings/evidence", func(r Router) {
		r.GET("/", h.GetEvidenceSettings, middleware.RequireAdmin())
		r.PUT("/", h.UpdateEvidenceSettings, middleware.RequireAdmin())
	}, buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)...)
}
