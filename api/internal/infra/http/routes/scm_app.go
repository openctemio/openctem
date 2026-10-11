package routes

// SCM app installations for CI checks and pull request comments
// (docs/rfcs/RFC-077-ci-enforced-gate-and-pr-feedback.md).
//
//   - /api/v1/ci/scm-apps...: the console session, the scans module and the
//     scans:ci:* permissions (binding an installation is an administrator's
//     act: scans:ci:write).
//   - POST /api/v1/webhooks/incoming/github-app: public; the GitHub App's webhook
//     secret (HMAC-SHA256 over the raw body) is the credential, checked
//     before anything is read. Per-IP limit before the check.

import (
	"time"

	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func registerSCMAppRoutes(router Router, h *handler.SCMAppHandler, authMiddleware, userSyncMiddleware, moduleGate Middleware, log *logger.Logger) {
	if h == nil {
		return
	}
	webhookRL := middleware.NewTelemetryRateLimiter(5, 50, time.Hour, log).
		MiddlewareKeyed(middleware.ClientIPKey, "Webhook rate limit exceeded")
	router.POST("/api/v1/webhooks/incoming/github-app", h.GitHubWebhook, webhookRL)

	router.Group("/api/v1/ci/scm-apps", func(r Router) {
		r.GET("", h.List, middleware.Require(permission.CIRead))
		r.POST("/github/install-url", h.GitHubInstallURL, middleware.Require(permission.CIWrite))
		r.POST("/github/installations", h.CompleteGitHubInstall, middleware.Require(permission.CIWrite))
		r.DELETE("/installations/{id}", h.Remove, middleware.Require(permission.CIWrite))
	}, append(buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware), moduleGate)...)
}
