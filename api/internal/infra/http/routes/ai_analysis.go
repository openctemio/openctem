package routes

import (
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
)

// registerAIAnalysisRoutes wires AI analysts and their runs
// (docs/architecture/ai-analysis.md):
//
//   - reading analysts: ai_triage:read (every member who uses AI may see who
//     the analysts are and who answers for them);
//   - creating, deleting, changing owners or the preset, and resuming:
//     service_accounts:manage plus a recent sign-in (an analyst is a service
//     account); the role grant ceiling and the owners' ceiling apply in the
//     service;
//   - disabling (the kill switch): service_accounts:manage;
//   - pausing and attesting: ai_triage:read on the route, and in the service
//     an accountable owner, or service_accounts:manage (pause) or an
//     administrator (attest);
//   - runs: findings:read and ai_triage:read, and the caller's data scope on
//     the run's subject in the service.
func registerAIAnalysisRoutes(router Router, h *handler.AIAnalysisHandler, authMiddleware, userSyncMiddleware, moduleGate Middleware) {
	if h == nil {
		return
	}
	tenant := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)
	gated := append(append([]Middleware{}, tenant...), moduleGate)
	manage := middleware.Require(permission.ServiceAccountsManage)
	router.Group("/api/v1/ai/analysts", func(r Router) {
		r.GET("/", h.ListAnalysts, middleware.Require(permission.AITriageRead))
		r.POST("/", h.CreateAnalyst, manage, requireStepUp())
		r.GET("/{id}", h.GetAnalyst, middleware.Require(permission.AITriageRead))
		r.DELETE("/{id}", h.DeleteAnalyst, manage, requireStepUp())
		r.PUT("/{id}/owners", h.SetOwners, manage, requireStepUp())
		r.PUT("/{id}/preset", h.SetPreset, manage, requireStepUp())
		r.POST("/{id}/resume", h.Resume, manage, requireStepUp())
		r.POST("/{id}/disable", h.Disable, manage)
		r.POST("/{id}/pause", h.Pause, middleware.Require(permission.AITriageRead))
		r.POST("/{id}/attest", h.Attest, middleware.Require(permission.AITriageRead))
	}, gated...)
	router.Group("/api/v1/ai/runs", func(r Router) {
		r.GET("/{id}", h.GetRun, middleware.RequireAll(permission.FindingsRead, permission.AITriageRead))
	}, gated...)
	router.Group("/api/v1/findings/{id}/ai", func(r Router) {
		r.GET("/runs", h.ListFindingRuns, middleware.RequireAll(permission.FindingsRead, permission.AITriageRead))
	}, gated...)
}
