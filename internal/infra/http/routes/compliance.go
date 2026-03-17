package routes

import (
	"github.com/openctemio/api/internal/infra/http/handler"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/domain/permission"
)

// registerComplianceRoutes registers all compliance framework management endpoints.
func registerComplianceRoutes(
	router Router,
	h *handler.ComplianceHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
) {
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)

	// Framework routes
	router.Group("/api/v1/compliance/frameworks", func(r Router) {
		r.GET("/", h.ListFrameworks, middleware.Require(permission.ComplianceFrameworksRead))
		r.GET("/{id}", h.GetFramework, middleware.Require(permission.ComplianceFrameworksRead))
		r.GET("/{id}/controls", h.ListControls, middleware.Require(permission.ComplianceFrameworksRead))
		r.GET("/{id}/stats", h.GetFrameworkStats, middleware.Require(permission.ComplianceFrameworksRead))
	}, tenantMiddlewares...)

	// Control routes (direct access by control ID)
	router.Group("/api/v1/compliance/controls", func(r Router) {
		r.GET("/{id}", h.GetControl, middleware.Require(permission.ComplianceFrameworksRead))
		r.POST("/{id}/assess", h.UpdateAssessment, middleware.Require(permission.ComplianceAssessmentsWrite))
	}, tenantMiddlewares...)

	// Assessment routes
	router.Group("/api/v1/compliance/assessments", func(r Router) {
		r.GET("/", h.ListAssessments, middleware.Require(permission.ComplianceAssessmentsRead))
	}, tenantMiddlewares...)

	// Stats route
	router.Group("/api/v1/compliance/stats", func(r Router) {
		r.GET("/", h.GetComplianceStats, middleware.Require(permission.ComplianceFrameworksRead))
	}, tenantMiddlewares...)

	// Finding-to-control mapping routes
	router.Group("/api/v1/compliance/findings", func(r Router) {
		r.GET("/{findingId}/controls", h.GetFindingControls, middleware.Require(permission.ComplianceMappingsRead))
		r.POST("/{findingId}/controls", h.MapFindingToControl, middleware.Require(permission.ComplianceMappingsWrite))
		r.DELETE("/{findingId}/controls/{mappingId}", h.UnmapFindingFromControl, middleware.Require(permission.ComplianceMappingsWrite))
	}, tenantMiddlewares...)
}
