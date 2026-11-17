package routes

import (
	"github.com/openctemio/openctem/server/internal/infra/http/handler"
	"github.com/openctemio/openctem/server/internal/infra/http/middleware"
	"github.com/openctemio/openctem/server/pkg/domain/permission"
)

// registerSavedViewRoutes mounts /api/v1/views (saved list views). The
// route asks for the least a caller needs: the read permission of at least
// one list that has views. The service then resolves the request's page key
// in the page registry (pkg/domain/savedview/pages.go) and requires the read
// permission of exactly that page's list: 403 for a list or a save by key,
// 404 for a view read by id (docs/architecture/saved-views.md).
//
// The permissions below are the registry's, spelled out so the route gate
// tools read them; TestSavedViewRouteGateIsTheRegistry fails when the two
// differ.
func registerSavedViewRoutes(router Router, h *handler.SavedViewHandler, authMiddleware, userSyncMiddleware Middleware) {
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)
	router.Group("/api/v1/views", func(r Router) {
		read := middleware.RequireAny(
			permission.APIKeysRead, permission.AssetGroupsRead, permission.AssetsRead, permission.AttackerProfilesRead,
			permission.AuditRead, permission.AutomationsRead, permission.BusinessServicesRead, permission.CIRead,
			permission.CTEMCyclesRead, permission.CompensatingControlsRead, permission.ComplianceFrameworksRead,
			permission.ComponentsRead, permission.ContentPacksRead, permission.CredentialsRead, permission.ExposuresRead,
			permission.FindingsRead, permission.FindingsStatus, permission.GroupsRead, permission.IntegrationsManage,
			permission.IntegrationsRead, permission.MembersRead, permission.PentestCampaignsRead, permission.PentestRead,
			permission.PriorityRulesRead, permission.ProgramsRead, permission.RemediationRead, permission.RolesRead,
			permission.SLARead, permission.ScanProfilesRead, permission.ScanWorkflowsRead,
			permission.ScannerTemplatesRead, permission.ScansRead, permission.ScopeRead, permission.SecretStoreRead,
			permission.SensorEgressRead, permission.SensorsRead, permission.SuppressionsRead, permission.TeamUpdate,
			permission.ThreatIntelRead, permission.ToolsRead, permission.VulnerabilitiesRead,
		)
		r.GET("/", h.List, read)
		r.POST("/", h.Create, read)
		r.GET("/{id}", h.Get, read)
		r.PUT("/{id}", h.Update, read)
		r.DELETE("/{id}", h.Delete, read)
	}, tenantMiddlewares...)
}

// registerNavPinRoutes mounts /api/v1/me/pins: the caller's own sidebar pins
// in the current organization. Any member; view pins need findings:read,
// checked by the service, and every count is computed as the caller.
func registerNavPinRoutes(router Router, h *handler.NavPinHandler, authMiddleware, userSyncMiddleware Middleware) {
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)
	router.Group("/api/v1/me/pins", func(r Router) {
		r.GET("/", h.List)
		r.PUT("/", h.Replace)
	}, tenantMiddlewares...)
}
