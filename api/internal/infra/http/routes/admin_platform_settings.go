package routes

import (
	"net/http"

	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
)

// registerAdminPlatformSettingsRoutes mounts the settings that moved from
// the environment into the console (RFC-079):
//
//	/admin/settings/captcha        any admin   PUT: super_admin + fresh step-up + reason
//	                                           (critical audit, admins told);
//	                                           verify: super_admin
//	/admin/settings/region         any admin   PUT (once, before the first
//	                                           organization): super_admin + fresh
//	                                           step-up + reason (critical audit)
//	/admin/settings/storage-quota  any admin   PUT: super_admin + step-up (audited)
//	/admin/settings/alerts         any admin   PUT: super_admin + fresh step-up + reason
//	                                           (critical audit, admins told);
//	                                           test: super_admin
//	/admin/settings/ai             any admin   PUT: super_admin + fresh step-up + reason
//	                                           (critical audit, admins told);
//	                                           test: super_admin
//
// Secrets are never returned by any of them.
func registerAdminPlatformSettingsRoutes(router Router, h Handlers, adminMiddlewares []Middleware,
	stepUp, freshStepUp func(purpose string) Middleware) {
	ps := h.AdminPlatformSettings
	if ps == nil {
		return
	}
	requireSuper := h.AdminAuthMiddleware.RequireRole(admin.AdminRoleSuperAdmin)
	// A setting whose service is not wired answers 503 (the routes always
	// exist, so the route inventories see them).
	on := func(wired bool, f http.HandlerFunc) http.HandlerFunc {
		if wired {
			return f
		}
		return func(w http.ResponseWriter, _ *http.Request) {
			apierror.ServiceUnavailable("This setting is not available").WriteJSON(w)
		}
	}
	captcha, region, quota, alerts, ai := ps.Captcha != nil, ps.Region != nil, ps.StorageQuota != nil, ps.Alerts != nil, ps.AI != nil
	router.Group("/api/v1/admin/settings/captcha", func(r Router) {
		r.GET("/", on(captcha, ps.GetCaptcha))
		r.PUT("/", on(captcha, ps.UpdateCaptcha), requireSuper, freshStepUp("settings.captcha"))
		r.POST("/verify", on(captcha, ps.VerifyCaptcha), requireSuper)
	}, adminMiddlewares...)
	router.Group("/api/v1/admin/settings/region", func(r Router) {
		r.GET("/", on(region, ps.GetRegion))
		r.PUT("/", on(region, ps.SetRegion), requireSuper, freshStepUp("settings.region"))
	}, adminMiddlewares...)
	router.Group("/api/v1/admin/settings/storage-quota", func(r Router) {
		r.GET("/", on(quota, ps.GetStorageQuota))
		r.PUT("/", on(quota, ps.UpdateStorageQuota), requireSuper, stepUp("settings.storage_quota"))
	}, adminMiddlewares...)
	router.Group("/api/v1/admin/settings/alerts", func(r Router) {
		r.GET("/", on(alerts, ps.GetAlertWebhook))
		r.PUT("/", on(alerts, ps.UpdateAlertWebhook), requireSuper, freshStepUp("settings.alerts"))
		r.POST("/test", on(alerts, ps.TestAlertWebhook), requireSuper)
	}, adminMiddlewares...)
	router.Group("/api/v1/admin/settings/ai", func(r Router) {
		r.GET("/", on(ai, ps.GetPlatformAI))
		r.PUT("/", on(ai, ps.UpdatePlatformAI), requireSuper, freshStepUp("settings.ai"))
		r.POST("/test", on(ai, ps.TestPlatformAI), requireSuper)
	}, adminMiddlewares...)
}
