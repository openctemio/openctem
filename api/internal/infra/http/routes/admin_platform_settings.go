package routes

import (
	"net/http"

	"github.com/openctemio/openctem/api/pkg/apierror"
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
//	/admin/settings/threat-intel-source  any admin   PUT: super_admin + step-up (audited)
//	/admin/settings/alerts         any admin   PUT: super_admin + fresh step-up + reason
//	                                           (critical audit, admins told);
//	                                           test: super_admin
//	/admin/settings/auth-mfa       any admin   PUT: super_admin + fresh step-up + reason
//	                                           (critical audit, admins told)
//	/admin/settings/email-relay    any admin   PUT: super_admin + fresh step-up + reason
//	                                           (critical audit, admins told)
//	/admin/settings/ai             any admin   PUT: super_admin + fresh step-up + reason
//	                                           (critical audit, admins told);
//	                                           test: super_admin
//	/admin/settings/social-login-providers   any admin   PUT /{provider}: super_admin + fresh step-up
//	                                           + reason (critical audit, admins told);
//	                                           test: super_admin
//
// Secrets are never returned by any of them.
func registerAdminPlatformSettingsRoutes(router Router, h Handlers, adminMiddlewares []Middleware,
	stepUp, freshStepUp func(purpose string) Middleware) {
	ps := h.AdminPlatformSettings
	if ps == nil {
		return
	}
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
	threatSource := ps.ThreatSource != nil
	social := ps.SocialLogin != nil
	// The client check asks a provider with a secret: bounded like a sign-in
	// attempt, in its own bucket.
	checkRL := newAuthRateLimiter("console-settings-check").LoginMiddleware()
	router.Group("/api/v1/admin/settings/captcha", func(r Router) {
		r.GET("/", on(captcha, ps.GetCaptcha))
		r.PUT("/", on(captcha, ps.UpdateCaptcha), freshStepUp("settings.captcha"))
		r.POST("/verify", on(captcha, ps.VerifyCaptcha))
	}, adminMiddlewares...)
	router.Group("/api/v1/admin/settings/region", func(r Router) {
		r.GET("/", on(region, ps.GetRegion))
		r.PUT("/", on(region, ps.SetRegion), freshStepUp("settings.region"))
	}, adminMiddlewares...)
	router.Group("/api/v1/admin/settings/storage-quota", func(r Router) {
		r.GET("/", on(quota, ps.GetStorageQuota))
		r.PUT("/", on(quota, ps.UpdateStorageQuota), stepUp("settings.storage_quota"))
	}, adminMiddlewares...)
	router.Group("/api/v1/admin/settings/threat-intel-source", func(r Router) {
		r.GET("/", on(threatSource, ps.GetThreatSource))
		r.PUT("/", on(threatSource, ps.UpdateThreatSource), stepUp("settings.threat_intel_source"))
	}, adminMiddlewares...)
	scanIdent := ps.ScanIdentity != nil
	router.Group("/api/v1/admin/settings/scan-identification", func(r Router) {
		r.GET("/", on(scanIdent, ps.GetScanIdentification))
		r.PUT("/", on(scanIdent, ps.UpdateScanIdentification), stepUp("settings.scan_identification"))
	}, adminMiddlewares...)
	mfaFloor := ps.MFA != nil
	router.Group("/api/v1/admin/settings/auth-mfa", func(r Router) {
		r.GET("/", on(mfaFloor, ps.GetMFAFloor))
		r.PUT("/", on(mfaFloor, ps.UpdateMFAFloor), freshStepUp("settings.auth_mfa"))
	}, adminMiddlewares...)
	emailRelay := ps.EmailRelay != nil
	router.Group("/api/v1/admin/settings/email-relay", func(r Router) {
		r.GET("/", on(emailRelay, ps.GetEmailRelay))
		r.PUT("/", on(emailRelay, ps.UpdateEmailRelay), freshStepUp("settings.email_relay"))
	}, adminMiddlewares...)
	router.Group("/api/v1/admin/settings/alerts", func(r Router) {
		r.GET("/", on(alerts, ps.GetAlertWebhook))
		r.PUT("/", on(alerts, ps.UpdateAlertWebhook), freshStepUp("settings.alerts"))
		r.POST("/test", on(alerts, ps.TestAlertWebhook))
	}, adminMiddlewares...)
	router.Group("/api/v1/admin/settings/ai", func(r Router) {
		r.GET("/", on(ai, ps.GetPlatformAI))
		r.PUT("/", on(ai, ps.UpdatePlatformAI), freshStepUp("settings.ai"))
		r.POST("/test", on(ai, ps.TestPlatformAI))
		r.PUT("/org-policy", on(ai, ps.UpdateOrgAIPolicy), freshStepUp("settings.ai_org_policy"))
	}, adminMiddlewares...)
	router.Group("/api/v1/admin/settings/social-login-providers", func(r Router) {
		r.GET("/", on(social, ps.GetSocialLogin))
		r.PUT("/{provider}", on(social, ps.UpdateSocialLogin), freshStepUp("settings.social_login"))
		r.POST("/{provider}/test", on(social, ps.CheckSocialLogin), checkRL)
	}, adminMiddlewares...)
}
