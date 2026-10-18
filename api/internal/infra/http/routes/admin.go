package routes

import (
	"net/http"

	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
)

// =============================================================================
// Platform Admin Routes
// =============================================================================
//
// These routes are for OpenCTEM platform administrators only.
// They manage shared infrastructure that serves all tenants.
//
// Every admin route requires a verified console session (RFC-022): the
// administrator signed in on /login and passed the TOTP step. There are no
// admin API keys. This is separate from tenant admin routes (RequireTeamAdmin).
//
// AUTHORIZATION MODEL (route-layer, centralized here — do NOT rely on ad-hoc
// in-handler role checks for the guarantee):
//
//	Group                     Read (GET)        Write (POST/PATCH/DELETE)
//	------------------------  ----------------  --------------------------
//	/admin/auth/validate      any admin         —
//	/admin/overview           any admin         —
//	/admin/operations         any admin         —
//	/admin/system             any admin         —
//	/admin/announcements      any admin         ops_admin+ + step-up + reason
//	                                            (audited)
//	/admin/console-sessions   super_admin       super_admin + step-up + reason +
//	                                            fresh code in the body (audited
//	                                            high)
//	/admin/platform-users     ops_admin+ (list  ops_admin+, reason, rate-limited,
//	                          and view audited) audited; platform admins refused;
//	                                            block/unblock: + step-up
//	/admin/users              super_admin       update/delete: super_admin
//	                                            (audited); reset credentials,
//	                                            break-glass test, IdP unbind:
//	                                            super_admin + step-up
//	/admin/administrators     —                 super_admin + step-up (audited)
//	/admin/approvals          super_admin       request: super_admin + step-up;
//	                                            approve: another super_admin
//	                                            (not break-glass) + fresh
//	                                            step-up; reject: step-up;
//	                                            cancel: requester (critical audit)
//	/admin/audit-logs         any admin         —
//	/admin/target-mappings    any admin         ops_admin+ (+ audited)
//	/admin/threat-intel       any admin         sync: ops_admin+ (audited);
//	                                            turn a feed on or off: ops_admin+ +
//	                                            step-up (audited)
//	/admin/platform-idp       super_admin       super_admin + step-up (audited)
//	/admin/access-requests    any admin         ops_admin+ (approve: + step-up;
//	                                            reject; audited)
//	/admin/tenants            any admin         create: ops_admin+ + step-up;
//	                                            first owner: ops_admin+ + fresh
//	                                            step-up (recovery: super_admin +
//	                                            reason + fresh code in the body);
//	                                            SSO writes: super_admin + step-up
//	                                            (audited)
//	/admin/settings/limits    any admin         super_admin + step-up + fresh code
//	                                            in the body
//	/admin/tenants/{id}/limits
//	                          any admin         ops_admin+ + step-up (audited)
//	/admin/tenants/{id}/modules
//	                          any admin         ops_admin+ + step-up + fresh code
//	                                            in the body (deny; audited)
//	/admin/settings/signup    any admin         super_admin + step-up + fresh code
//	                                            in the body (critical audit,
//	                                            admins emailed)
//	/admin/signup-events      any admin         — (sign-up feed: email domain and
//	                                            network prefix only)
//	/admin/settings/signup-alerts
//	                          any admin         read; update: super_admin + step-up
//	                                            + fresh code in the body + reason
//	                                            (critical audit, admins emailed)
//	/admin/settings/legal     any admin         super_admin + step-up + fresh code
//	                                            in the body (critical audit; read
//	                                            publicly at GET /api/v1/legal)
//	/admin/settings/email     any admin         update: super_admin + step-up +
//	                                            fresh code in the body (critical
//	                                            audit, password never returned);
//	                                            test: super_admin, to the
//	                                            caller's address only (no step-up)
//	/admin/settings/console-mfa
//	                          any admin         super_admin + fresh step-up (a
//	                                            fresh code or a single-use
//	                                            security-key confirmation)
//	/admin/auth/factors, webauthn/*, recovery-codes
//	                          own account only  register (options) and new codes:
//	                                            fresh step-up; remove: step-up;
//	                                            rename: session only
//	/admin/auth/elevate       —                 start: step-up; end: session only
//	/admin/support            own grants only   open a session: ops_admin+ named in
//	                                            a live grant + step-up; reads only
//	                                            through a live session (audited in
//	                                            both logs)
//	/admin/settings/scan-approval-policy, /admin/tenants/{id}/scan-approval-policy
//	                          any admin         super_admin + step-up + fresh code
//	                                            in the body + reason (critical
//	                                            audit, admins emailed, tenant
//	                                            admins told)
//	/admin/shared-sensors     any admin (fleet,  pause/resume/retire: super_admin +
//	                          queue, job         step-up + reason (critical audit);
//	                          metadata)          instance enrollment token:
//	                                            super_admin + step-up + fresh code
//	                                            in the body; job view: super/ops
//	                                            admin + reason (audited high,
//	                                            rate-limited)
//	/admin/settings/shared-sensors(/egress), /admin/tenants/{id}/shared-sensors
//	                          any admin         super_admin + step-up + fresh code
//	                                            in the body + reason (critical
//	                                            audit, admins emailed); switch-on
//	                                            refused until shared sensors are
//	                                            ready
//	/admin/instance-scan-zones
//	                          any admin         super_admin + step-up + reason +
//	                                            fresh code in the body
//	/admin/tenants/{id}/dashboard-data
//	                          any admin         rebuild: ops_admin+ (audited; once
//	                                            per hour per organization)
//	/admin/tenants/{id}/audit-chain
//	                          any admin         rebaseline: super_admin + step-up +
//	                                            fresh code in the body (audited,
//	                                            both logs)
//	/admin/content-packs      any admin         super_admin + step-up + reason +
//	                                            fresh code in the body (audited
//	                                            with the reason)
//	/admin/content-catalog    any admin         import, publish, revoke: super_admin +
//	                                            step-up + reason + fresh code in
//	                                            the body (audited)
//	/admin/version-check      any admin         import: super_admin + step-up
//	                                            (audited high)
//	/admin/auth/idp*          public (sign-in)  public, rate-limited
//
// "step-up" is the route-level gate (middleware.RequireAdminStepUp): a fresh
// authenticator code in X-Admin-Step-Up, or the five-minute step-up window of
// the same console session. "fresh step-up" (RequireAdminFreshStepUp) never
// uses the window. "fresh code in the body" is the older check in the handler
// (confirmAdminStepUp: a code in the request body, every time), which many
// routes keep on top of the route-level step-up.
//
// A super administrator's write is also recorded before it runs (the
// "admin.write_started" row of AuditMiddleware.WriteAhead); when that row
// cannot be written the request is refused with 503 AUDIT_UNAVAILABLE.
//
// registerAdminRoutes registers all platform admin endpoints.
// These are privileged operations for managing shared infrastructure.
// Admin routes authenticate the console session, not the tenant session.
// crossSite (middleware.RejectCrossSiteBrowser; nil in route-shape tests)
// guards the console's sign-in steps, which run before a console session and
// its admin_csrf cookie exist.
func registerAdminRoutes(
	router Router,
	h Handlers,
	crossSite Middleware,
) {
	// ==========================================================================
	// Console-session authenticated routes
	// ==========================================================================
	if h.AdminAuthMiddleware == nil {
		return
	}

	// The console network check first, on every console route (the
	// server-wide gate already ran on the raw path; this one sees what was
	// routed here).
	// Every console response is no-store (sessions, CSRF tokens, admin data).
	netGate := []Middleware{consoleNoStore}
	if h.AdminNetwork != nil {
		netGate = append(netGate, h.AdminNetwork)
	}

	// Base chain: the network check, then a verified console session (any role).
	// A super administrator's write is on record before it runs; when the
	// audit log cannot be written the write is refused (authedWrite is the
	// session check followed by that write-ahead row).
	authedWrite := h.AdminAuthMiddleware.Authenticate
	if h.AdminAuditMiddleware != nil {
		authenticate, writeAhead := h.AdminAuthMiddleware.Authenticate, h.AdminAuditMiddleware.WriteAhead()
		authedWrite = func(next http.Handler) http.Handler { return authenticate(writeAhead(next)) }
	}
	adminMiddlewares := append(cloneMW(netGate), authedWrite)

	// Super-admin group guard, composed onto the base chain. Built here so the
	// authorization guarantee lives at the route layer, not in handlers.
	// (append onto a fresh slice so the shared base chain is never aliased.)
	superAdminOnly := append(append([]Middleware{}, adminMiddlewares...),
		h.AdminAuthMiddleware.RequireRole(admin.AdminRoleSuperAdmin))

	// stepUp is the route-level step-up of a protected action: a fresh
	// authenticator code in X-Admin-Step-Up, or the step-up window of the same
	// console session. Every identity, privilege and platform-trust change
	// takes it; adminWriteInventory (admin_step_up_inventory_test.go) lists
	// every console write and fails on one that is not classified.
	stepUp := func(purpose string) Middleware {
		return middleware.RequireAdminStepUp(h.AdminStepUp, purpose)
	}

	// freshStepUp is for adding or replacing a sign-in factor and turning the
	// factor policy: a fresh code or a single-use security-key confirmation,
	// never the session's step-up window.
	freshStepUp := func(purpose string) Middleware {
		return middleware.RequireAdminFreshStepUp(h.AdminStepUp, purpose)
	}

	// Auth: one group (chi cannot mount the same prefix twice), so the guard is
	// per route. /validate needs a verified console session. The console signs
	// in on its own: /login checks the account's email and password and opens
	// a pending console session, /mfa completes it. No tenant session is read.
	if h.AdminAuth != nil || h.AdminConsole != nil {
		consoleRL := newAuthRateLimiter("console")
		loginRL := consoleRL.LoginMiddleware()
		// The same chain as every other authenticated console route, so a
		// super administrator's password, factor and elevation changes are
		// written ahead too.
		authed := authedWrite

		router.Group("/api/v1/admin/auth", func(r Router) {
			if h.AdminAuth != nil {
				r.GET("/validate", h.AdminAuth.Validate, authed)
			}
			if h.AdminConsole != nil {
				r.POST("/login", h.AdminConsole.Login, preSession(crossSite, loginRL)...)
				r.POST("/mfa", h.AdminConsole.VerifyMFA, preSession(crossSite, loginRL)...)
				r.POST("/logout", h.AdminConsole.Logout, preSession(crossSite)...)
				r.POST("/password", h.AdminConsole.ChangePassword, consoleRL.PasswordMiddleware(), authed)
				// Security keys and recovery codes (RFC-078). The sign-in steps
				// share the TOTP step's login bucket and pending cookie.
				r.POST("/webauthn/session/options", h.AdminConsole.WebAuthnLoginOptions, preSession(crossSite, loginRL)...)
				r.POST("/webauthn/session", h.AdminConsole.WebAuthnLogin, preSession(crossSite, loginRL)...)
				r.POST("/recovery", h.AdminConsole.RecoveryLogin, preSession(crossSite, loginRL)...)
				r.GET("/factors", h.AdminConsole.Factors, authed)
				r.POST("/webauthn/credentials/options", h.AdminConsole.WebAuthnRegisterOptions, authed, freshStepUp("webauthn.register"))
				r.POST("/webauthn/credentials", h.AdminConsole.WebAuthnRegister, authed)
				r.PATCH("/webauthn/credentials/{id}", h.AdminConsole.WebAuthnRename, authed)
				r.DELETE("/webauthn/credentials/{id}", h.AdminConsole.WebAuthnRemove, authed, stepUp("webauthn.remove"))
				r.POST("/recovery-codes", h.AdminConsole.GenerateRecoveryCodes, authed, freshStepUp("recovery_codes.generate"))
				r.POST("/step-up/webauthn/options", h.AdminConsole.WebAuthnStepUpOptions, authed)
				r.POST("/step-up/webauthn", h.AdminConsole.WebAuthnStepUp, consoleRL.LoginMiddleware(), authed)
				// Time-boxed elevation: read-only until the session elevates
				// (a fresh confirmation); ending it is always allowed.
				r.POST("/elevate", h.AdminConsole.Elevate, authed, stepUp("console.elevate"))
				r.DELETE("/elevate", h.AdminConsole.EndElevation, authed)
				// Platform identity provider sign-in (RFC-022 revision 4). Not a
				// credential-guessing surface (the IdP authenticates, the state is
				// single use), so it uses the token-exchange bucket (20/min) rather
				// than the 5/min login bucket: behind the UI proxy every
				// administrator shares one client IP, and one IdP sign-in is
				// start + callback + the TOTP step. The TOTP step (/mfa) stays on
				// the login bucket.
				idpRL := consoleRL.TokenExchangeMiddleware()
				r.GET("/idp", h.AdminConsole.IdPInfo)
				r.POST("/idp/start", h.AdminConsole.IdPStart, preSession(crossSite, idpRL)...)
				r.POST("/idp/callback", h.AdminConsole.IdPCallback, preSession(crossSite, idpRL)...)
			}
		}, netGate...)
	}

	// Support access (RFC-063): the administrator a grant names opens a
	// support session with a step-up and reads through it. Every read is
	// authorized live and audited in both logs by the handler; there is no
	// write route.
	if h.AdminSupport != nil {
		supportChain := append(append([]Middleware{}, adminMiddlewares...),
			h.AdminAuthMiddleware.RequireRole(admin.AdminRoleSuperAdmin, admin.AdminRoleOpsAdmin))
		router.Group("/api/v1/admin/support", func(r Router) {
			r.GET("/grants", h.AdminSupport.Grants)
			r.POST("/grants/{grant_id}/sessions", h.AdminSupport.StartSession, stepUp("support.session_start"))
			r.DELETE("/sessions/{session_id}", h.AdminSupport.EndSession)
			r.GET("/sessions/{session_id}/overview", h.AdminSupport.Overview)
			r.GET("/sessions/{session_id}/findings", h.AdminSupport.Findings)
			r.GET("/sessions/{session_id}/findings/{id}", h.AdminSupport.Finding)
			r.GET("/sessions/{session_id}/assets", h.AdminSupport.Assets)
			r.GET("/sessions/{session_id}/assets/{id}", h.AdminSupport.Asset)
		}, supportChain...)
	}

	// Build identity for the console's Help > About (any admin role).
	router.GET("/api/v1/admin/version", handler.Version, adminMiddlewares...)

	// The console overview's attention queue (any admin role): counts only,
	// no tenant content and no administrator emails.
	if h.AdminOverview != nil {
		router.GET("/api/v1/admin/overview", h.AdminOverview.Get, adminMiddlewares...)
	}
	// System > Announcements: any admin reads; ops_admin+ publishes or ends
	// one with a reason (audited).
	if h.Announcement != nil {
		opsAnn := []Middleware{h.AdminAuthMiddleware.RequireRole(admin.AdminRoleSuperAdmin, admin.AdminRoleOpsAdmin)}
		// A banner every user of every organization sees is a phishing
		// channel in a hijacked session: publishing or ending one needs a
		// step-up.
		annAudit := func(action string) []Middleware {
			out := append(cloneMW(opsAnn), stepUp(action))
			if h.AdminAuditMiddleware != nil {
				out = append(out, h.AdminAuditMiddleware.AuditLog(action, "announcement", "announcement_id"))
			}
			return out
		}
		router.Group("/api/v1/admin/announcements", func(r Router) {
			r.GET("/", h.Announcement.AdminList)
			r.POST("/", h.Announcement.AdminCreate, annAudit("announcement.create")...)
			r.POST("/{announcement_id}/cancel", h.Announcement.AdminEnd, annAudit("announcement.cancel")...)
		}, adminMiddlewares...)
	}

	// Console > Operations (any admin role): build, schema, database, Redis,
	// work queues, sensor versions, controllers. Infrastructure facts only.
	if h.AdminOperations != nil {
		router.GET("/api/v1/admin/operations", h.AdminOperations.Get, adminMiddlewares...)
	}

	// Console > System (RFC-114): service health, free space, backup age,
	// certificate expiry, version. Read-only, any admin role, aggregates only.
	if h.AdminSystem != nil {
		router.GET("/api/v1/admin/system", h.AdminSystem.Get, adminMiddlewares...)
	}

	// Default limits of self-service organizations (Console > System >
	// Limits): any admin reads; a super admin changes them with a fresh
	// authenticator code (checked in the handler, audited critical).
	if h.Limits != nil {
		requireSuperLimits := h.AdminAuthMiddleware.RequireRole(admin.AdminRoleSuperAdmin)
		router.Group("/api/v1/admin/settings/limits", func(r Router) {
			r.GET("/", h.Limits.GetSelfServiceDefaults)
			r.PUT("/", h.Limits.UpdateSelfServiceDefaults, requireSuperLimits, stepUp("settings.limits"))
		}, adminMiddlewares...)
	}

	// The sign-up policy (Console > System > Sign-up): who may create an
	// organization. Any admin reads; a super admin changes it with a fresh
	// authenticator code (checked in the handler, which also writes the
	// critical audit row and tells the other administrators).
	// One group per prefix (chi cannot mount the same prefix twice): the
	// super-admin guard is on the PUT route.
	if h.AdminSignup != nil {
		requireSuper := h.AdminAuthMiddleware.RequireRole(admin.AdminRoleSuperAdmin)
		router.Group("/api/v1/admin/settings/signup", func(r Router) {
			r.GET("/", h.AdminSignup.Get)
			r.PUT("/", h.AdminSignup.Update, requireSuper, stepUp("settings.signup"))
		}, adminMiddlewares...)
	}

	// The sign-up feed (Console > Requests > Sign-ups) and its burst alert
	// thresholds: any admin reads; a super admin changes the thresholds with
	// a reason and a fresh authenticator code (critical audit, admins
	// emailed). The feed holds email domains and network prefixes only.
	if h.AdminSignupEvents != nil {
		requireSuper := h.AdminAuthMiddleware.RequireRole(admin.AdminRoleSuperAdmin)
		router.Group("/api/v1/admin/signup-events", func(r Router) {
			r.GET("/", h.AdminSignupEvents.List)
			r.GET("/daily", h.AdminSignupEvents.Daily)
		}, adminMiddlewares...)
		router.Group("/api/v1/admin/settings/signup-alerts", func(r Router) {
			r.GET("/", h.AdminSignupEvents.GetThresholds)
			r.PUT("/", h.AdminSignupEvents.UpdateThresholds, requireSuper, stepUp("settings.signup_alerts"))
		}, adminMiddlewares...)
	}

	// Console MFA policy ("require security keys", RFC-078): any admin reads;
	// a super admin changes it with a step-up.
	if h.AdminConsole != nil {
		requireSuper := h.AdminAuthMiddleware.RequireRole(admin.AdminRoleSuperAdmin)
		router.Group("/api/v1/admin/settings/console-mfa", func(r Router) {
			r.GET("/", h.AdminConsole.GetMFAPolicy)
			r.PUT("/", h.AdminConsole.PutMFAPolicy, requireSuper, freshStepUp("settings.console_mfa"))
		}, adminMiddlewares...)
	}

	// Platform e-mail (Console > System > E-mail, RFC-079): any admin reads;
	// a super admin changes it with a fresh authenticator code and sends the
	// test message (to their own address only).
	if h.AdminEmail != nil {
		requireSuper := h.AdminAuthMiddleware.RequireRole(admin.AdminRoleSuperAdmin)
		router.Group("/api/v1/admin/settings/email", func(r Router) {
			r.GET("/", h.AdminEmail.Get)
			r.PUT("/", h.AdminEmail.Update, requireSuper, stepUp("settings.email"))
			r.POST("/test", h.AdminEmail.SendTest, requireSuper)
		}, adminMiddlewares...)
	}

	// Settings moved from the environment into the console (RFC-079).
	registerAdminPlatformSettingsRoutes(router, h, adminMiddlewares, stepUp, freshStepUp)

	// Legal information (Console > System > Legal, RFC-079): any admin reads;
	// a super admin changes it with a fresh authenticator code.
	if h.AdminLegal != nil {
		requireSuper := h.AdminAuthMiddleware.RequireRole(admin.AdminRoleSuperAdmin)
		router.Group("/api/v1/admin/settings/legal", func(r Router) {
			r.GET("/", h.AdminLegal.Get)
			r.PUT("/", h.AdminLegal.Update, requireSuper, stepUp("settings.legal"))
		}, adminMiddlewares...)
	}

	// Scope-widening approvals (RFC-054 §12.6): any admin reads; a super
	// admin changes the platform default with a fresh authenticator code and
	// a reason (checked in the handler; the service audits and notifies).
	if h.AdminScanPolicy != nil {
		requireSuper := h.AdminAuthMiddleware.RequireRole(admin.AdminRoleSuperAdmin)
		router.Group("/api/v1/admin/settings/scan-approval-policy", func(r Router) {
			r.GET("/", h.AdminScanPolicy.GetDefault)
			r.PUT("/", h.AdminScanPolicy.UpdateDefault, requireSuper, stepUp("settings.scan_approval"))
		}, adminMiddlewares...)
		// Verified domain before platform sensors scan (RFC-054 §8.1):
		// same gate, step-up and audit.
		router.Group("/api/v1/admin/settings/platform-sensor-proof", func(r Router) {
			r.GET("/", h.AdminScanPolicy.GetProof)
			r.PUT("/", h.AdminScanPolicy.UpdateProof, requireSuper, stepUp("settings.platform_sensor_proof"))
		}, adminMiddlewares...)
		// Shared sensor access (RFC-100 §5): same gate, step-up and audit;
		// turning the switch on is refused until shared sensors are ready.
		router.Group("/api/v1/admin/settings/shared-sensors", func(r Router) {
			r.GET("/", h.AdminScanPolicy.GetSharedSensors)
			r.PUT("/", h.AdminScanPolicy.UpdateSharedSensors, requireSuper, stepUp("settings.shared_sensors"))
			// Egress addresses organizations see to allowlist the scanners.
			r.GET("/egress", h.AdminScanPolicy.GetSharedSensorsEgress)
			r.PUT("/egress", h.AdminScanPolicy.UpdateSharedSensorsEgress, requireSuper, stepUp("settings.shared_sensors_egress"))
		}, adminMiddlewares...)
		// Shared sensors may scan internal zones, and the anomaly alert
		// thresholds (RFC-100 §6, §9): same gate, step-up and audit.
		router.Group("/api/v1/admin/settings/shared-sensor-internal-zones", func(r Router) {
			r.GET("/", h.AdminScanPolicy.GetSharedSensorInternalZones)
			r.PUT("/", h.AdminScanPolicy.UpdateSharedSensorInternalZones, requireSuper, stepUp("settings.shared_sensor_internal_zones"))
		}, adminMiddlewares...)
		router.Group("/api/v1/admin/settings/shared-sensor-anomaly", func(r Router) {
			r.GET("/", h.AdminScanPolicy.GetSharedSensorAnomaly)
			r.PUT("/", h.AdminScanPolicy.UpdateSharedSensorAnomaly, requireSuper, stepUp("settings.shared_sensor_anomaly"))
		}, adminMiddlewares...)
	}

	// Instance scan zones (RFC-100 §6.1): any admin reads; a super admin
	// changes a zone, its shared sensors and its organizations with a fresh
	// code and a reason (the service records it with the job signer first
	// and writes the critical audit row).
	if h.AdminInstanceScanZone != nil {
		requireSuper := h.AdminAuthMiddleware.RequireRole(admin.AdminRoleSuperAdmin)
		z := h.AdminInstanceScanZone
		router.Group("/api/v1/admin/instance-scan-zones", func(r Router) {
			r.GET("/", z.List)
			r.POST("/", z.Create, requireSuper, stepUp("instance_scan_zone.create"))
			r.GET("/{zone_id}", z.Get)
			r.PUT("/{zone_id}", z.Update, requireSuper, stepUp("instance_scan_zone.update"))
			r.DELETE("/{zone_id}", z.Delete, requireSuper, stepUp("instance_scan_zone.delete"))
			r.PUT("/{zone_id}/sensors", z.SetSensors, requireSuper, stepUp("instance_scan_zone.sensors"))
			r.PUT("/{zone_id}/organizations", z.SetOrganizations, requireSuper, stepUp("instance_scan_zone.organizations"))
		}, adminMiddlewares...)
	}

	// Shared sensors (RFC-100). Fleet (§12): any admin reads the fleet, queue
	// aggregates and job metadata; a job's targets and logs only through
	// the audited view with a reason (super or ops admin, rate-limited);
	// pause, resume and retire need a super admin, a reason and a fresh code.
	// Enrollment (§7): a super admin issues a single-use instance enrollment
	// token with a reason and a fresh console authenticator code (checked in
	// the handler; the service writes the console audit row). One group:
	// the prefix can be mounted only once.
	if h.AdminSharedFleet != nil || h.AdminSharedSensor != nil {
		requireSuper := h.AdminAuthMiddleware.RequireRole(admin.AdminRoleSuperAdmin)
		router.Group("/api/v1/admin/shared-sensors", func(r Router) {
			if f := h.AdminSharedFleet; f != nil {
				view := []Middleware{h.AdminAuthMiddleware.RequireRole(admin.AdminRoleSuperAdmin, admin.AdminRoleOpsAdmin)}
				if h.AdminSupportRateLimiter != nil {
					view = append(view, h.AdminSupportRateLimiter.WriteMiddleware())
				}
				r.GET("/", f.List)
				r.GET("/queue", f.Queue)
				r.GET("/jobs", f.Jobs)
				r.POST("/jobs/{job_id}/view", f.ViewJob, view...)
				r.POST("/{sensor_id}/disable", f.Pause, requireSuper, stepUp("shared_sensor.pause"))
				r.POST("/{sensor_id}/enable", f.Resume, requireSuper, stepUp("shared_sensor.resume"))
				r.POST("/{sensor_id}/revoke", f.Retire, requireSuper, stepUp("shared_sensor.retire"))
			}
			if h.AdminSharedSensor != nil {
				r.POST("/enrollment-tokens", h.AdminSharedSensor.CreateInstanceEnrollmentToken, requireSuper,
					stepUp("shared_sensors.enrollment_token"))
			}
		}, adminMiddlewares...)
	}

	// The request-access queue: any admin reads; approving (creates the
	// organization, requester as owner) or rejecting needs ops_admin+, audited.
	if h.AccessRequest != nil {
		requireOps := h.AdminAuthMiddleware.RequireRole(admin.AdminRoleSuperAdmin, admin.AdminRoleOpsAdmin)
		decide := func(action string, extra ...Middleware) []Middleware {
			mws := append([]Middleware{requireOps}, extra...)
			if h.AdminAuditMiddleware != nil {
				mws = append(mws, h.AdminAuditMiddleware.AuditLog(action, "access_request", "id"))
			}
			return mws
		}
		router.Group("/api/v1/admin/access-requests", func(r Router) {
			r.GET("/", h.AccessRequest.List)
			// Approving creates an organization with the requester as owner:
			// an identity change, so it takes step-up.
			r.POST("/{id}/approve", h.AccessRequest.Approve, decide("access_request.approve", stepUp("access_request.approve"))...)
			r.POST("/{id}/reject", h.AccessRequest.Reject, decide("access_request.reject")...)
		}, adminMiddlewares...)
	}

	// Version check (RFC-105): any admin reads the status; importing the
	// signed release feed file (air-gapped instances) needs super_admin and
	// the step-up, audited high.
	if h.AdminVersionCheck != nil {
		requireSuper := h.AdminAuthMiddleware.RequireRole(admin.AdminRoleSuperAdmin)
		vc := h.AdminVersionCheck
		router.Group("/api/v1/admin/version-check", func(r Router) {
			r.GET("/", vc.Status)
			r.POST("/import", vc.Import, requireSuper, stepUp("version_check.import"))
			// Switching the daily check: an egress and privacy decision.
			r.PUT("/enabled", vc.SetEnabled, requireSuper, stepUp("version_check.switch"))
		}, adminMiddlewares...)
	}

	// Configuration overview: any admin reads where each setting comes from.
	if h.AdminConfiguration != nil {
		router.GET("/api/v1/admin/configuration", h.AdminConfiguration.List, adminMiddlewares...)
	}

	if h.AdminContentCatalog != nil {
		// Import: super_admin here; the handler adds the reason, a fresh
		// console authenticator code and its own high admin audit row.
		requireSuper := h.AdminAuthMiddleware.RequireRole(admin.AdminRoleSuperAdmin)
		c := h.AdminContentCatalog
		router.Group("/api/v1/admin/content-catalog", func(r Router) {
			r.GET("/", c.Status)
			r.GET("/packages", c.Packages)
			r.GET("/packages/{namespace}/{name}/versions", c.PackageVersions)
			r.POST("/import", c.Import, requireSuper, stepUp("content_catalog.change"))
			r.POST("/packages", c.Publish, requireSuper, stepUp("content_catalog.change"))
			r.POST("/packages/revoke", c.Revoke, requireSuper, stepUp("content_catalog.change"))
		}, adminMiddlewares...)
	}

	if h.PlatformContentPack != nil {
		// Writes: super_admin here; the handler adds the reason, a fresh
		// console authenticator code (confirmAdminStepUp) and its own admin
		// audit row carrying the reason.
		requireSuper := h.AdminAuthMiddleware.RequireRole(admin.AdminRoleSuperAdmin)
		p := h.PlatformContentPack
		router.Group("/api/v1/admin/content-packs", func(r Router) {
			r.GET("/", p.List)
			r.GET("/channels", p.Channels)
			r.GET("/signing-key", p.SigningKey)
			r.GET("/{id}", p.Get)
			r.GET("/{id}/download", p.Download)
			r.POST("/", p.Upload, requireSuper, stepUp("content_pack.change"))
			r.POST("/import", p.Import, requireSuper, stepUp("content_pack.change"))
			r.POST("/{id}/revoke", p.Revoke, requireSuper, stepUp("content_pack.change"))
			r.PUT("/channels/{channel}", p.SetChannel, requireSuper, stepUp("content_pack.change"))
		}, adminMiddlewares...)
	}

	// Provisioning a platform administrator (always a new users-table
	// account). Super admin only, with step-up; the service writes the audit
	// row (console.admin_provisioned).
	if h.AdminConsole != nil {
		router.Group("/api/v1/admin/administrators", func(r Router) {
			r.POST("/", h.AdminConsole.Provision, stepUp("admin.provision"))
		}, superAdminOnly...)

		// The administrators' identity provider (System -> Admin sign-in):
		// who may sign in to the console, so every change takes step-up. The
		// service writes high-severity audit rows for every change.
		router.Group("/api/v1/admin/platform-idp", func(r Router) {
			r.GET("/", h.AdminConsole.GetPlatformIdP)
			r.PUT("/", h.AdminConsole.PutPlatformIdP, stepUp("platform_idp.update"))
			r.DELETE("/", h.AdminConsole.DeletePlatformIdP, stepUp("platform_idp.delete"))
		}, superAdminOnly...)
	}

	// Security > Approvals (four-eyes): a super admin asks with a reason and
	// a step-up; another super admin approves with a fresh step-up (never
	// their own request, never a break-glass account) or rejects; the
	// requester may cancel. The service writes the critical audit rows.
	if h.AdminApproval != nil {
		router.Group("/api/v1/admin/approvals", func(r Router) {
			r.GET("/", h.AdminApproval.List)
			r.POST("/", h.AdminApproval.Create, stepUp("approval.request"))
			r.POST("/{id}/approve", h.AdminApproval.Approve, freshStepUp("approval.approve"))
			r.POST("/{id}/reject", h.AdminApproval.Reject, stepUp("approval.reject"))
			r.POST("/{id}/cancel", h.AdminApproval.Cancel)
		}, superAdminOnly...)
	}

	// Organizations (RFC-022 Phase 2): the platform admin's cross-tenant view,
	// organization creation, and per-organization SSO. Reads are open to any
	// admin; creating an organization needs ops_admin+; SSO changes (the
	// organization's login trust) need super_admin. SAML, identity-provider and
	// verified-domain setup reuse the tenant handlers under AdminTenantScope,
	// which sets the path organization as the request tenant.
	if h.AdminOrganization != nil {
		opsWrite := h.AdminAuthMiddleware.RequireRole(admin.AdminRoleSuperAdmin, admin.AdminRoleOpsAdmin)
		superWrite := h.AdminAuthMiddleware.RequireRole(admin.AdminRoleSuperAdmin)
		scope := middleware.AdminTenantScope(h.AdminOrganization.TenantExists)
		audit := func(action string) []Middleware {
			if h.AdminAuditMiddleware == nil {
				return nil
			}
			return []Middleware{h.AdminAuditMiddleware.AuditLog(action, "tenant", middleware.AdminTenantParam)}
		}
		with := func(mws ...[]Middleware) []Middleware {
			out := []Middleware{}
			for _, m := range mws {
				out = append(out, m...)
			}
			return out
		}
		read := []Middleware{scope}
		// Grant-bypass paths (RFC-063 section 11.5): console routes that reach
		// the organization's data without a support grant. Never blocked; each
		// use goes to the organization's audit log and its owners' email.
		bypass := func(route string, repeatable bool) []Middleware {
			if h.AdminSupport == nil {
				return nil
			}
			return []Middleware{h.AdminSupport.TenantDataNotice(route, repeatable)}
		}
		// Organization SSO writes change who may sign in to the organization:
		// super admin, step-up, audited.
		ssoStepUp := stepUp("organization.sso_change")
		write := func(action string) []Middleware {
			return with([]Middleware{superWrite, ssoStepUp, scope}, audit(action))
		}

		router.Group("/api/v1/admin/tenants", func(r Router) {
			r.GET("/", h.AdminOrganization.List)
			r.POST("/", h.AdminOrganization.Create, with([]Middleware{opsWrite, stepUp("organization.create")}, audit("organization.create"))...)
			r.GET("/{tenantId}", h.AdminOrganization.Get)

			// Organization users: list, and bootstrap the FIRST owner of an
			// organization that has none (RFC-022 rev. 5). The platform
			// administrator never adds users to an organization that has an
			// owner (409); the owner and its administrators do that.
			// The member list is personal data: every view is audited, and a
			// read-only administrator gets counts only (the handler redacts).
			r.GET("/{tenantId}/users", h.AdminOrganization.ListUsers, with(read, bypass("user list", true), audit("organization.users_view"))...)
			// Creating the first owner (or recovering one) hands an
			// organization to a person: step-up.
			r.POST("/{tenantId}/users", h.AdminOrganization.CreateUser,
				with([]Middleware{opsWrite, freshStepUp("organization.owner_create"), scope}, bypass("owner create or recovery", false), audit("organization.user_create"))...)

			// Suspend / lift (docs/architecture/organization-suspension.md):
			// cuts or restores every credential of the organization at once.
			// ops_admin+ (abuse response), a fresh authenticator code, a
			// reason; the service writes the critical admin audit row.
			if h.AdminSuspension != nil {
				r.POST("/{tenantId}/suspend", h.AdminSuspension.SuspendOrganization, opsWrite, stepUp("organization.suspend"), scope)
				r.POST("/{tenantId}/unsuspend", h.AdminSuspension.UnsuspendOrganization, opsWrite, stepUp("organization.unsuspend"), scope)
				// Delete now (docs/architecture/organization-deletion.md):
				// irreversible, so super_admin and a fresh code, not the
				// step-up window.
				r.POST("/{tenantId}/purge", h.AdminSuspension.PurgeOrganization, superWrite, freshStepUp("organization.purge"), scope)
			}

			r.GET("/{tenantId}/sso/enforcement", h.AdminOrganization.GetSSOEnforcement)
			r.PUT("/{tenantId}/sso/enforcement", h.AdminOrganization.SetSSOEnforcement,
				with([]Middleware{superWrite, ssoStepUp}, audit("organization.sso_enforcement"))...)

			if h.SAML != nil {
				r.GET("/{tenantId}/sso/saml", h.SAML.GetConfig, read...)
				r.PUT("/{tenantId}/sso/saml", h.SAML.SetConfig, write("organization.saml_update")...)
				r.DELETE("/{tenantId}/sso/saml", h.SAML.DeleteConfig, write("organization.saml_delete")...)
			}
			// SAML and identity-provider creates/updates from here wait for an
			// owner of the organization (unless it has no owner yet); the
			// admin sees what is pending.
			if h.SSOChange != nil {
				r.GET("/{tenantId}/sso/changes", h.SSOChange.AdminList, read...)
			}
			if h.SSO != nil {
				r.GET("/{tenantId}/sso/identity-providers", h.SSO.ListProviders, read...)
				r.POST("/{tenantId}/sso/identity-providers", h.SSO.CreateProvider, with(write("organization.idp_create"), bypass("identity provider creation", false))...)
				r.GET("/{tenantId}/sso/identity-providers/{id}", h.SSO.GetProvider, read...)
				r.PUT("/{tenantId}/sso/identity-providers/{id}", h.SSO.UpdateProvider, write("organization.idp_update")...)
				r.DELETE("/{tenantId}/sso/identity-providers/{id}", h.SSO.DeleteProvider, write("organization.idp_delete")...)
			}
			// The organization's audit hash-chain: classify (any admin) and
			// rebaseline (super_admin). The rebaseline handler also demands a
			// fresh authenticator code and writes its own high-severity admin
			// audit row (with the rebaseline id and the outcome), so it does not
			// take the generic audit middleware.
			if h.AdminAuditChain != nil {
				r.GET("/{tenantId}/audit-chain", h.AdminAuditChain.Classify, read...)
				r.POST("/{tenantId}/audit-chain/rebaseline", h.AdminAuditChain.Rebaseline, superWrite, stepUp("organization.audit_chain_rebaseline"), scope)
			}

			// Dashboard data of an organization (docs/architecture/dashboards.md,
			// "Facts maintainer"): any admin reads the status; ops_admin+ asks
			// for a rebuild of derived data (once per hour per organization,
			// shared with the organization's own request; audited, no step-up:
			// no identity, privilege or trust changes).
			if h.DashboardFacts != nil {
				r.GET("/{tenantId}/dashboard-data", h.DashboardFacts.ConsoleStatus, read...)
				r.POST("/{tenantId}/dashboard-data/rebuild", h.DashboardFacts.ConsoleRequestRebuild,
					with([]Middleware{opsWrite, scope}, audit("organization.dashboard_data_rebuild"))...)
			}

			// Idle policy of an organization (off by default): any admin
			// reads; ops_admin+ turns it on or off (audited by the service).
			if h.IdleWorkspace != nil {
				r.GET("/{tenantId}/idle", h.IdleWorkspace.Get, read...)
				r.PUT("/{tenantId}/idle/policy", h.IdleWorkspace.SetPolicy, with([]Middleware{opsWrite, stepUp("organization.idle_policy"), scope})...)
			}

			// Limits of one organization: any admin reads (with usage and the
			// over-limit flag); ops_admin+ sets or removes one (audited by
			// the service).
			if h.Limits != nil {
				r.GET("/{tenantId}/limits", h.Limits.GetTenantLimits, read...)
				// A limit of 0 freezes an organization: step-up like module denies.
				r.PUT("/{tenantId}/limits/{key}", h.Limits.SetTenantLimit, with([]Middleware{opsWrite, stepUp("organization.limit"), scope})...)
				r.DELETE("/{tenantId}/limits/{key}", h.Limits.DeleteTenantLimit, with([]Middleware{opsWrite, stepUp("organization.limit"), scope})...)
				// Modules of one organization: any admin reads; ops_admin+
				// denies one or lifts the deny with a fresh authenticator code
				// (audited by the service; a denied module keeps read access
				// for the grace period).
				r.GET("/{tenantId}/modules", h.Limits.GetTenantModules, read...)
				r.PUT("/{tenantId}/modules/{module_id}/deny", h.Limits.SetModuleDeny, with([]Middleware{opsWrite, stepUp("organization.module_deny"), scope})...)
				r.DELETE("/{tenantId}/modules/{module_id}/deny", h.Limits.DeleteModuleDeny, with([]Middleware{opsWrite, stepUp("organization.module_deny"), scope})...)
			}

			// The organization's scope approval policy (RFC-054 §12.6): any
			// admin reads; a super admin changes it with a fresh code and a
			// reason (the service writes the critical audit row).
			if h.AdminScanPolicy != nil {
				r.GET("/{tenantId}/scan-approval-policy", h.AdminScanPolicy.GetOrganization, read...)
				r.PUT("/{tenantId}/scan-approval-policy", h.AdminScanPolicy.UpdateOrganization, superWrite, stepUp("organization.scan_approval"), scope)
				// Shared sensor access of the organization (RFC-100 §5):
				// allow, deny or the instance default; same gate.
				r.GET("/{tenantId}/shared-sensors", h.AdminScanPolicy.GetOrganizationSharedSensors, read...)
				r.PUT("/{tenantId}/shared-sensors", h.AdminScanPolicy.UpdateOrganizationSharedSensors, superWrite, stepUp("organization.shared_sensors"), scope)
			}

			if h.VerifiedDomain != nil {
				r.GET("/{tenantId}/sso/verified-domains", h.VerifiedDomain.List, read...)
				r.POST("/{tenantId}/sso/verified-domains", h.VerifiedDomain.AddDomain, write("organization.domain_add")...)
				r.POST("/{tenantId}/sso/verified-domains/{id}/verify", h.VerifiedDomain.Verify, write("organization.domain_verify")...)
				r.DELETE("/{tenantId}/sso/verified-domains/{id}", h.VerifiedDomain.Delete, write("organization.domain_delete")...)
				r.PATCH("/{tenantId}/sso/verified-domains/{id}", h.VerifiedDomain.UpdateJIT, write("organization.domain_jit")...)
			}
		}, adminMiddlewares...)
	}

	// Console > Users (RFC-022): find an account across
	// organizations (any admin; viewing one is audited) and run a support
	// action on it (ops_admin+, reason required, rate-limited, audited).
	// Account-level facts only, never organization data.
	if h.AdminPlatformUser != nil {
		opsSupport := []Middleware{h.AdminAuthMiddleware.RequireRole(admin.AdminRoleSuperAdmin, admin.AdminRoleOpsAdmin)}
		if h.AdminSupportRateLimiter != nil {
			opsSupport = append(opsSupport, h.AdminSupportRateLimiter.WriteMiddleware())
		}
		audited := func(action string, base []Middleware) []Middleware {
			out := cloneMW(base)
			if base != nil {
				// Account support actions change a person's sign-in state:
				// step-up on each.
				out = append(out, stepUp(action))
			}
			if h.AdminAuditMiddleware != nil {
				out = append(out, h.AdminAuditMiddleware.AuditLog(action, "user", "user_id"))
			}
			return out
		}
		// Finding people by email is personal data: ops_admin+ (a read-only
		// administrator sees counts elsewhere, never accounts).
		opsRead := []Middleware{h.AdminAuthMiddleware.RequireRole(admin.AdminRoleSuperAdmin, admin.AdminRoleOpsAdmin)}
		router.Group("/api/v1/admin/platform-users", func(r Router) {
			r.GET("/", h.AdminPlatformUser.List, opsRead...)
			r.GET("/{user_id}", h.AdminPlatformUser.Get, append(cloneMW(opsRead), audited("platform_user.view", nil)...)...)
			r.POST("/{user_id}/revoke-sessions", h.AdminPlatformUser.RevokeSessions, audited("platform_user.revoke_sessions", opsSupport)...)
			r.POST("/{user_id}/unlock", h.AdminPlatformUser.Unlock, audited("platform_user.unlock", opsSupport)...)
			r.POST("/{user_id}/password-reset", h.AdminPlatformUser.SendPasswordReset, audited("platform_user.password_reset", opsSupport)...)
			r.POST("/{user_id}/verification-emails", h.AdminPlatformUser.ResendVerification, audited("platform_user.resend_verification", opsSupport)...)
			// Block / unblock platform-wide: ops_admin+, step-up, reason; the
			// service writes the critical admin audit row.
			if h.AdminSuspension != nil {
				r.POST("/{user_id}/block", h.AdminSuspension.BlockUser, append(cloneMW(opsSupport), stepUp("platform_user.block"))...)
				r.POST("/{user_id}/unblock", h.AdminSuspension.UnblockUser, append(cloneMW(opsSupport), stepUp("platform_user.unblock"))...)
			}
		}, adminMiddlewares...)
	}

	// Security > Sessions: every administrator's open console session, and
	// ending one (reason + fresh authenticator code, audited high). Super
	// admin only, like the roster.
	if h.AdminSession != nil {
		router.Group("/api/v1/admin/console-sessions", func(r Router) {
			r.GET("/", h.AdminSession.List)
			end := []Middleware{stepUp("console.session_end")}
			if h.AdminAuditMiddleware != nil {
				end = append(end, h.AdminAuditMiddleware.AuditLog("console.session_ended", "admin_session", "console_session_id"))
			}
			r.DELETE("/{console_session_id}", h.AdminSession.End, end...)
		}, superAdminOnly...)
	}

	// Admin user management — the platform admin roster (emails, last-used
	// IPs). New administrators are added through /admin/administrators. Restricted to super_admin for BOTH reads and writes:
	// only super_admin CanManageAdmins, and the roster itself is sensitive
	// (AUTHZ-8: List/Get were previously ungated, so any admin key — including
	// readonly — could enumerate all admins). Writes are additionally audited.
	if h.AdminUser != nil {
		// Every roster write changes an administrator's identity or
		// privilege: step-up on each, audited.
		var auditUpdate, auditDelete []Middleware
		if h.AdminAuditMiddleware != nil {
			auditUpdate = []Middleware{h.AdminAuditMiddleware.AuditAdminUpdate()}
			auditDelete = []Middleware{h.AdminAuditMiddleware.AuditAdminDelete()}
		}
		withAudit := func(purpose string, audit []Middleware) []Middleware {
			return append([]Middleware{stepUp(purpose)}, audit...)
		}
		router.Group("/api/v1/admin/users", func(r Router) {
			r.GET("/", h.AdminUser.List)
			r.GET("/{id}", h.AdminUser.Get)
			r.PATCH("/{id}", h.AdminUser.Update, withAudit("admin.update", auditUpdate)...)
			r.DELETE("/{id}", h.AdminUser.Delete, withAudit("admin.delete", auditDelete)...)
			if h.AdminConsole != nil {
				// The console service writes these audit rows itself.
				r.POST("/{id}/reset-credentials", h.AdminConsole.ResetCredentials, stepUp("admin.reset_credentials"))
				r.POST("/{id}/break-glass-test", h.AdminConsole.ConfirmBreakGlassTest, stepUp("admin.break_glass_test"))
				r.DELETE("/{id}/idp-binding", h.AdminConsole.UnbindIdP, stepUp("admin.idp_unbind"))
			}
		}, superAdminOnly...)
	}

	// Audit log endpoints — read-only, viewable by ANY admin role (readonly
	// included: CanViewAuditLogs is true for all three roles).
	if h.AdminAudit != nil {
		router.Group("/api/v1/admin/audit-logs", func(r Router) {
			r.GET("/", h.AdminAudit.List)
			r.GET("/stats", h.AdminAudit.GetStats)
			// The hash chain's state (append-only log, migration 002545).
			r.GET("/chain", h.AdminAudit.VerifyChain)
			r.GET("/{id}", h.AdminAudit.Get)
		}, adminMiddlewares...)
	}

	// Threat-intelligence feeds (EPSS, CISA KEV): platform-wide, so only the
	// platform administrator runs or toggles their sync. Reads: any admin.
	// Writes: ops_admin+, audited.
	if h.ThreatIntel != nil {
		router.Group("/api/v1/admin/threat-intel", func(r Router) {
			r.GET("/sync", h.ThreatIntel.GetSyncStatuses)
			feedWrite := []Middleware{h.AdminAuthMiddleware.RequireRole(admin.AdminRoleSuperAdmin, admin.AdminRoleOpsAdmin)}
			// Turning a feed off changes every organization's prioritization.
			syncMW, toggleMW := cloneMW(feedWrite), append(cloneMW(feedWrite), stepUp("threat_intel.sync_toggle"))
			if h.AdminAuditMiddleware != nil {
				syncMW = append(syncMW, h.AdminAuditMiddleware.AuditLog("threat_intel.sync", "threat_intel_feed", ""))
				toggleMW = append(toggleMW, h.AdminAuditMiddleware.AuditLog("threat_intel.sync_toggle", "threat_intel_feed", ""))
			}
			r.POST("/sync", h.ThreatIntel.TriggerSync, syncMW...)
			r.PATCH("/sync/{source}", h.ThreatIntel.SetSyncEnabled, toggleMW...)
		}, adminMiddlewares...)
	}

	// AI applications (MCP clients, RFC-062 §12). Reads: any admin, counts
	// only. Block / unblock: ops_admin+, audited.
	if h.MCPConnections != nil {
		router.Group("/api/v1/admin/mcp-clients", func(r Router) {
			r.GET("/", h.MCPConnections.AdminListClients)
			write := []Middleware{h.AdminAuthMiddleware.RequireRole(admin.AdminRoleSuperAdmin, admin.AdminRoleOpsAdmin)}
			// Unblocking readmits an application that was cut off: both
			// directions need a step-up.
			block, unblock := append(cloneMW(write), stepUp("mcp_client.block")), append(cloneMW(write), stepUp("mcp_client.unblock"))
			if h.AdminAuditMiddleware != nil {
				block = append(block, h.AdminAuditMiddleware.AuditLog("mcp_client.blocked", "mcp_client", "id"))
				unblock = append(unblock, h.AdminAuditMiddleware.AuditLog("mcp_client.unblocked", "mcp_client", "id"))
			}
			r.POST("/{id}/block", h.MCPConnections.AdminBlockClient, block...)
			r.POST("/{id}/unblock", h.MCPConnections.AdminUnblockClient, unblock...)
		}, adminMiddlewares...)
	}

	// Target mapping management (scanner target type -> asset type).
	// Reads: any admin. Writes: ops_admin+ (readonly rejected) — target
	// mappings are shared platform configuration, gated at the route layer to
	// match the domain's CanManage* semantics. Writes are rate-limited + audited.
	if h.AdminTargetMapping != nil {
		router.Group("/api/v1/admin/target-mappings", func(r Router) {
			// Read operations — any authenticated admin.
			r.GET("/stats", h.AdminTargetMapping.GetStats)
			r.GET("/types", h.AdminTargetMapping.Types)
			r.GET("/", h.AdminTargetMapping.List)
			r.GET("/{id}", h.AdminTargetMapping.Get)

			// Write operations — ops_admin+, rate-limited, and (when wired) audited.
			var writeMiddlewares []Middleware
			writeMiddlewares = append(writeMiddlewares, h.AdminAuthMiddleware.RequireRole(admin.AdminRoleSuperAdmin, admin.AdminRoleOpsAdmin))
			if h.AdminMappingRateLimiter != nil {
				writeMiddlewares = append(writeMiddlewares, h.AdminMappingRateLimiter.WriteMiddleware())
			}

			if h.AdminAuditMiddleware != nil {
				r.POST("/", h.AdminTargetMapping.Create, append(cloneMW(writeMiddlewares), h.AdminAuditMiddleware.AuditTargetMappingCreate())...)
				r.PATCH("/{id}", h.AdminTargetMapping.Update, append(cloneMW(writeMiddlewares), h.AdminAuditMiddleware.AuditTargetMappingUpdate())...)
				r.DELETE("/{id}", h.AdminTargetMapping.Delete, append(cloneMW(writeMiddlewares), h.AdminAuditMiddleware.AuditTargetMappingDelete())...)
			} else {
				r.POST("/", h.AdminTargetMapping.Create, cloneMW(writeMiddlewares)...)
				r.PATCH("/{id}", h.AdminTargetMapping.Update, cloneMW(writeMiddlewares)...)
				r.DELETE("/{id}", h.AdminTargetMapping.Delete, cloneMW(writeMiddlewares)...)
			}
		}, adminMiddlewares...)
	}
}

// cloneMW returns a copy of the middleware slice so appending a per-route
// middleware (e.g. an audit factory) cannot mutate the shared write chain.
func cloneMW(mws []Middleware) []Middleware {
	return append([]Middleware{}, mws...)
}

// preSession prepends the cross-site guard (when set) to a route's middlewares.
func preSession(crossSite Middleware, mws ...Middleware) []Middleware {
	if crossSite == nil {
		return mws
	}
	return append([]Middleware{crossSite}, mws...)
}

// consoleNoStore marks every console response no-store: the sign-in and
// validate responses carry the session's CSRF token, and every other one
// carries administrators' data. No shared or browser cache may keep them.
func consoleNoStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}
