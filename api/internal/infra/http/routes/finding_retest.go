package routes

import (
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
)

// registerFindingRetestRoutes wires continuous retest (RFC-039) on its own
// /api/v1/findings/{id}/retests mount, on the token-tenant chain — which ends
// with DataScopeGuard, so a restricted member gets 404 for a finding outside
// their scope.
//
// "Retest now" needs findings:verify: a clean retest resolves the finding, the
// same segregation-of-duties permission a person needs to resolve it.
func registerFindingRetestRoutes(router Router, h *handler.FindingRetestHandler, authMiddleware, userSyncMiddleware Middleware) {
	if h == nil {
		return
	}
	router.Group("/api/v1/findings/{id}/retests", func(r Router) {
		r.GET("/", h.List, middleware.Require(permission.FindingsRead))
		r.POST("/", h.Request, middleware.Require(permission.FindingsVerify))
	}, buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)...)
}

// registerRetestSettingsRoutes wires the organization's auto-retest settings
// (RFC-039) under the token singleton /api/v1/organization: the tenant comes
// from the credential, never from the path (docs/architecture/api-conventions.md
// §2). Owner/admin only; changes are audited.
func registerRetestSettingsRoutes(router Router, h *handler.TenantHandler, authMiddleware, userSyncMiddleware Middleware) {
	if h == nil {
		return
	}
	router.Group("/api/v1/organization/settings/retest", func(r Router) {
		r.GET("/", h.GetRetestSettings, middleware.RequireAdmin())
		r.PUT("/", h.UpdateRetestSettings, middleware.RequireAdmin())
	}, buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)...)
}

// registerVulnMatchingSettingsRoutes wires the organization's vulnerability
// matching policy (RFC-066 §9) under the token singleton
// /api/v1/organization. Owner/admin only; changes are audited.
func registerVulnMatchingSettingsRoutes(router Router, h *handler.TenantHandler, authMiddleware, userSyncMiddleware Middleware) {
	if h == nil {
		return
	}
	router.Group("/api/v1/organization/settings/vuln-matching", func(r Router) {
		r.GET("/", h.GetVulnMatchingSettings, middleware.RequireAdmin())
		r.PUT("/", h.UpdateVulnMatchingSettings, middleware.RequireAdmin())
	}, buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)...)
}

// registerAssetReconciliationSettingsRoutes wires which sources decide asset
// attributes (RFC-069) under the token singleton /api/v1/organization.
// Owner/admin only; changes are audited.
func registerAssetReconciliationSettingsRoutes(router Router, h *handler.TenantHandler, authMiddleware, userSyncMiddleware Middleware) {
	if h == nil {
		return
	}
	router.Group("/api/v1/organization/settings/asset-reconciliation", func(r Router) {
		r.GET("/", h.GetAssetReconciliationSettings, middleware.RequireAdmin())
		r.PUT("/", h.UpdateAssetReconciliationSettings, middleware.RequireAdmin())
		r.POST("/preview", h.PreviewAssetReconciliationSettings, middleware.RequireAdmin())
	}, buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)...)
}

// registerScanGovernanceRoutes wires the organization's scan approval
// settings (RFC-072) under the token singleton /api/v1/organization. Reads:
// scans:read. The mode: owner only; the rules: owner or administrator; both
// need step-up re-authentication and a reason, and are audited.
func registerScanGovernanceRoutes(router Router, h *handler.ScanGovernanceHandler, authMiddleware, userSyncMiddleware Middleware) {
	if h == nil {
		return
	}
	router.Group("/api/v1/organization/settings/scan-governance", func(r Router) {
		r.GET("/", h.Get, middleware.Require(permission.ScansRead))
		r.PUT("/mode", h.UpdateMode, middleware.RequireOwner(), requireStepUp())
		r.PUT("/rules", h.UpdateRules, middleware.RequireAdmin(), requireStepUp())
	}, buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)...)
}

// registerScanApprovalRoutes wires the scan approvals inbox and decisions
// (RFC-072). Reads: scans:read. Approve, reject and self-approve:
// scans:approve (the service checks the rule's approvers and that the
// requester never approves). Remind and withdraw: scans:write.
func registerScanApprovalRoutes(router Router, h *handler.ScanApprovalHandler, authMiddleware, userSyncMiddleware Middleware) {
	if h == nil {
		return
	}
	router.Group("/api/v1/scan-approvals", func(r Router) {
		r.GET("/", h.List, middleware.Require(permission.ScansRead))
		r.GET("/{id}", h.Get, middleware.Require(permission.ScansRead))
		r.POST("/{id}/approve", h.Approve, middleware.Require(permission.ScansApprove))
		r.POST("/{id}/reject", h.Reject, middleware.Require(permission.ScansApprove))
		r.POST("/{id}/self-approve", h.SelfApprove, middleware.Require(permission.ScansApprove))
		r.POST("/{id}/remind", h.Remind, middleware.Require(permission.ScansWrite))
		r.POST("/{id}/cancel", h.Cancel, middleware.Require(permission.ScansWrite))
	}, buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)...)
}
