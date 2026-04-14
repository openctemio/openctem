package routes

import (
	"github.com/openctemio/api/internal/infra/http/handler"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/domain/permission"
)

// registerAttachmentRoutes registers file attachment endpoints.
//
// Authorization:
//   - Upload: requires pentest:findings:write (create evidence)
//   - Download: requires pentest:findings:read (view evidence)
//     NOTE: context-based auth (campaign membership) is enforced at the handler
//     level by inspecting context_type/context_id and calling
//     ResolveCampaignRoleForFinding or equivalent. This is a defense-in-depth
//     approach because the attachment may not have a context at upload time.
//   - Delete: requires pentest:findings:write (same as upload)
//   - Meta: same as download
//
//nolint:cyclop // Route registration
func registerAttachmentRoutes(
	router Router,
	h *handler.AttachmentHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
) {
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)

	router.Group("/api/v1/attachments", func(r Router) {
		// List by context — requires read permission
		r.GET("/", h.List, middleware.Require(permission.PentestFindingsRead))
		// Upload — requires write permission
		r.POST("/", h.Upload, middleware.Require(permission.PentestFindingsWrite))
		// Download — requires read permission (images served inline for markdown)
		r.GET("/{id}", h.Download, middleware.Require(permission.PentestFindingsRead))
		// Meta — requires read permission
		r.GET("/{id}/meta", h.GetMeta, middleware.Require(permission.PentestFindingsRead))
		// Delete — requires write permission
		r.DELETE("/{id}", h.Delete, middleware.Require(permission.PentestFindingsWrite))
		// Link orphan attachments to a finding after creation
		r.POST("/link", h.LinkToContext, middleware.Require(permission.PentestFindingsWrite))
		// Storage config — admin only
		r.GET("/storage-config", h.GetStorageConfig, middleware.RequireAdmin())
		r.PATCH("/storage-config", h.UpdateStorageConfig, middleware.RequireAdmin())
	}, tenantMiddlewares...)
}
