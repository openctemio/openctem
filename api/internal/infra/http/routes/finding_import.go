package routes

import (
	"time"

	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
)

// registerFindingImportRoutes registers POST /api/v1/findings/import.
//
// An import parses up to 110 MiB of hostile input and writes findings, so it
// is limited per organization (not per client address, which members share
// or rotate): 6 per minute, burst 3, across all its members.
func registerFindingImportRoutes(router Router, h *handler.FindingImportHandler, authMiddleware, userSyncMiddleware Middleware) {
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)
	importRL := middleware.NewRateLimiter(&config.RateLimitConfig{
		Enabled:         true,
		RequestsPerSec:  6.0 / 60.0,
		Burst:           3,
		CleanupInterval: 5 * time.Minute,
	}, nil)
	router.Group("/api/v1/findings/import", func(r Router) {
		// Findings and assets are written; a VEX document closing findings
		// additionally needs findings:approve, checked in the handler.
		r.POST("/", h.Import, findingImportMiddlewares(importRL)...)
	}, tenantMiddlewares...)
}

// findingImportMiddlewares is the import route's own chain. Its body limit
// replaces the global one (10 MiB by default), which otherwise refused every
// file above it with a misleading "larger than 110 MiB" answer.
func findingImportMiddlewares(importRL *middleware.RateLimiter) []Middleware {
	return []Middleware{
		middleware.RequireAll(permission.FindingsWrite, permission.AssetsWrite, permission.AssetsImport),
		importRL.TenantMiddleware(),
		middleware.BodyLimit(handler.MaxFindingImportBody),
	}
}
