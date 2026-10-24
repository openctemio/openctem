package routes

import (
	"net/http"
	"time"

	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
)

// registerFindingImportRoutes registers the upload route POST
// /api/v1/findings/imports and the receipt reads
// (docs/rfcs/RFC-122-ingest-receipts.md).
//
// An import parses up to 110 MiB of hostile input and writes findings, so it
// is limited per organization (not per client address, which members share
// or rotate): 6 per minute, burst 3, across all its members.
func registerFindingImportRoutes(router Router, h *handler.FindingImportHandler, receipts *handler.IngestReceiptHandler,
	authMiddleware, userSyncMiddleware Middleware) {
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)
	importRL := middleware.NewRateLimiter(&config.RateLimitConfig{
		Enabled:         true,
		RequestsPerSec:  6.0 / 60.0,
		Burst:           3,
		CleanupInterval: 5 * time.Minute,
	}, nil)
	router.Group("/api/v1/findings/imports", func(r Router) {
		if h != nil {
			// Findings and assets are written; a VEX document closing findings
			// additionally needs findings:approve, checked in the handler.
			// The route's own body limit replaces the global one (10 MiB by
			// default), which otherwise refused every file above it with a
			// misleading "larger than 110 MiB" answer.
			// coverage=full closes findings in bulk: step-up, as POST
			// /findings/bulk/status closing findings.
			r.POST("/", h.Import,
				middleware.RequireAll(permission.FindingsWrite, permission.AssetsWrite, permission.AssetsImport),
				requireStepUpWhenFullCoverage(),
				importRL.TenantMiddleware(),
				middleware.BodyLimit(handler.MaxFindingImportBody))
		}
		if receipts != nil {
			// Receipts: counts are organization-wide, so a caller without the
			// organization view reads only their own uploads (handler).
			r.GET("/", receipts.List, middleware.Require(permission.FindingsRead))
			r.GET("/{id}", receipts.Get, middleware.Require(permission.FindingsRead))
			r.GET("/{id}/actions", receipts.Actions, middleware.Require(permission.FindingsRead))
			r.GET("/{id}/result", receipts.Result, middleware.Require(permission.FindingsRead))
			r.GET("/{id}/items", receipts.Items, middleware.Require(permission.FindingsRead))
		}
	}, tenantMiddlewares...)
	if receipts != nil {
		router.Group("/api/v1/findings/{id}/imports", func(r Router) {
			r.GET("/", receipts.FindingReceipts, middleware.Require(permission.FindingsRead))
		}, tenantMiddlewares...)
	}
}

// requireStepUpWhenFullCoverage is requireStepUp for an upload that declares
// coverage=full (it closes what it does not report). Any other upload,
// which closes nothing, needs no re-authentication. The query is read the
// way the handler reads it (the first coverage value).
func requireStepUpWhenFullCoverage() Middleware {
	gate := requireStepUp()
	return func(next http.Handler) http.Handler {
		gated := gate(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Query().Get("coverage") == "full" {
				gated.ServeHTTP(w, r)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
