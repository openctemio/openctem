package routes

import (
	"github.com/openctemio/api/internal/infra/http/handler"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/domain/permission"
)

// registerValidationRoutes wires CTEM Stage-4 validation evidence:
//   - agents POST proof-of-fix / technique-execution evidence for a finding,
//     authenticated with the same agent API-key chain as the other ingest
//     endpoints (tenant taken from the agent, never the body).
//   - users GET the evidence recorded for a finding (JWT, findings:read) for the
//     finding detail page.
func registerValidationRoutes(
	router Router,
	h *handler.ValidationHandler,
	ingestHandler *handler.IngestHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
) {
	if h == nil {
		return
	}

	// Agent ingest — API-key auth + ingest body limit.
	if ingestHandler != nil {
		bodyLimit := middleware.BodyLimit(middleware.IngestMaxBodySize)
		router.Group("/api/v1/validation", func(r Router) {
			r.POST("/evidence", h.IngestEvidence, bodyLimit)
		}, ingestHandler.AuthenticateSource)
	}

	// User read — finding evidence list.
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)
	router.Group("/api/v1/findings/{id}/evidence", func(r Router) {
		r.GET("/", h.ListFindingEvidence, middleware.Require(permission.FindingsRead))
	}, tenantMiddlewares...)
}
