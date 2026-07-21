package routes

import (
	"github.com/openctemio/api/internal/infra/http/handler"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/domain/permission"
)

// registerValidationRoutes wires CTEM Stage-4 validation evidence plus the
// manual (operator-added) evidence endpoints. Both share the single
// /api/v1/findings/{id}/evidence chi mount — chi forbids a second mount on the
// same path, so all evidence routes for a finding are registered here:
//   - agents POST proof-of-fix / technique-execution evidence for a finding,
//     authenticated with the same agent API-key chain as the other ingest
//     endpoints (tenant taken from the agent, never the body).
//   - users GET the validation evidence recorded for a finding (JWT, findings:read).
//   - users POST a manual evidence note and GET the manual evidence notes
//     (JWT; findings:write / findings:read) — served by the vulnerability
//     handler's tenant-scoped, pentest-gate-free path.
func registerValidationRoutes(
	router Router,
	h *handler.ValidationHandler,
	vulnHandler *handler.VulnerabilityHandler,
	ingestHandler *handler.IngestHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
) {
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)

	// Agent ingest — API-key auth + ingest body limit.
	if h != nil && ingestHandler != nil {
		bodyLimit := middleware.BodyLimit(middleware.IngestMaxBodySize)
		router.Group("/api/v1/validation", func(r Router) {
			r.POST("/evidence", h.IngestEvidence, bodyLimit)
		}, ingestHandler.AuthenticateSource)
	}

	// Single /evidence mount hosts validation-evidence read + manual evidence
	// read/write. Registered whenever either handler is present.
	if h != nil || vulnHandler != nil {
		router.Group("/api/v1/findings/{id}/evidence", func(r Router) {
			if h != nil {
				// Validation (proof-of-fix / technique) evidence list.
				r.GET("/", h.ListFindingEvidence, middleware.Require(permission.FindingsRead))
			}
			if vulnHandler != nil {
				// Manual evidence note: add + list. The list lives on /notes so
				// it does not collide with the validation GET on "/".
				r.POST("/", vulnHandler.AddFindingEvidence, middleware.Require(permission.FindingsWrite))
				r.GET("/notes", vulnHandler.ListFindingEvidence, middleware.Require(permission.FindingsRead))
			}
		}, tenantMiddlewares...)
	}

	if h != nil {
		router.Group("/api/v1/validation/coverage", func(r Router) {
			r.GET("/", h.Coverage, middleware.Require(permission.FindingsRead))
		}, tenantMiddlewares...)
	}
}
