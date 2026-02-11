package middleware

import (
	"context"
	"net/http"

	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/domain/agent"
)

// ModuleChecker interface for checking module access.
// This allows dependency injection and testing.
type ModuleChecker interface {
	TenantHasModule(ctx context.Context, tenantID, moduleID string) (bool, error)
}

// SubModuleChecker interface for checking sub-module access.
// Sub-modules use the format "parent.child" (e.g., "integrations.scm").
type SubModuleChecker interface {
	TenantHasSubModule(ctx context.Context, tenantID, parentModuleID, subModuleID string) (bool, error)
}

// RequireModule creates a middleware that checks if the tenant has access to the specified module.
// If the tenant doesn't have the module enabled, returns 403 Forbidden.
//
// This middleware should be used AFTER authentication and RequireTenant() middleware,
// as it requires the tenant ID to be present in the context.
//
// Usage:
//
//	router.Group("/api/v1/assets", func(r Router) {
//	    r.GET("/", h.List, middleware.Require(permission.AssetsRead))
//	}, middlewares..., middleware.RequireModule(moduleService, "assets"))
func RequireModule(checker ModuleChecker, moduleID string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get tenant ID from context (set by RequireTenant middleware)
			tenantID := GetTenantID(r.Context())
			if tenantID == "" {
				// This shouldn't happen if RequireTenant is applied before this middleware
				apierror.Unauthorized("Tenant ID not found in token").WriteJSON(w)
				return
			}

			// Check if tenant has module enabled
			hasModule, err := checker.TenantHasModule(r.Context(), tenantID, moduleID)
			if err != nil {
				// Log error but don't expose internal details
				apierror.InternalError(err).WriteJSON(w)
				return
			}

			if !hasModule {
				apierror.New(
					http.StatusForbidden,
					"MODULE_NOT_ENABLED",
					"This feature is not available in your current plan. Please upgrade to access this module.",
				).WriteJSON(w)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireModuleFunc is a convenience function that returns a middleware factory.
// Use this when you need to create multiple module middlewares with the same checker.
//
// Usage:
//
//	requireModule := middleware.RequireModuleFunc(moduleService)
//	router.Group("/api/v1/assets", func(r Router) {
//	    // ...
//	}, middlewares..., requireModule("assets"))
func RequireModuleFunc(checker ModuleChecker) func(moduleID string) func(http.Handler) http.Handler {
	return func(moduleID string) func(http.Handler) http.Handler {
		return RequireModule(checker, moduleID)
	}
}

// AgentContextProvider is an interface for retrieving agent from context.
// This allows decoupling middleware from handler package.
type AgentContextProvider interface {
	FromContext(ctx context.Context) *agent.Agent
}

// AgentContextProviderFunc is a function adapter for AgentContextProvider.
type AgentContextProviderFunc func(ctx context.Context) *agent.Agent

// FromContext implements AgentContextProvider.
func (f AgentContextProviderFunc) FromContext(ctx context.Context) *agent.Agent {
	return f(ctx)
}

// RequireModuleForAgent creates a middleware that checks if the agent's tenant
// has access to the specified module. Unlike RequireModule which reads tenantID
// from JWT context, this reads from the agent context set by AuthenticateSource.
//
// This middleware should be used AFTER AuthenticateSource middleware,
// as it requires the agent to be present in the context.
//
// Usage:
//
//	router.Group("/api/v1/agent", func(r Router) {
//	    r.POST("/ingest", h.Ingest)
//	}, ingestHandler.AuthenticateSource,
//	   middleware.RequireModuleForAgent(moduleService, agentProvider, "scans"))
func RequireModuleForAgent(
	checker ModuleChecker,
	agentProvider AgentContextProvider,
	moduleID string,
) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get agent from context (set by AuthenticateSource middleware)
			agt := agentProvider.FromContext(r.Context())
			if agt == nil {
				apierror.Unauthorized("Agent not found in context").WriteJSON(w)
				return
			}

			// Get tenant ID from agent
			tenantID := agt.TenantID.String()
			if tenantID == "" {
				apierror.Unauthorized("Agent has no tenant association").WriteJSON(w)
				return
			}

			// Check if tenant has module enabled
			hasModule, err := checker.TenantHasModule(r.Context(), tenantID, moduleID)
			if err != nil {
				apierror.InternalError(err).WriteJSON(w)
				return
			}

			if !hasModule {
				apierror.New(
					http.StatusForbidden,
					"MODULE_NOT_ENABLED",
					"This feature is not available in your current plan. Please upgrade to access this module.",
				).WriteJSON(w)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireModuleForAgentFunc is a convenience function that returns a middleware factory.
// Use this when you need to create multiple agent module middlewares with the same checker.
func RequireModuleForAgentFunc(
	checker ModuleChecker,
	agentProvider AgentContextProvider,
) func(moduleID string) func(http.Handler) http.Handler {
	return func(moduleID string) func(http.Handler) http.Handler {
		return RequireModuleForAgent(checker, agentProvider, moduleID)
	}
}

// =============================================================================
// Sub-Module Middleware
// =============================================================================

// RequireSubModule creates a middleware that checks if the tenant has access to a specific sub-module.
// Sub-modules are children of parent modules (e.g., "integrations.scm" is a sub-module of "integrations").
//
// This middleware checks BOTH:
// 1. Parent module access (e.g., "integrations")
// 2. Sub-module access (e.g., "integrations.scm")
//
// Usage:
//
//	router.Group("/api/v1/integrations/scm", func(r Router) {
//	    r.GET("/connections", h.List)
//	}, middlewares..., middleware.RequireSubModule(moduleService, "integrations", "scm"))
func RequireSubModule(checker SubModuleChecker, parentModuleID, subModuleID string) func(http.Handler) http.Handler {
	// Construct the full sub-module ID (e.g., "integrations.scm")
	fullSubModuleID := parentModuleID + "." + subModuleID

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tenantID := GetTenantID(r.Context())
			if tenantID == "" {
				apierror.Unauthorized("Tenant ID not found in token").WriteJSON(w)
				return
			}

			// Check if tenant has sub-module enabled
			hasSubModule, err := checker.TenantHasSubModule(r.Context(), tenantID, parentModuleID, fullSubModuleID)
			if err != nil {
				apierror.InternalError(err).WriteJSON(w)
				return
			}

			if !hasSubModule {
				apierror.New(
					http.StatusForbidden,
					"SUBMODULE_NOT_ENABLED",
					"This feature is not available in your current plan. Please upgrade to access this module.",
				).WriteJSON(w)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireSubModuleFunc is a convenience function that returns a middleware factory for sub-modules.
//
// Usage:
//
//	requireSubModule := middleware.RequireSubModuleFunc(moduleService)
//	router.Group("/api/v1/integrations/scm", func(r Router) {
//	    // ...
//	}, middlewares..., requireSubModule("integrations", "scm"))
func RequireSubModuleFunc(checker SubModuleChecker) func(parentModuleID, subModuleID string) func(http.Handler) http.Handler {
	return func(parentModuleID, subModuleID string) func(http.Handler) http.Handler {
		return RequireSubModule(checker, parentModuleID, subModuleID)
	}
}
