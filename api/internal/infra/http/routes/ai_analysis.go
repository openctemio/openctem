package routes

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"

	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
)

// registerAIAnalysisRoutes wires the AI governance routes
// (docs/architecture/ai-analysis.md):
//
//   - the organization's AI use cases under /api/v1/organization/settings/ai:
//     owners and administrators with settings:read / settings:write; a body
//     that turns auto-apply on or raises the data class ceiling above internal
//     needs a recent sign-in;
//   - a finding's AI suggestions, AI runs and the apply, dismiss and undo
//     actions: findings:read and ai_triage:read on the route, the module gate,
//     the caller's data scope on the subject in the service, and the
//     permission of the change itself (findings:severity or findings:write)
//     checked per suggestion.
func registerAIAnalysisRoutes(router Router, h *handler.AIAnalysisHandler, authMiddleware, userSyncMiddleware, moduleGate Middleware) {
	if h == nil {
		return
	}
	tenant := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)
	router.Group("/api/v1/organization/settings/ai/use-cases", func(r Router) {
		r.GET("/", h.ListUseCases, middleware.RequireAdmin(), middleware.Require(permission.SettingsRead))
		r.PUT("/{use_case}", h.UpdateUseCase, middleware.RequireAdmin(), middleware.Require(permission.SettingsWrite),
			requireStepUpWhenAILoosens())
	}, tenant...)

	gated := append(append([]Middleware{}, tenant...), moduleGate)
	router.Group("/api/v1/findings/{id}/ai", func(r Router) {
		r.GET("/suggestions", h.ListFindingSuggestions, middleware.RequireAll(permission.FindingsRead, permission.AITriageRead))
	}, gated...)
	router.Group("/api/v1/ai", func(r Router) {
		r.GET("/runs/{id}", h.GetRun, middleware.RequireAll(permission.FindingsRead, permission.AITriageRead))
		r.POST("/runs/{id}/undo", h.UndoRun, middleware.RequireAll(permission.FindingsRead, permission.AITriageRead))
		r.POST("/suggestions/{id}/apply", h.ApplySuggestion, middleware.RequireAll(permission.FindingsRead, permission.AITriageRead))
		r.POST("/suggestions/{id}/dismiss", h.DismissSuggestion, middleware.RequireAll(permission.FindingsRead, permission.AITriageRead))
		r.POST("/suggestions/{id}/undo", h.UndoSuggestion, middleware.RequireAll(permission.FindingsRead, permission.AITriageRead))
	}, gated...)
}

// requireStepUpWhenAILoosens is requireStepUp for an AI use-case change only
// when the body turns auto-apply on or raises the data class ceiling above
// internal (more is sent to the model, or applied without a person). A body
// that cannot be parsed is gated too; the handler then rejects it.
func requireStepUpWhenAILoosens() Middleware {
	gate := requireStepUp()
	return func(next http.Handler) http.Handler {
		gated := gate(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4<<10))
			if err != nil {
				apierror.BadRequest("Invalid request body").WriteJSON(w)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
			var req struct {
				Mode             *string `json:"mode"`
				DataClassCeiling *string `json:"data_class_ceiling"`
			}
			if len(bytes.TrimSpace(body)) == 0 || json.NewDecoder(bytes.NewReader(body)).Decode(&req) == nil {
				loosens := (req.Mode != nil && *req.Mode == "auto_apply") ||
					(req.DataClassCeiling != nil && *req.DataClassCeiling != "public" && *req.DataClassCeiling != "internal")
				if !loosens {
					next.ServeHTTP(w, r)
					return
				}
			}
			gated.ServeHTTP(w, r)
		})
	}
}
