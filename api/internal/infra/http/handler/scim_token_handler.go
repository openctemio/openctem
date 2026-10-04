package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/scim"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// SCIMTokenHandler manages a tenant's SCIM bearer tokens (admin-only, JWT auth).
// The plaintext token is returned exactly once, at creation.
type SCIMTokenHandler struct {
	tokens *scim.TokenService
	groups *scim.GroupService
	audit  *auditapp.AuditService
	logger *logger.Logger
}

// SetAuditService wires the audit log for SCIM token creation and revocation.
func (h *SCIMTokenHandler) SetAuditService(a *auditapp.AuditService) { h.audit = a }

// NewSCIMTokenHandler creates the handler.
func NewSCIMTokenHandler(tokens *scim.TokenService, log *logger.Logger) *SCIMTokenHandler {
	return &SCIMTokenHandler{tokens: tokens, logger: log.With("handler", "scim-token")}
}

// SetGroupService wires the SCIM group service for group→role mapping admin.
func (h *SCIMTokenHandler) SetGroupService(g *scim.GroupService) { h.groups = g }

type groupMappingsBody struct {
	Mappings map[string]string `json:"mappings"`
}

// GetGroupMappings handles GET /api/v1/scim-tokens/group-mappings (JWT admin).
func (h *SCIMTokenHandler) GetGroupMappings(w http.ResponseWriter, r *http.Request) {
	tenantID, err := shared.IDFromString(middleware.MustGetTenantID(r.Context()))
	if err != nil || h.groups == nil {
		apierror.Unauthorized("invalid tenant context").WriteJSON(w)
		return
	}
	mappings, err := h.groups.GetRoleMappings(r.Context(), tenantID)
	if err != nil {
		h.logger.Error("get scim group mappings failed", "error", err)
		apierror.InternalServerError("failed to load group mappings").WriteJSON(w)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(groupMappingsBody{Mappings: mappings})
}

// SetGroupMappings handles PUT /api/v1/scim-tokens/group-mappings (JWT admin) —
// replaces the tenant's group→role overrides and re-reconciles members.
func (h *SCIMTokenHandler) SetGroupMappings(w http.ResponseWriter, r *http.Request) {
	tenantID, err := shared.IDFromString(middleware.MustGetTenantID(r.Context()))
	if err != nil || h.groups == nil {
		apierror.Unauthorized("invalid tenant context").WriteJSON(w)
		return
	}
	var body groupMappingsBody
	if derr := json.NewDecoder(r.Body).Decode(&body); derr != nil {
		apierror.BadRequest("invalid JSON body").WriteJSON(w)
		return
	}
	if err := h.groups.SetRoleMappings(r.Context(), tenantID, body.Mappings); err != nil {
		if errors.Is(err, shared.ErrValidation) {
			apierror.BadRequest("role must be admin, member, or viewer").WriteJSON(w)
			return
		}
		h.logger.Error("set scim group mappings failed", "error", err)
		apierror.InternalServerError("failed to save group mappings").WriteJSON(w)
		return
	}
	h.GetGroupMappings(w, r)
}

type createSCIMTokenRequest struct {
	Name string `json:"name"`
}

type scimTokenView struct {
	ID         string  `json:"id"`
	Name       string  `json:"name"`
	Prefix     string  `json:"prefix"`
	Status     string  `json:"status"`
	CreatedAt  string  `json:"created_at"`
	LastUsedAt *string `json:"last_used_at,omitempty"`
}

// Create handles POST /api/v1/scim-tokens — mints a token, returns plaintext once.
func (h *SCIMTokenHandler) Create(w http.ResponseWriter, r *http.Request) {
	tenantID, err := shared.IDFromString(middleware.MustGetTenantID(r.Context()))
	if err != nil {
		apierror.Unauthorized("invalid tenant context").WriteJSON(w)
		return
	}
	var req createSCIMTokenRequest
	_ = json.NewDecoder(r.Body).Decode(&req)

	var createdBy *shared.ID
	if uid := middleware.GetUserID(r.Context()); uid != "" {
		if id, perr := shared.IDFromString(uid); perr == nil {
			createdBy = &id
		}
	}

	res, err := h.tokens.Mint(r.Context(), tenantID, req.Name, createdBy)
	if err != nil {
		h.logger.Error("mint scim token failed", "error", err)
		apierror.InternalServerError("failed to create SCIM token").WriteJSON(w)
		return
	}
	// A SCIM token can create, suspend and re-role members: High.
	recordConfigAudit(r.Context(), h.audit, h.logger, configAuditContext(r),
		auditapp.NewSuccessEvent(auditdom.ActionSCIMTokenCreated, auditdom.ResourceTypeSCIMToken, res.Token.ID().String()).
			WithResourceName(res.Token.Name()).
			WithSeverity(auditdom.SeverityHigh).
			WithMessage(fmt.Sprintf("SCIM token %q created", res.Token.Name())).
			WithMetadata("prefix", res.Token.Prefix()))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"id":         res.Token.ID().String(),
		"name":       res.Token.Name(),
		"prefix":     res.Token.Prefix(),
		"token":      res.Plaintext, // shown once
		"created_at": res.Token.CreatedAt().UTC().Format("2006-01-02T15:04:05Z07:00"),
		"endpoint":   "/scim/v2",
	})
}

// List handles GET /api/v1/scim-tokens.
func (h *SCIMTokenHandler) List(w http.ResponseWriter, r *http.Request) {
	tenantID, err := shared.IDFromString(middleware.MustGetTenantID(r.Context()))
	if err != nil {
		apierror.Unauthorized("invalid tenant context").WriteJSON(w)
		return
	}
	toks, err := h.tokens.List(r.Context(), tenantID)
	if err != nil {
		h.logger.Error("list scim tokens failed", "error", err)
		apierror.InternalServerError("failed to list SCIM tokens").WriteJSON(w)
		return
	}
	views := make([]scimTokenView, 0, len(toks))
	for _, t := range toks {
		v := scimTokenView{
			ID:        t.ID().String(),
			Name:      t.Name(),
			Prefix:    t.Prefix(),
			Status:    string(t.Status()),
			CreatedAt: t.CreatedAt().UTC().Format("2006-01-02T15:04:05Z07:00"),
		}
		if lu := t.LastUsedAt(); lu != nil {
			s := lu.UTC().Format("2006-01-02T15:04:05Z07:00")
			v.LastUsedAt = &s
		}
		views = append(views, v)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{"tokens": views})
}

// Revoke handles DELETE /api/v1/scim-tokens/{id}.
func (h *SCIMTokenHandler) Revoke(w http.ResponseWriter, r *http.Request) {
	tenantID, err := shared.IDFromString(middleware.MustGetTenantID(r.Context()))
	if err != nil {
		apierror.Unauthorized("invalid tenant context").WriteJSON(w)
		return
	}
	id, err := shared.IDFromString(chi.URLParam(r, "id"))
	if err != nil {
		apierror.BadRequest("invalid token id").WriteJSON(w)
		return
	}
	if err := h.tokens.Revoke(r.Context(), tenantID, id); err != nil {
		apierror.NotFound("SCIM token").WriteJSON(w)
		return
	}
	recordConfigAudit(r.Context(), h.audit, h.logger, configAuditContext(r),
		auditapp.NewSuccessEvent(auditdom.ActionSCIMTokenRevoked, auditdom.ResourceTypeSCIMToken, id.String()).
			WithSeverity(auditdom.SeverityMedium).
			WithMessage("SCIM token revoked"))
	w.WriteHeader(http.StatusNoContent)
}
