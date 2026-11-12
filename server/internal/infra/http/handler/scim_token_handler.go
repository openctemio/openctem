package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/scim"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/scimtoken"
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
	actx := auditapp.AuditContext{
		TenantID:   tenantID.String(),
		ActorID:    middleware.GetUserID(r.Context()),
		ActorEmail: middleware.GetUsername(r.Context()),
		ActorIP:    getClientIP(r),
		UserAgent:  r.UserAgent(),
		RequestID:  middleware.GetRequestID(r.Context()),
	}
	if err := h.groups.SetRoleMappings(r.Context(), tenantID, body.Mappings, actx); err != nil {
		if WriteFeatureDenied(w, err) {
			return
		}
		if errors.Is(err, shared.ErrForbidden) {
			apierror.Forbidden("Only the organization owner can map a group to the admin role or change such a mapping").WriteJSON(w)
			return
		}
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
	// ExpiresInDays is required, 1..365.
	ExpiresInDays int `json:"expires_in_days"`
}

type rotateSCIMTokenRequest struct {
	// ExpiresInDays of the replacement, 1..365; omitted or 0 keeps the
	// replaced token's lifetime.
	ExpiresInDays int `json:"expires_in_days"`
}

type scimTokenView struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Prefix string `json:"prefix"`
	// Status is active, expired or revoked.
	Status     string  `json:"status"`
	CreatedAt  string  `json:"created_at"`
	LastUsedAt *string `json:"last_used_at,omitempty"`
	ExpiresAt  string  `json:"expires_at"`
}

const scimTimeLayout = "2006-01-02T15:04:05Z07:00"

func (h *SCIMTokenHandler) callerID(r *http.Request) *shared.ID {
	if uid := middleware.GetUserID(r.Context()); uid != "" {
		if id, perr := shared.IDFromString(uid); perr == nil {
			return &id
		}
	}
	return nil
}

func writeSCIMTokenError(w http.ResponseWriter, err error) bool {
	switch {
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(err.Error()).WriteJSON(w)
	case errors.Is(err, scimtoken.ErrNotFound):
		apierror.NotFound("SCIM token").WriteJSON(w)
	default:
		return false
	}
	return true
}

// Create handles POST /api/v1/scim-tokens: mints a token valid for
// expires_in_days (1..365, required) and returns the plaintext once.
func (h *SCIMTokenHandler) Create(w http.ResponseWriter, r *http.Request) {
	tenantID, err := shared.IDFromString(middleware.MustGetTenantID(r.Context()))
	if err != nil {
		apierror.Unauthorized("invalid tenant context").WriteJSON(w)
		return
	}
	var req createSCIMTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}

	res, err := h.tokens.Mint(r.Context(), tenantID, req.Name, h.callerID(r), req.ExpiresInDays)
	if err != nil {
		if writeSCIMTokenError(w, err) || WriteFeatureDenied(w, err) {
			return
		}
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
			WithMetadata("prefix", res.Token.Prefix()).
			WithMetadata("expires_at", res.Token.ExpiresAt().Format(scimTimeLayout)))

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"id":         res.Token.ID().String(),
		"name":       res.Token.Name(),
		"prefix":     res.Token.Prefix(),
		"token":      res.Plaintext, // shown once
		"created_at": res.Token.CreatedAt().UTC().Format(scimTimeLayout),
		"expires_at": res.Token.ExpiresAt().UTC().Format(scimTimeLayout),
		"endpoint":   "/scim/v2",
	})
}

// Rotate handles POST /api/v1/scim-tokens/{id}/rotate: mints the replacement
// (plaintext shown once) and cuts the replaced token off within 24 hours.
// @Summary      Rotate a SCIM token
// @Description  Mints a replacement token with the same name, returned once in this response (Cache-Control: no-store), and brings the replaced token's expiry forward to at most 24 hours from now so the identity provider can switch without a provisioning gap. expires_in_days (1-365) sets the replacement's lifetime; omitted or 0 keeps the replaced token's. A revoked, expired or unknown token is 404. Owner only, requires step-up.
// @Tags         SCIM
// @Accept       json
// @Produce      json
// @Param        id       path  string                   true   "SCIM token ID"  format(uuid)
// @Param        request  body  rotateSCIMTokenRequest   false  "Replacement lifetime"
// @Success      201  {object}  map[string]any  "Replacement token (shown once) and the replaced token's new expiry"
// @Failure      400  {object}  map[string]string  "expires_in_days outside 1-365"
// @Failure      401  {object}  map[string]string  "Unauthorized"
// @Failure      403  {object}  map[string]string  "Forbidden (owner or step-up)"
// @Failure      404  {object}  map[string]string  "Not found"
// @Security     BearerAuth
// @Router       /scim-tokens/{id}/rotate [post]
func (h *SCIMTokenHandler) Rotate(w http.ResponseWriter, r *http.Request) {
	tenantID, err := shared.IDFromString(middleware.MustGetTenantID(r.Context()))
	if err != nil {
		apierror.Unauthorized("invalid tenant context").WriteJSON(w)
		return
	}
	id, err := shared.IDFromString(chi.URLParam(r, "id"))
	if err != nil {
		apierror.NotFound("SCIM token").WriteJSON(w)
		return
	}
	var req rotateSCIMTokenRequest
	if r.ContentLength != 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			apierror.BadRequest("invalid request body").WriteJSON(w)
			return
		}
	}
	res, err := h.tokens.Rotate(r.Context(), tenantID, id, h.callerID(r), req.ExpiresInDays)
	if err != nil {
		if writeSCIMTokenError(w, err) {
			return
		}
		h.logger.Error("rotate scim token failed", "error", err)
		apierror.InternalServerError("failed to rotate SCIM token").WriteJSON(w)
		return
	}
	recordConfigAudit(r.Context(), h.audit, h.logger, configAuditContext(r),
		auditapp.NewSuccessEvent(auditdom.ActionSCIMTokenRotated, auditdom.ResourceTypeSCIMToken, id.String()).
			WithResourceName(res.Replaced.Name()).
			WithSeverity(auditdom.SeverityHigh).
			WithMessage(fmt.Sprintf("SCIM token %q rotated", res.Replaced.Name())).
			WithMetadata("replacement_id", res.Token.ID().String()).
			WithMetadata("replaced_expires_at", res.ReplacedExpiresAt.Format(scimTimeLayout)).
			WithMetadata("expires_at", res.Token.ExpiresAt().Format(scimTimeLayout)))

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"id":                  res.Token.ID().String(),
		"name":                res.Token.Name(),
		"prefix":              res.Token.Prefix(),
		"token":               res.Plaintext, // shown once
		"created_at":          res.Token.CreatedAt().UTC().Format(scimTimeLayout),
		"expires_at":          res.Token.ExpiresAt().UTC().Format(scimTimeLayout),
		"endpoint":            "/scim/v2",
		"replaced_id":         id.String(),
		"replaced_expires_at": res.ReplacedExpiresAt.UTC().Format(scimTimeLayout),
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
	now := time.Now()
	for _, t := range toks {
		v := scimTokenView{
			ID:        t.ID().String(),
			Name:      t.Name(),
			Prefix:    t.Prefix(),
			Status:    string(t.Status()),
			CreatedAt: t.CreatedAt().UTC().Format(scimTimeLayout),
			ExpiresAt: t.ExpiresAt().UTC().Format(scimTimeLayout),
		}
		if t.IsActive() && !t.UsableAt(now) {
			v.Status = "expired"
		}
		if lu := t.LastUsedAt(); lu != nil {
			s := lu.UTC().Format(scimTimeLayout)
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
