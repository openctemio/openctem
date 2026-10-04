package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/accesscontrol"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// AssetOwnerHandler handles asset ownership HTTP requests.
//
// Being an owner is an assignment (accountability) only: a user owner gains no
// data access. A group owner is the group's asset assignment, which is the
// group data-scope path, so adding or removing a group owner also needs
// team:groups:write. A user's direct access is an explicit access grant
// (/assets/{id}/access-grants, team:groups:read / team:groups:write).
type AssetOwnerHandler struct {
	repo         accesscontrol.Repository
	assetRepo    asset.Repository
	auditService *auditapp.AuditService
	logger       *logger.Logger
}

// SetAuditService wires the audit logger for access grant changes. Nil-safe.
func (h *AssetOwnerHandler) SetAuditService(svc *auditapp.AuditService) {
	h.auditService = svc
}

// NewAssetOwnerHandler creates a new asset owner handler.
//
// assetRepo is required for the per-request tenant check on AddOwner /
// UpdateOwner / RemoveOwner — without it a user with assets:write in
// tenant A could craft a request for an asset in tenant B because
// asset_owners is not directly tenant-scoped.
func NewAssetOwnerHandler(
	repo accesscontrol.Repository,
	assetRepo asset.Repository,
	log *logger.Logger,
) *AssetOwnerHandler {
	return &AssetOwnerHandler{
		repo:      repo,
		assetRepo: assetRepo,
		logger:    log,
	}
}

// requireAssetInTenant verifies the asset exists and belongs to the caller's
// tenant. Returns the parsed asset ID on success. On failure it writes the
// appropriate error response and returns the zero value + false; callers
// should bail out immediately.
//
// We deliberately respond with a generic 404 in both "asset doesn't exist"
// and "asset belongs to a different tenant" cases — leaking the difference
// would let an attacker probe the cross-tenant ID space.
func (h *AssetOwnerHandler) requireAssetInTenant(
	w http.ResponseWriter,
	r *http.Request,
	rawAssetID string,
) (shared.ID, bool) {
	parsed, err := shared.IDFromString(rawAssetID)
	if err != nil {
		apierror.BadRequest("Invalid asset ID").WriteJSON(w)
		return shared.ID{}, false
	}
	tenantID := middleware.MustGetTenantID(r.Context())
	parsedTenantID, terr := shared.IDFromString(tenantID)
	if terr != nil {
		apierror.BadRequest("Invalid tenant ID").WriteJSON(w)
		return shared.ID{}, false
	}
	if _, gerr := h.assetRepo.GetByID(r.Context(), parsedTenantID, parsed); gerr != nil {
		// Generic 404 — do not distinguish "not found" from "wrong tenant".
		apierror.NotFound("Asset").WriteJSON(w)
		return shared.ID{}, false
	}
	return parsed, true
}

// AddAssetOwnerRequest represents the request to add an owner to an asset.
type AddAssetOwnerRequest struct {
	UserID        *string `json:"user_id"`
	GroupID       *string `json:"group_id"`
	OwnershipType string  `json:"ownership_type" validate:"required"`
}

// AssetOwnerResponse represents an asset owner in API responses.
type AssetOwnerResponse struct {
	ID             string    `json:"id"`
	UserID         *string   `json:"user_id,omitempty"`
	UserName       *string   `json:"user_name,omitempty"`
	UserEmail      *string   `json:"user_email,omitempty"`
	GroupID        *string   `json:"group_id,omitempty"`
	GroupName      *string   `json:"group_name,omitempty"`
	OwnershipType  string    `json:"ownership_type"`
	AssignedAt     time.Time `json:"assigned_at"`
	AssignedByName *string   `json:"assigned_by_name,omitempty"`
	// AssignmentSource says who created the row: manual (a person),
	// scope_rule (a group scope rule) or owner_ref (matched from the asset's
	// owner reference; removing it clears the owner reference).
	AssignmentSource string `json:"assignment_source" enums:"manual,scope_rule,owner_ref"`
}

// UpdateAssetOwnerRequest represents the request to update an owner's type.
type UpdateAssetOwnerRequest struct {
	OwnershipType string `json:"ownership_type" validate:"required"`
}

// ListOwners handles GET /api/v1/assets/{id}/owners
func (h *AssetOwnerHandler) ListOwners(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	assetID := r.PathValue("id")
	if assetID == "" {
		apierror.BadRequest("Asset ID is required").WriteJSON(w)
		return
	}

	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		apierror.BadRequest("Invalid tenant ID").WriteJSON(w)
		return
	}

	// An asset of another tenant is a 404, like an unknown one (it used to
	// answer an empty list).
	parsedAssetID, ok := h.requireAssetInTenant(w, r, assetID)
	if !ok {
		return
	}

	owners, err := h.repo.ListAssetOwnersWithNames(r.Context(), parsedTenantID, parsedAssetID)
	if err != nil {
		h.logger.Error("failed to list asset owners", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	data := make([]AssetOwnerResponse, 0, len(owners))
	for _, o := range owners {
		resp := AssetOwnerResponse{
			ID:               o.ID().String(),
			OwnershipType:    o.OwnershipType().String(),
			AssignedAt:       o.AssignedAt(),
			AssignmentSource: o.AssignmentSource,
		}

		if o.UserID() != nil {
			uid := o.UserID().String()
			resp.UserID = &uid
			if o.UserName != "" {
				resp.UserName = &o.UserName
			}
			if o.UserEmail != "" {
				resp.UserEmail = &o.UserEmail
			}
		}

		if o.GroupID() != nil {
			gid := o.GroupID().String()
			resp.GroupID = &gid
			if o.GroupName != "" {
				resp.GroupName = &o.GroupName
			}
		}

		if o.AssignedByName != "" {
			resp.AssignedByName = &o.AssignedByName
		}

		data = append(data, resp)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"data":  data,
		"total": len(data),
	})
}

// AddOwner handles POST /api/v1/assets/{id}/owners
func (h *AssetOwnerHandler) AddOwner(w http.ResponseWriter, r *http.Request) {
	assetID := r.PathValue("id")
	if assetID == "" {
		apierror.BadRequest("Asset ID is required").WriteJSON(w)
		return
	}

	// Tenant check FIRST. We must verify the asset belongs to the caller's
	// tenant before doing anything else, otherwise an attacker with
	// assets:write in tenant A could craft a POST against an asset ID in
	// tenant B and have us happily insert an asset_owners row referencing
	// it (the table is keyed by asset_id only and does not carry tenant_id).
	parsedAssetID, ok := h.requireAssetInTenant(w, r, assetID)
	if !ok {
		return
	}

	// The principal (user_id / group_id) comes from the request body and is
	// otherwise unscoped — asset_owners has no tenant_id column and
	// CreateAssetOwner is a plain INSERT. Without this check a caller could
	// assign a foreign tenant's user or group as an owner of their own asset.
	parsedTenantID, terr := shared.IDFromString(middleware.MustGetTenantID(r.Context()))
	if terr != nil {
		apierror.BadRequest("Invalid tenant ID").WriteJSON(w)
		return
	}

	var req AddAssetOwnerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	// Validate: must have either user_id or group_id
	if req.UserID == nil && req.GroupID == nil {
		apierror.BadRequest("Either user_id or group_id is required").WriteJSON(w)
		return
	}
	if req.UserID != nil && req.GroupID != nil {
		apierror.BadRequest("Cannot specify both user_id and group_id").WriteJSON(w)
		return
	}

	// Validate ownership type
	ownershipType := accesscontrol.OwnershipType(req.OwnershipType)
	if !ownershipType.IsValid() {
		apierror.BadRequest("Invalid ownership_type. Must be one of: primary, secondary, stakeholder, informed, regulatory").WriteJSON(w)
		return
	}

	// Get acting user for assigned_by
	actingUserID := middleware.GetUserID(r.Context())
	var assignedBy *shared.ID
	if actingUserID != "" {
		uid, err := shared.IDFromString(actingUserID)
		if err == nil {
			assignedBy = &uid
		}
	}

	var ao *accesscontrol.AssetOwner

	if req.UserID != nil {
		userID, err := shared.IDFromString(*req.UserID)
		if err != nil {
			apierror.BadRequest("Invalid user_id").WriteJSON(w)
			return
		}
		// Reject a user that is not a member of the caller's tenant.
		inTenant, cerr := h.repo.IsUserInTenant(r.Context(), parsedTenantID, userID)
		if cerr != nil {
			h.logger.Error("failed to verify user tenant membership", "error", cerr)
			apierror.InternalError(cerr).WriteJSON(w)
			return
		}
		if !inTenant {
			apierror.Forbidden("user_id does not belong to this tenant").WriteJSON(w)
			return
		}
		ao, err = accesscontrol.NewAssetOwnerForUser(parsedAssetID, userID, ownershipType, assignedBy)
		if err != nil {
			apierror.BadRequest(err.Error()).WriteJSON(w)
			return
		}
	} else {
		// A group owner is the group's asset assignment: its members see the
		// asset. That is an access-control change, so it needs the groups
		// permission, not only assets:write.
		if !middleware.HasPermission(r.Context(), permission.GroupsWrite.String()) {
			apierror.Forbidden("Adding a group as owner gives its members access to the asset; it requires team:groups:write").WriteJSON(w)
			return
		}
		groupID, err := shared.IDFromString(*req.GroupID)
		if err != nil {
			apierror.BadRequest("Invalid group_id").WriteJSON(w)
			return
		}
		// Reject a group that belongs to a different tenant.
		inTenant, cerr := h.repo.IsGroupInTenant(r.Context(), parsedTenantID, groupID)
		if cerr != nil {
			h.logger.Error("failed to verify group tenant membership", "error", cerr)
			apierror.InternalError(cerr).WriteJSON(w)
			return
		}
		if !inTenant {
			apierror.Forbidden("group_id does not belong to this tenant").WriteJSON(w)
			return
		}
		ao, err = accesscontrol.NewAssetOwnerForGroup(parsedAssetID, groupID, ownershipType, assignedBy)
		if err != nil {
			apierror.BadRequest(err.Error()).WriteJSON(w)
			return
		}
	}

	if err := h.repo.CreateAssetOwner(r.Context(), ao); err != nil {
		if errors.Is(err, accesscontrol.ErrAssetOwnerExists) {
			apierror.Conflict("This owner is already assigned to the asset").WriteJSON(w)
			return
		}
		h.logger.Error("failed to create asset owner", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	// A user owner gains no data access (owner decision O1). A group owner
	// is the group's asset assignment: refresh its members' access.
	if req.GroupID != nil {
		groupID, _ := shared.IDFromString(*req.GroupID)
		if refreshErr := h.repo.RefreshAccessForAssetAssign(r.Context(), groupID, parsedAssetID, req.OwnershipType); refreshErr != nil {
			h.logger.Warn("failed to refresh access for group owner add", "error", refreshErr)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"id":             ao.ID().String(),
		"ownership_type": ao.OwnershipType().String(),
	})
}

// UpdateOwner handles PUT /api/v1/assets/{id}/owners/{ownerID}
func (h *AssetOwnerHandler) UpdateOwner(w http.ResponseWriter, r *http.Request) {
	assetID := r.PathValue("id")
	ownerID := r.PathValue("ownerId")
	if ownerID == "" {
		apierror.BadRequest("Owner ID is required").WriteJSON(w)
		return
	}

	// Tenant check on the asset before allowing the update — defense
	// against the same cross-tenant attack as AddOwner.
	if _, ok := h.requireAssetInTenant(w, r, assetID); !ok {
		return
	}

	var req UpdateAssetOwnerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	ownershipType := accesscontrol.OwnershipType(req.OwnershipType)
	if !ownershipType.IsValid() {
		apierror.BadRequest("Invalid ownership_type").WriteJSON(w)
		return
	}

	parsedOwnerID, err := shared.IDFromString(ownerID)
	if err != nil {
		apierror.BadRequest("Invalid owner ID").WriteJSON(w)
		return
	}

	ao, err := h.repo.GetAssetOwnerByID(r.Context(), parsedOwnerID)
	if err != nil {
		if errors.Is(err, accesscontrol.ErrAssetOwnerNotFound) {
			apierror.NotFound("Asset owner").WriteJSON(w)
			return
		}
		h.logger.Error("failed to get asset owner", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	// Verify the owner belongs to the asset from URL path (prevents IDOR)
	if ao.AssetID().String() != assetID {
		apierror.NotFound("Asset owner").WriteJSON(w)
		return
	}

	if err := ao.UpdateOwnershipType(ownershipType); err != nil {
		apierror.BadRequest(err.Error()).WriteJSON(w)
		return
	}

	if err := h.repo.UpdateAssetOwner(r.Context(), ao); err != nil {
		h.logger.Error("failed to update asset owner", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// RemoveOwner handles DELETE /api/v1/assets/{id}/owners/{ownerID}
func (h *AssetOwnerHandler) RemoveOwner(w http.ResponseWriter, r *http.Request) {
	assetID := r.PathValue("id")
	ownerID := r.PathValue("ownerId")
	if ownerID == "" {
		apierror.BadRequest("Owner ID is required").WriteJSON(w)
		return
	}

	// Tenant check on the asset before allowing the delete.
	if _, ok := h.requireAssetInTenant(w, r, assetID); !ok {
		return
	}

	parsedOwnerID, err := shared.IDFromString(ownerID)
	if err != nil {
		apierror.BadRequest("Invalid owner ID").WriteJSON(w)
		return
	}

	// Get owner first to know if it's a user or group (for access refresh)
	ao, err := h.repo.GetAssetOwnerByID(r.Context(), parsedOwnerID)
	if err != nil {
		if errors.Is(err, accesscontrol.ErrAssetOwnerNotFound) {
			apierror.NotFound("Asset owner").WriteJSON(w)
			return
		}
		h.logger.Error("failed to get asset owner", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	// Verify the owner belongs to the asset from URL path (prevents IDOR)
	if ao.AssetID().String() != assetID {
		apierror.NotFound("Asset owner").WriteJSON(w)
		return
	}

	if ao.GroupID() != nil && !middleware.HasPermission(r.Context(), permission.GroupsWrite.String()) {
		apierror.Forbidden("Removing a group owner removes its members' access to the asset; it requires team:groups:write").WriteJSON(w)
		return
	}

	source, err := h.repo.GetAssetOwnerSource(r.Context(), parsedOwnerID)
	if err != nil {
		h.logger.Error("failed to get asset owner source", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	if err := h.repo.DeleteAssetOwnerByID(r.Context(), parsedOwnerID); err != nil {
		if errors.Is(err, accesscontrol.ErrAssetOwnerNotFound) {
			apierror.NotFound("Asset owner").WriteJSON(w)
			return
		}
		h.logger.Error("failed to delete asset owner", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	// An owner matched from the asset's owner_ref would be matched again by
	// the owner-resolution controller, so removing it clears owner_ref too.
	if source == accesscontrol.AssignmentSourceOwnerRef {
		h.clearOwnerRef(r, ao.AssetID())
	}

	// Removing a user owner changes no access. Removing a group owner removes
	// the group's assignment: refresh its members' access.
	if ao.GroupID() != nil {
		if refreshErr := h.repo.RefreshAccessForAssetUnassign(r.Context(), *ao.GroupID(), ao.AssetID()); refreshErr != nil {
			h.logger.Warn("failed to refresh access for group owner remove", "error", refreshErr)
		}
	}

	w.WriteHeader(http.StatusNoContent)
}

// clearOwnerRef empties the asset's owner reference after its derived owner
// was removed. Best-effort: the owner row is already gone.
func (h *AssetOwnerHandler) clearOwnerRef(r *http.Request, assetID shared.ID) {
	tenantID, err := shared.IDFromString(middleware.MustGetTenantID(r.Context()))
	if err != nil {
		return
	}
	a, err := h.assetRepo.GetByID(r.Context(), tenantID, assetID)
	if err != nil {
		h.logger.Warn("failed to load asset to clear owner_ref", "asset_id", assetID.String(), "error", err)
		return
	}
	if a.OwnerRef() == "" {
		return
	}
	a.SetOwnerRef("")
	if err := h.assetRepo.Update(r.Context(), a); err != nil {
		h.logger.Warn("failed to clear owner_ref", "asset_id", assetID.String(), "error", err)
	}
}
