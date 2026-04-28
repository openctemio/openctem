package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"sync"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/domain/module"
	"github.com/openctemio/api/pkg/domain/tenant"
	"github.com/openctemio/api/pkg/logger"
	"golang.org/x/sync/errgroup"
)

// BootstrapHandler handles the bootstrap endpoint that returns all initial data
// needed after login in a single API call.
type BootstrapHandler struct {
	permCacheSvc   *app.PermissionCacheService
	permVersionSvc *app.PermissionVersionService
	moduleSvc      *app.ModuleService
	tenantSvc      *app.TenantService
	logger         *logger.Logger
}

// NewBootstrapHandler creates a new bootstrap handler.
func NewBootstrapHandler(
	permCacheSvc *app.PermissionCacheService,
	permVersionSvc *app.PermissionVersionService,
	moduleSvc *app.ModuleService,
	tenantSvc *app.TenantService,
	log *logger.Logger,
) *BootstrapHandler {
	return &BootstrapHandler{
		permCacheSvc:   permCacheSvc,
		permVersionSvc: permVersionSvc,
		moduleSvc:      moduleSvc,
		tenantSvc:      tenantSvc,
		logger:         log,
	}
}

// =============================================================================
// Response Types
// =============================================================================

// BootstrapResponse combines all initial data needed after login.
type BootstrapResponse struct {
	Permissions BootstrapPermissions   `json:"permissions"`
	Modules     *TenantModulesResponse `json:"modules,omitempty"`
	RiskLevels  *tenant.RiskLevelConfig `json:"risk_levels,omitempty"`
}

// BootstrapPermissions contains user permissions and version.
type BootstrapPermissions struct {
	List    []string `json:"list"`
	Version int      `json:"version"`
}

// TenantModulesResponse represents the modules available to a tenant.
type TenantModulesResponse struct {
	ModuleIDs           []string                             `json:"module_ids"`
	Modules             []LicensingModuleResponse            `json:"modules"`
	SubModules          map[string][]LicensingModuleResponse `json:"sub_modules,omitempty"`
	EventTypes          []string                             `json:"event_types,omitempty"`
	ComingSoonModuleIDs []string                             `json:"coming_soon_module_ids,omitempty"`
	BetaModuleIDs       []string                             `json:"beta_module_ids,omitempty"`
}

// LicensingModuleResponse represents a module in the response.
type LicensingModuleResponse struct {
	ID             string  `json:"id"`
	Slug           string  `json:"slug"`
	Name           string  `json:"name"`
	Description    string  `json:"description,omitempty"`
	Icon           string  `json:"icon,omitempty"`
	Category       string  `json:"category"`
	DisplayOrder   int     `json:"display_order"`
	IsActive       bool    `json:"is_active"`
	ReleaseStatus  string  `json:"release_status"`
	ParentModuleID *string `json:"parent_module_id,omitempty"`
}

// =============================================================================
// Shared Helper
// =============================================================================

// buildModulesResponse builds the TenantModulesResponse from enabled modules output.
// It processes top-level modules and their sub-modules, applying permission filtering
// and organizing sub-modules by parent ID.
func (h *BootstrapHandler) buildModulesResponse(
	enabledModules *app.GetTenantEnabledModulesOutput,
	userPermissions []string,
	isAdmin bool,
) *TenantModulesResponse {
	// Filter top-level modules based on user's permissions
	filteredModules := module.FilterModulesByPermissions(enabledModules.Modules, userPermissions, isAdmin)

	// Build a set of filtered top-level module IDs for sub-module inclusion
	filteredSet := make(map[string]bool, len(filteredModules))
	for _, m := range filteredModules {
		filteredSet[m.ID()] = true
	}

	modulesResp := make([]LicensingModuleResponse, 0, len(filteredModules))
	moduleIDs := make([]string, 0, len(filteredModules)+len(enabledModules.SubModules))
	comingSoonIDs := make([]string, 0)
	betaIDs := make([]string, 0)
	subModulesMap := make(map[string][]LicensingModuleResponse)

	// Process top-level modules
	for _, m := range filteredModules {
		moduleResp := toLicensingModuleResponse(m)
		modulesResp = append(modulesResp, moduleResp)
		moduleIDs = append(moduleIDs, m.ID())

		if m.IsComingSoon() {
			comingSoonIDs = append(comingSoonIDs, m.ID())
		} else if m.IsBeta() {
			betaIDs = append(betaIDs, m.ID())
		}
	}

	// Process sub-modules from GetTenantEnabledModules output.
	// enabledModules.SubModules already has disabled sub-modules filtered out.
	// Only include sub-modules whose parent passed permission filtering.
	for parentID, subs := range enabledModules.SubModules {
		if !filteredSet[parentID] {
			continue
		}
		subResps := make([]LicensingModuleResponse, 0, len(subs))
		for _, sub := range subs {
			subResp := toLicensingModuleResponse(sub)
			subResps = append(subResps, subResp)
			moduleIDs = append(moduleIDs, sub.ID())

			if sub.IsComingSoon() {
				comingSoonIDs = append(comingSoonIDs, sub.ID())
			} else if sub.IsBeta() {
				betaIDs = append(betaIDs, sub.ID())
			}
		}
		if len(subResps) > 0 {
			subModulesMap[parentID] = subResps
		}
	}

	return &TenantModulesResponse{
		ModuleIDs:           moduleIDs,
		Modules:             modulesResp,
		SubModules:          subModulesMap,
		ComingSoonModuleIDs: comingSoonIDs,
		BetaModuleIDs:       betaIDs,
	}
}

// toLicensingModuleResponse converts a module domain object to response DTO.
func toLicensingModuleResponse(m *module.Module) LicensingModuleResponse {
	return LicensingModuleResponse{
		ID:             m.ID(),
		Slug:           m.Slug(),
		Name:           m.Name(),
		Description:    m.Description(),
		Icon:           m.Icon(),
		Category:       m.Category(),
		DisplayOrder:   m.DisplayOrder(),
		IsActive:       m.IsActive(),
		ReleaseStatus:  string(m.ReleaseStatus()),
		ParentModuleID: m.ParentModuleID(),
	}
}

// =============================================================================
// Bootstrap Endpoint
// =============================================================================

// Bootstrap returns all initial data needed after login in a single API call.
//
// @Summary      Bootstrap initial data
// @Description  Returns all initial data needed after login: permissions and modules.
// @Tags         Bootstrap
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  BootstrapResponse
// @Failure      401  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Router       /me/bootstrap [get]
func (h *BootstrapHandler) Bootstrap(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get user and tenant from context
	userID := middleware.GetUserID(ctx)
	tenantID := middleware.MustGetTenantID(ctx)
	isAdmin := middleware.IsAdmin(ctx)

	if userID == "" || tenantID == "" {
		apierror.Unauthorized("User or tenant context not found").WriteJSON(w)
		return
	}

	var (
		permissions []string
		permVersion int
		mu          sync.Mutex
	)

	g, gctx := errgroup.WithContext(ctx)

	// Fetch permissions (always required)
	g.Go(func() error {
		perms, err := h.permCacheSvc.GetPermissionsWithFallback(gctx, tenantID, userID)
		if err != nil {
			h.logger.Error("bootstrap: failed to get permissions",
				"user_id", userID,
				"tenant_id", tenantID,
				"error", err,
			)
			return err
		}
		version := h.permVersionSvc.Get(gctx, tenantID, userID)

		// Sort permissions for consistency
		sort.Strings(perms)

		mu.Lock()
		permissions = perms
		permVersion = version
		mu.Unlock()
		return nil
	})

	// Wait for all goroutines
	if err := g.Wait(); err != nil {
		h.logger.Error("bootstrap: failed", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	// Get enabled modules for tenant
	enabledModules, err := h.moduleSvc.GetTenantEnabledModules(ctx, tenantID)
	if err != nil {
		h.logger.Error("bootstrap: failed to get enabled modules",
			"tenant_id", tenantID,
			"error", err,
		)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	userPermissions := permissions
	if isAdmin {
		userPermissions = nil // Admin sees all
	}

	// Fetch risk levels from tenant settings (lightweight, just reads tenant row)
	var riskLevels *tenant.RiskLevelConfig
	if h.tenantSvc != nil {
		rs, err := h.tenantSvc.GetRiskScoringSettings(ctx, tenantID)
		if err != nil {
			h.logger.Warn("bootstrap: failed to get risk scoring settings", "error", err)
		} else {
			riskLevels = &rs.RiskLevels
		}
	}

	// Build response
	resp := BootstrapResponse{
		Permissions: BootstrapPermissions{
			List:    permissions,
			Version: permVersion,
		},
		Modules:    h.buildModulesResponse(enabledModules, userPermissions, isAdmin),
		RiskLevels: riskLevels,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		h.logger.Error("bootstrap: failed to encode response", "error", err)
	}
}

// =============================================================================
// Tenant Modules Endpoint
// =============================================================================

// GetTenantModules returns the modules available to the current tenant.
//
// @Summary      Get tenant modules
// @Description  Returns the modules available to the current tenant based on their subscription.
// @Tags         Modules
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  TenantModulesResponse
// @Failure      401  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Router       /me/modules [get]
func (h *BootstrapHandler) GetTenantModules(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get user and tenant from context
	userID := middleware.GetUserID(ctx)
	tenantID := middleware.MustGetTenantID(ctx)
	isAdmin := middleware.IsAdmin(ctx)

	if tenantID == "" {
		apierror.Unauthorized("Tenant context not found").WriteJSON(w)
		return
	}

	// Get user's permissions for filtering
	var userPermissions []string
	if !isAdmin && h.permCacheSvc != nil && userID != "" {
		perms, err := h.permCacheSvc.GetPermissionsWithFallback(ctx, tenantID, userID)
		if err != nil {
			h.logger.Warn("failed to get permissions from cache",
				"user_id", userID,
				"tenant_id", tenantID,
				"error", err,
			)
		} else {
			userPermissions = perms
		}
	}

	// ETag based on (tenant module version + user permission version)
	// — both must match for the cached payload to still be valid. The
	// permission half catches role/permission changes that affect what
	// modules this user can SEE, distinct from what the tenant has
	// enabled. Hex-encode the tuple so it's a single opaque token.
	modVersion := h.moduleSvc.GetTenantModuleVersion(ctx, tenantID)
	permVersion := 0
	if h.permVersionSvc != nil && userID != "" {
		permVersion = h.permVersionSvc.Get(ctx, tenantID, userID)
	}
	// Include tenant_id in etag so a CDN/proxy that incorrectly shares
	// cache entries across tenants cannot serve tenant A's response to
	// tenant B (defense-in-depth: HTTP semantics already require
	// per-user caching with private cache-control, but belt-and-braces).
	etag := fmt.Sprintf(`"t%s-m%d-p%d"`, tenantID[:8], modVersion, permVersion)
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "private, max-age=300")
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}

	// Get enabled modules for tenant
	enabledModules, err := h.moduleSvc.GetTenantEnabledModules(ctx, tenantID)
	if err != nil {
		h.logger.Error("failed to get tenant modules",
			"tenant_id", tenantID,
			"error", err,
		)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	resp := h.buildModulesResponse(enabledModules, userPermissions, isAdmin)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		h.logger.Error("failed to encode modules response", "error", err)
	}
}
