package handler

import (
	"encoding/json"
	"net/http"
	"sort"
	"sync"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/domain/module"
	"github.com/openctemio/api/pkg/logger"
	"golang.org/x/sync/errgroup"
)

// BootstrapHandler handles the bootstrap endpoint that returns all initial data
// needed after login in a single API call.
type BootstrapHandler struct {
	permCacheSvc   *app.PermissionCacheService
	permVersionSvc *app.PermissionVersionService
	moduleSvc   *app.ModuleService
	logger         *logger.Logger
}

// NewBootstrapHandler creates a new bootstrap handler.
func NewBootstrapHandler(
	permCacheSvc *app.PermissionCacheService,
	permVersionSvc *app.PermissionVersionService,
	moduleSvc *app.ModuleService,
	log *logger.Logger,
) *BootstrapHandler {
	return &BootstrapHandler{
		permCacheSvc:   permCacheSvc,
		permVersionSvc: permVersionSvc,
		moduleSvc:   moduleSvc,
		logger:         log,
	}
}

// =============================================================================
// Response Types
// =============================================================================

// BootstrapResponse combines all initial data needed after login.
type BootstrapResponse struct {
	Permissions BootstrapPermissions  `json:"permissions"`
	Modules     *TenantModulesResponse `json:"modules,omitempty"`
}

// BootstrapPermissions contains user permissions and version.
type BootstrapPermissions struct {
	List    []string `json:"list"`
	Version int      `json:"version"`
}

// TenantModulesResponse represents the modules available to a tenant.
type TenantModulesResponse struct {
	ModuleIDs           []string                            `json:"module_ids"`
	Modules             []LicensingModuleResponse           `json:"modules"`
	SubModules          map[string][]LicensingModuleResponse `json:"sub_modules,omitempty"`
	EventTypes          []string                            `json:"event_types,omitempty"`
	ComingSoonModuleIDs []string                            `json:"coming_soon_module_ids,omitempty"`
	BetaModuleIDs       []string                            `json:"beta_module_ids,omitempty"`
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

	// Build response
	resp := BootstrapResponse{
		Permissions: BootstrapPermissions{
			List:    permissions,
			Version: permVersion,
		},
	}

	// OSS Edition: All modules are enabled, fetched from database
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

	// Filter modules based on user's permissions
	filteredModules := module.FilterModulesByPermissions(enabledModules.Modules, userPermissions, isAdmin)

	modulesResp := make([]LicensingModuleResponse, 0, len(filteredModules))
	moduleIDs := make([]string, 0, len(filteredModules))
	comingSoonIDs := make([]string, 0)
	betaIDs := make([]string, 0)

	// Separate sub-modules for dedicated response field
	subModulesMap := make(map[string][]LicensingModuleResponse)

	for _, m := range filteredModules {
		moduleResp := LicensingModuleResponse{
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

		// Add to modules list
		modulesResp = append(modulesResp, moduleResp)
		moduleIDs = append(moduleIDs, m.ID())

		// Also organize sub-modules by parent
		if m.ParentModuleID() != nil {
			parentID := *m.ParentModuleID()
			subModulesMap[parentID] = append(subModulesMap[parentID], moduleResp)
		}

		if m.IsComingSoon() {
			comingSoonIDs = append(comingSoonIDs, m.ID())
		} else if m.IsBeta() {
			betaIDs = append(betaIDs, m.ID())
		}
	}

	resp.Modules = &TenantModulesResponse{
		ModuleIDs:           moduleIDs,
		Modules:             modulesResp,
		SubModules:          subModulesMap,
		ComingSoonModuleIDs: comingSoonIDs,
		BetaModuleIDs:       betaIDs,
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

	// OSS Edition: All modules are enabled, fetched from database
	enabledModules, err := h.moduleSvc.GetTenantEnabledModules(ctx, tenantID)
	if err != nil {
		h.logger.Error("failed to get tenant modules",
			"tenant_id", tenantID,
			"error", err,
		)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	// Filter modules based on user's permissions
	filteredModules := module.FilterModulesByPermissions(enabledModules.Modules, userPermissions, isAdmin)

	modulesResp := make([]LicensingModuleResponse, 0, len(filteredModules))
	moduleIDs := make([]string, 0, len(filteredModules))
	comingSoonIDs := make([]string, 0)
	betaIDs := make([]string, 0)

	// Separate sub-modules for dedicated response field
	subModulesMap := make(map[string][]LicensingModuleResponse)

	for _, m := range filteredModules {
		moduleResp := LicensingModuleResponse{
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

		// Add to modules list
		modulesResp = append(modulesResp, moduleResp)
		moduleIDs = append(moduleIDs, m.ID())

		// Also organize sub-modules by parent
		if m.ParentModuleID() != nil {
			parentID := *m.ParentModuleID()
			subModulesMap[parentID] = append(subModulesMap[parentID], moduleResp)
		}

		if m.IsComingSoon() {
			comingSoonIDs = append(comingSoonIDs, m.ID())
		} else if m.IsBeta() {
			betaIDs = append(betaIDs, m.ID())
		}
	}

	resp := TenantModulesResponse{
		ModuleIDs:           moduleIDs,
		Modules:             modulesResp,
		SubModules:          subModulesMap,
		ComingSoonModuleIDs: comingSoonIDs,
		BetaModuleIDs:       betaIDs,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		h.logger.Error("failed to encode modules response", "error", err)
	}
}
