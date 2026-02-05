package handler

import (
	"crypto/md5" //nolint:gosec // G501: MD5 used for ETag generation, not cryptographic security
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/logger"
)

// PermissionHandler handles permission-related HTTP requests.
// This handler provides the real-time permission sync endpoint.
type PermissionHandler struct {
	permCacheSvc   *app.PermissionCacheService
	permVersionSvc *app.PermissionVersionService
	logger         *logger.Logger
}

// NewPermissionHandler creates a new permission handler.
func NewPermissionHandler(
	permCacheSvc *app.PermissionCacheService,
	permVersionSvc *app.PermissionVersionService,
	log *logger.Logger,
) *PermissionHandler {
	return &PermissionHandler{
		permCacheSvc:   permCacheSvc,
		permVersionSvc: permVersionSvc,
		logger:         log,
	}
}

// PermissionsResponse represents the response for GET /me/permissions.
type PermissionsResponse struct {
	Permissions []string `json:"permissions"`
	Version     int      `json:"version"`
}

// GetMyPermissions returns the current user's permissions.
// This endpoint supports ETag-based caching for efficient polling.
//
// Headers:
//   - If-None-Match: ETag from previous response (returns 304 if unchanged)
//
// Response Headers:
//   - ETag: Hash of permissions for conditional requests
//   - X-Permission-Version: Current version number
//
// @Summary      Get current user permissions
// @Description  Returns the permissions for the authenticated user in the current tenant.
// @Description  Supports ETag-based caching: send If-None-Match header to check for changes.
// @Tags         Permissions
// @Produce      json
// @Security     BearerAuth
// @Param        If-None-Match  header    string  false  "ETag from previous response"
// @Success      200  {object}  PermissionsResponse
// @Success      304  "Not Modified - permissions unchanged"
// @Failure      401  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Router       /me/permissions [get]
func (h *PermissionHandler) GetMyPermissions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get user and tenant from context
	userID := middleware.GetUserID(ctx)
	tenantID := middleware.MustGetTenantID(ctx)

	if userID == "" || tenantID == "" {
		apierror.Unauthorized("User or tenant context not found").WriteJSON(w)
		return
	}

	// Get current permission version
	version := h.permVersionSvc.Get(ctx, tenantID, userID)

	// Get permissions from cache
	permissions, err := h.permCacheSvc.GetPermissionsWithFallback(ctx, tenantID, userID)
	if err != nil {
		h.logger.Error("failed to get permissions",
			"user_id", userID,
			"tenant_id", tenantID,
			"error", err,
		)
		apierror.InternalError(fmt.Errorf("failed to get permissions: %w", err)).WriteJSON(w)
		return
	}

	// Sort permissions for consistent ETag
	sort.Strings(permissions)

	// Generate ETag from permissions and version
	etag := generateETag(permissions, version)

	// Check If-None-Match header for conditional request
	ifNoneMatch := r.Header.Get("If-None-Match")
	if ifNoneMatch != "" && ifNoneMatch == etag {
		// Permissions unchanged, return 304 Not Modified
		w.Header().Set("ETag", etag)
		w.Header().Set("X-Permission-Version", strconv.Itoa(version))
		w.WriteHeader(http.StatusNotModified)
		return
	}

	// Set response headers
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("ETag", etag)
	w.Header().Set("X-Permission-Version", strconv.Itoa(version))
	w.Header().Set("Cache-Control", "private, no-cache, must-revalidate")

	// Return permissions
	response := PermissionsResponse{
		Permissions: permissions,
		Version:     version,
	}

	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.logger.Error("failed to encode response", "error", err)
	}
}

// generateETag creates an ETag from permissions and version.
// Format: "v{version}-{md5_hash_of_sorted_permissions}"
func generateETag(permissions []string, version int) string {
	// Create a deterministic string from sorted permissions
	// Pre-allocate estimated capacity for efficiency
	estimatedSize := len(permissions) * 30 // Average permission length ~30 chars
	data := make([]byte, 0, estimatedSize+10)
	for _, p := range permissions {
		data = append(data, p...)
		data = append(data, ',')
	}
	data = append(data, strconv.Itoa(version)...)

	// Generate MD5 hash (sufficient for ETag, not security critical)
	hash := md5.Sum(data) //nolint:gosec // G401: MD5 used for ETag generation, not cryptographic security
	return fmt.Sprintf(`"v%d-%s"`, version, hex.EncodeToString(hash[:8]))
}
