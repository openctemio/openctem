package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/domain/integration"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/validator"
)

// IntegrationHandler handles integration-related HTTP requests.
type IntegrationHandler struct {
	service              *app.IntegrationService
	validator            *validator.Validator
	logger               *logger.Logger
	testNotifRateLimiter *testNotificationRateLimiter
}

// testNotificationRateLimiter limits test notification requests per user+integration.
type testNotificationRateLimiter struct {
	mu       sync.Mutex
	requests map[string][]time.Time // key: "userID:integrationID"
	limit    int                    // max requests per window
	window   time.Duration          // time window
}

// newTestNotificationRateLimiter creates a new rate limiter.
// Default: 5 requests per minute per user+integration.
func newTestNotificationRateLimiter() *testNotificationRateLimiter {
	rl := &testNotificationRateLimiter{
		requests: make(map[string][]time.Time),
		limit:    5,
		window:   time.Minute,
	}
	// Start cleanup goroutine
	go rl.cleanup()
	return rl
}

// allow checks if a request is allowed and records it if so.
// Returns (allowed, remaining, retryAfter).
func (rl *testNotificationRateLimiter) allow(userID, integrationID string) (bool, int, time.Duration) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	key := userID + ":" + integrationID
	now := time.Now()
	cutoff := now.Add(-rl.window)

	// Filter to keep only requests within the window
	var recent []time.Time
	for _, t := range rl.requests[key] {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}

	remaining := rl.limit - len(recent)
	if remaining <= 0 {
		// Calculate retry after - time until oldest request expires
		if len(recent) > 0 {
			retryAfter := recent[0].Add(rl.window).Sub(now)
			if retryAfter < time.Second {
				retryAfter = time.Second
			}
			return false, 0, retryAfter
		}
		return false, 0, time.Second
	}

	// Allow and record
	recent = append(recent, now)
	rl.requests[key] = recent

	return true, remaining - 1, 0
}

// cleanup removes old entries periodically.
func (rl *testNotificationRateLimiter) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		cutoff := now.Add(-rl.window)
		for key, times := range rl.requests {
			var recent []time.Time
			for _, t := range times {
				if t.After(cutoff) {
					recent = append(recent, t)
				}
			}
			if len(recent) == 0 {
				delete(rl.requests, key)
			} else {
				rl.requests[key] = recent
			}
		}
		rl.mu.Unlock()
	}
}

// NewIntegrationHandler creates a new integration handler.
func NewIntegrationHandler(svc *app.IntegrationService, v *validator.Validator, log *logger.Logger) *IntegrationHandler {
	return &IntegrationHandler{
		service:              svc,
		validator:            v,
		logger:               log,
		testNotifRateLimiter: newTestNotificationRateLimiter(),
	}
}

// IntegrationResponse represents an integration in API responses.
// @Description Integration details including provider info and status
type IntegrationResponse struct {
	ID                  string                    `json:"id" example:"550e8400-e29b-41d4-a716-446655440000"`
	TenantID            string                    `json:"tenant_id,omitempty" example:"550e8400-e29b-41d4-a716-446655440001"`
	Name                string                    `json:"name" example:"GitHub Production"`
	Description         string                    `json:"description,omitempty" example:"Main GitHub integration"`
	Category            string                    `json:"category" example:"scm" enums:"scm,security,cloud,ticketing,notification"`
	Provider            string                    `json:"provider" example:"github"`
	Status              string                    `json:"status" example:"connected" enums:"pending,connected,disconnected,error"`
	StatusMessage       string                    `json:"status_message,omitempty" example:""`
	AuthType            string                    `json:"auth_type" example:"token" enums:"token,oauth,api_key,basic,app"`
	BaseURL             string                    `json:"base_url,omitempty" example:"https://github.com"`
	LastSyncAt          *time.Time                `json:"last_sync_at,omitempty" example:"2024-01-15T10:30:00Z"`
	NextSyncAt          *time.Time                `json:"next_sync_at,omitempty" example:"2024-01-15T11:30:00Z"`
	SyncIntervalMinutes int                       `json:"sync_interval_minutes" example:"60"`
	SyncError           string                    `json:"sync_error,omitempty" example:""`
	Config              map[string]any            `json:"config,omitempty"`
	Metadata            map[string]any            `json:"metadata,omitempty"`
	Stats               *IntegrationStatsResponse `json:"stats,omitempty"`
	SCMExtension        *SCMExtensionResponse     `json:"scm_extension,omitempty"`
	CreatedAt           time.Time                 `json:"created_at" example:"2024-01-01T00:00:00Z"`
	UpdatedAt           time.Time                 `json:"updated_at" example:"2024-01-15T10:30:00Z"`
	CreatedBy           string                    `json:"created_by,omitempty" example:"user-123"`
}

// IntegrationStatsResponse represents integration statistics.
type IntegrationStatsResponse struct {
	TotalAssets       int `json:"total_assets,omitempty"`
	TotalFindings     int `json:"total_findings,omitempty"`
	TotalRepositories int `json:"total_repositories,omitempty"`
}

// SCMExtensionResponse represents SCM-specific extension data.
type SCMExtensionResponse struct {
	SCMOrganization      string     `json:"scm_organization,omitempty" example:"my-organization"`
	RepositoryCount      int        `json:"repository_count" example:"25"`
	WebhookID            string     `json:"webhook_id,omitempty"`
	WebhookURL           string     `json:"webhook_url,omitempty"`
	DefaultBranchPattern string     `json:"default_branch_pattern,omitempty" example:"main,master"`
	AutoImportRepos      bool       `json:"auto_import_repos" example:"false"`
	ImportPrivateRepos   bool       `json:"import_private_repos" example:"true"`
	ImportArchivedRepos  bool       `json:"import_archived_repos" example:"false"`
	IncludePatterns      []string   `json:"include_patterns,omitempty"`
	ExcludePatterns      []string   `json:"exclude_patterns,omitempty"`
	LastRepoSyncAt       *time.Time `json:"last_repo_sync_at,omitempty"`
}

// sensitiveConfigKeys contains keys that should be redacted from integration config/metadata responses.
// These are case-insensitive patterns that may contain credentials or secrets.
var sensitiveConfigKeys = map[string]bool{
	"token":          true,
	"access_token":   true,
	"refresh_token":  true,
	"api_key":        true,
	"apikey":         true,
	"secret":         true,
	"secret_key":     true,
	"secretkey":      true,
	"password":       true,
	"private_key":    true,
	"privatekey":     true,
	"client_secret":  true,
	"clientsecret":   true,
	"credentials":    true,
	"auth":           true,
	"authorization":  true,
	"bearer":         true,
	"webhook_secret": true,
	"signing_secret": true,
	"app_secret":     true,
	"installation":   true, // GitHub App installation tokens
	"key":            true,
}

// sanitizeConfigMap removes sensitive values from a config/metadata map.
// Returns a new map with sensitive values replaced by "[REDACTED]".
func sanitizeConfigMap(config map[string]any) map[string]any {
	if config == nil {
		return nil
	}

	sanitized := make(map[string]any, len(config))
	for k, v := range config {
		keyLower := strings.ToLower(k)

		// Check if this key contains sensitive data
		isSensitive := false
		for sensitiveKey := range sensitiveConfigKeys {
			if strings.Contains(keyLower, sensitiveKey) {
				isSensitive = true
				break
			}
		}

		if isSensitive {
			sanitized[k] = "[REDACTED]"
		} else if nestedMap, ok := v.(map[string]any); ok {
			// Recursively sanitize nested maps
			sanitized[k] = sanitizeConfigMap(nestedMap)
		} else {
			sanitized[k] = v
		}
	}
	return sanitized
}

// toIntegrationResponse converts a domain integration to API response.
// Sensitive fields in Config and Metadata are automatically redacted.
func toIntegrationResponse(i *integration.Integration) IntegrationResponse {
	var createdBy string
	if i.CreatedBy() != nil {
		createdBy = i.CreatedBy().String()
	}

	resp := IntegrationResponse{
		ID:                  i.ID().String(),
		TenantID:            i.TenantID().String(),
		Name:                i.Name(),
		Description:         i.Description(),
		Category:            string(i.Category()),
		Provider:            string(i.Provider()),
		Status:              string(i.Status()),
		StatusMessage:       i.StatusMessage(),
		AuthType:            string(i.AuthType()),
		BaseURL:             i.BaseURL(),
		LastSyncAt:          i.LastSyncAt(),
		NextSyncAt:          i.NextSyncAt(),
		SyncIntervalMinutes: i.SyncIntervalMinutes(),
		SyncError:           i.SyncError(),
		Config:              sanitizeConfigMap(i.Config()),   // Sanitize sensitive data
		Metadata:            sanitizeConfigMap(i.Metadata()), // Sanitize sensitive data
		CreatedAt:           i.CreatedAt(),
		UpdatedAt:           i.UpdatedAt(),
		CreatedBy:           createdBy,
	}

	// Map stats
	stats := i.Stats()
	resp.Stats = &IntegrationStatsResponse{
		TotalAssets:       stats.TotalAssets,
		TotalFindings:     stats.TotalFindings,
		TotalRepositories: stats.TotalRepositories,
	}

	return resp
}

// toIntegrationWithSCMResponse converts a domain IntegrationWithSCM to API response.
func toIntegrationWithSCMResponse(iws *integration.IntegrationWithSCM) IntegrationResponse {
	resp := toIntegrationResponse(iws.Integration)

	if ext := iws.SCM; ext != nil {
		resp.SCMExtension = &SCMExtensionResponse{
			SCMOrganization:      ext.SCMOrganization(),
			RepositoryCount:      ext.RepositoryCount(),
			WebhookID:            ext.WebhookID(),
			WebhookURL:           ext.WebhookURL(),
			DefaultBranchPattern: ext.DefaultBranchPattern(),
			AutoImportRepos:      ext.AutoImportRepos(),
			ImportPrivateRepos:   ext.ImportPrivateRepos(),
			ImportArchivedRepos:  ext.ImportArchivedRepos(),
			IncludePatterns:      ext.IncludePatterns(),
			ExcludePatterns:      ext.ExcludePatterns(),
			LastRepoSyncAt:       ext.LastRepoSyncAt(),
		}
	}

	return resp
}

// CreateIntegrationRequest represents the request to create an integration.
// @Description Request body for creating a new integration
type CreateIntegrationRequest struct {
	Name            string `json:"name" validate:"required,min=1,max=255" example:"GitHub Production"`
	Description     string `json:"description" validate:"omitempty,max=1000" example:"Main GitHub integration"`
	Category        string `json:"category" validate:"required,oneof=scm security cloud ticketing notification" example:"scm"`
	Provider        string `json:"provider" validate:"required" example:"github"`
	AuthType        string `json:"auth_type" validate:"required,oneof=token oauth api_key basic app" example:"token"`
	BaseURL         string `json:"base_url" validate:"omitempty,url" example:"https://github.com"`
	Credentials     string `json:"credentials" validate:"omitempty,max=5000" example:"YOUR_TOKEN_HERE"`
	SCMOrganization string `json:"scm_organization" validate:"omitempty,max=255" example:"my-organization"`
}

// UpdateIntegrationRequest represents the request to update an integration.
// @Description Request body for updating an existing integration
type UpdateIntegrationRequest struct {
	Name            *string `json:"name" validate:"omitempty,min=1,max=255" example:"GitHub Production Updated"`
	Description     *string `json:"description" validate:"omitempty,max=1000"`
	Credentials     *string `json:"credentials" validate:"omitempty,max=5000"`
	BaseURL         *string `json:"base_url" validate:"omitempty,url"`
	SCMOrganization *string `json:"scm_organization" validate:"omitempty,max=255"`
}

// TestIntegrationCredentialsRequest represents the request to test credentials without creating.
// @Description Request body for testing integration credentials
type TestIntegrationCredentialsRequest struct {
	Category        string `json:"category" validate:"required,oneof=scm security cloud ticketing notification" example:"scm"`
	Provider        string `json:"provider" validate:"required" example:"github"`
	BaseURL         string `json:"base_url" validate:"omitempty,url" example:"https://github.com"`
	AuthType        string `json:"auth_type" validate:"required,oneof=token oauth api_key basic app" example:"token"`
	Credentials     string `json:"credentials" validate:"required,max=5000" example:"YOUR_TOKEN_HERE"`
	SCMOrganization string `json:"scm_organization" validate:"omitempty,max=255" example:"my-organization"`
}

// TestIntegrationCredentialsResponse represents the response from testing credentials.
// @Description Response from testing integration credentials
type TestIntegrationCredentialsResponse struct {
	Success         bool   `json:"success" example:"true"`
	Message         string `json:"message" example:"Connection successful"`
	RepositoryCount int    `json:"repository_count,omitempty" example:"25"`
	Organization    string `json:"organization,omitempty" example:"my-org"`
	Username        string `json:"username,omitempty" example:"octocat"`
}

// SCMRepositoryResponse represents a repository from an SCM provider.
// @Description Repository from SCM provider
type SCMRepositoryResponse struct {
	ID            string         `json:"id"`
	Name          string         `json:"name"`
	FullName      string         `json:"full_name"`
	Description   string         `json:"description,omitempty"`
	HTMLURL       string         `json:"html_url"`
	CloneURL      string         `json:"clone_url"`
	SSHURL        string         `json:"ssh_url"`
	DefaultBranch string         `json:"default_branch"`
	IsPrivate     bool           `json:"is_private"`
	IsFork        bool           `json:"is_fork"`
	IsArchived    bool           `json:"is_archived"`
	Language      string         `json:"language,omitempty"`
	Languages     map[string]int `json:"languages,omitempty"`
	Topics        []string       `json:"topics,omitempty"`
	Stars         int            `json:"stars"`
	Forks         int            `json:"forks"`
	Size          int            `json:"size"`
	CreatedAt     time.Time      `json:"created_at"`
	UpdatedAt     time.Time      `json:"updated_at"`
	PushedAt      time.Time      `json:"pushed_at"`
}

// ListSCMRepositoriesResponse represents the response for listing SCM repositories.
// @Description Response for listing SCM repositories
type ListSCMRepositoriesResponse struct {
	Repositories []SCMRepositoryResponse `json:"repositories"`
	Total        int                     `json:"total"`
	HasMore      bool                    `json:"has_more"`
	NextPage     int                     `json:"next_page"`
}

// handleValidationError converts validation errors to API errors.
func (h *IntegrationHandler) handleValidationError(w http.ResponseWriter, err error) {
	var validationErrors validator.ValidationErrors
	if errors.As(err, &validationErrors) {
		apiErrors := make([]apierror.ValidationError, len(validationErrors))
		for i, ve := range validationErrors {
			apiErrors[i] = apierror.ValidationError{
				Field:   ve.Field,
				Message: ve.Message,
			}
		}
		apierror.ValidationFailed("Validation failed", apiErrors).WriteJSON(w)
		return
	}
	apierror.BadRequest("Validation error").WriteJSON(w)
}

// handleServiceError converts service errors to API errors.
func (h *IntegrationHandler) handleServiceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Integration").WriteJSON(w)
	case errors.Is(err, shared.ErrAlreadyExists):
		apierror.Conflict("Integration already exists").WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(err.Error()).WriteJSON(w)
	default:
		h.logger.Error("service error", "error", err)
		apierror.InternalError(err).WriteJSON(w)
	}
}

// List handles GET /api/v1/integrations
// @Summary      List integrations
// @Description  Returns a paginated list of integrations for the current tenant
// @Tags         Integrations
// @Accept       json
// @Produce      json
// @Param        category   query     string  false  "Filter by category"  Enums(scm, security, cloud, ticketing, notification)
// @Param        provider   query     string  false  "Filter by provider"
// @Param        status     query     string  false  "Filter by status"    Enums(pending, connected, disconnected, error)
// @Param        search     query     string  false  "Search by name"
// @Param        page       query     int     false  "Page number"         default(1)  minimum(1)
// @Param        per_page   query     int     false  "Items per page"      default(20) minimum(1) maximum(100)
// @Param        sort       query     string  false  "Sort field"          Enums(name, category, provider, status, created_at, updated_at)
// @Param        order      query     string  false  "Sort order"          Enums(asc, desc)
// @Success      200  {object}  ListResponse[IntegrationResponse]  "List of integrations"
// @Failure      401  {object}  map[string]string  "Unauthorized"
// @Failure      403  {object}  map[string]string  "Forbidden - insufficient permissions"
// @Failure      500  {object}  map[string]string  "Internal server error"
// @Security     BearerAuth
// @Router       /integrations [get]
func (h *IntegrationHandler) List(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	query := r.URL.Query()
	input := app.ListIntegrationsInput{
		TenantID:  tenantID,
		Category:  query.Get("category"),
		Provider:  query.Get("provider"),
		Status:    query.Get("status"),
		Search:    query.Get("search"),
		Page:      parseQueryInt(query.Get("page"), 1),
		PerPage:   parseQueryInt(query.Get("per_page"), 20),
		SortBy:    query.Get("sort"),
		SortOrder: query.Get("order"),
	}

	result, err := h.service.ListIntegrations(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	data := make([]IntegrationResponse, len(result.Data))
	for i, intg := range result.Data {
		data[i] = toIntegrationResponse(intg)
	}

	response := ListResponse[IntegrationResponse]{
		Data:       data,
		Total:      result.Total,
		Page:       result.Page,
		PerPage:    result.PerPage,
		TotalPages: result.TotalPages,
		Links:      NewPaginationLinks(r, result.Page, result.PerPage, result.TotalPages),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}

// ListSCM handles GET /api/v1/integrations/scm
// @Summary      List SCM integrations
// @Description  Returns a list of SCM integrations with their extensions
// @Tags         Integrations
// @Accept       json
// @Produce      json
// @Success      200  {object}  map[string][]IntegrationResponse  "List of SCM integrations"
// @Failure      401  {object}  map[string]string  "Unauthorized"
// @Failure      403  {object}  map[string]string  "Forbidden"
// @Failure      500  {object}  map[string]string  "Internal server error"
// @Security     BearerAuth
// @Router       /integrations/scm [get]
func (h *IntegrationHandler) ListSCM(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	result, err := h.service.ListSCMIntegrations(r.Context(), tenantID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	data := make([]IntegrationResponse, len(result))
	for i, iws := range result {
		data[i] = toIntegrationWithSCMResponse(iws)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"data": data,
	})
}

// Create handles POST /api/v1/integrations
// @Summary      Create integration
// @Description  Creates a new integration for connecting with external providers
// @Tags         Integrations
// @Accept       json
// @Produce      json
// @Param        request  body      CreateIntegrationRequest  true  "Integration details"
// @Success      201      {object}  IntegrationResponse       "Created integration"
// @Failure      400      {object}  map[string]string         "Bad request - validation error"
// @Failure      401      {object}  map[string]string         "Unauthorized"
// @Failure      403      {object}  map[string]string         "Forbidden - insufficient permissions"
// @Failure      409      {object}  map[string]string         "Conflict - integration with same name exists"
// @Failure      500      {object}  map[string]string         "Internal server error"
// @Security     BearerAuth
// @Router       /integrations [post]
func (h *IntegrationHandler) Create(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	userID := middleware.GetUserID(r.Context())

	var req CreateIntegrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	// Suppress unused variable warning for userID (may be used for audit logging)
	_ = userID

	input := app.CreateIntegrationInput{
		TenantID:        tenantID,
		Name:            req.Name,
		Description:     req.Description,
		Category:        req.Category,
		Provider:        req.Provider,
		AuthType:        req.AuthType,
		BaseURL:         req.BaseURL,
		Credentials:     req.Credentials,
		SCMOrganization: req.SCMOrganization,
	}

	intg, err := h.service.CreateIntegration(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(toIntegrationWithSCMResponse(intg))
}

// Get handles GET /api/v1/integrations/{id}
// @Summary      Get integration
// @Description  Retrieves details of a specific integration by ID
// @Tags         Integrations
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "Integration ID"  format(uuid)
// @Success      200  {object}  IntegrationResponse  "Integration details"
// @Failure      400  {object}  map[string]string    "Bad request - invalid ID"
// @Failure      401  {object}  map[string]string    "Unauthorized"
// @Failure      403  {object}  map[string]string    "Forbidden - insufficient permissions"
// @Failure      404  {object}  map[string]string    "Not found"
// @Failure      500  {object}  map[string]string    "Internal server error"
// @Security     BearerAuth
// @Router       /integrations/{id} [get]
func (h *IntegrationHandler) Get(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	id := r.PathValue("id")
	if id == "" {
		apierror.BadRequest("Integration ID is required").WriteJSON(w)
		return
	}

	intg, err := h.service.GetIntegration(r.Context(), id)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	// Verify tenant ownership
	if intg.TenantID().String() != tenantID {
		apierror.NotFound("Integration").WriteJSON(w)
		return
	}

	// If it's an SCM integration, get the full details with extension
	if intg.IsSCM() {
		iws, err := h.service.GetIntegrationWithSCM(r.Context(), id)
		if err == nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(toIntegrationWithSCMResponse(iws))
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(toIntegrationResponse(intg))
}

// Update handles PUT /api/v1/integrations/{id}
// @Summary      Update integration
// @Description  Updates an existing integration. Only provided fields will be updated.
// @Tags         Integrations
// @Accept       json
// @Produce      json
// @Param        id       path      string                    true  "Integration ID"  format(uuid)
// @Param        request  body      UpdateIntegrationRequest  true  "Fields to update"
// @Success      200      {object}  IntegrationResponse       "Updated integration"
// @Failure      400      {object}  map[string]string         "Bad request - validation error"
// @Failure      401      {object}  map[string]string         "Unauthorized"
// @Failure      403      {object}  map[string]string         "Forbidden - insufficient permissions"
// @Failure      404      {object}  map[string]string          "Not found"
// @Failure      409      {object}  map[string]string         "Conflict - name already exists"
// @Failure      500      {object}  map[string]string         "Internal server error"
// @Security     BearerAuth
// @Router       /integrations/{id} [put]
func (h *IntegrationHandler) Update(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	id := r.PathValue("id")
	if id == "" {
		apierror.BadRequest("Integration ID is required").WriteJSON(w)
		return
	}

	var req UpdateIntegrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	input := app.UpdateIntegrationInput{
		Name:            req.Name,
		Description:     req.Description,
		Credentials:     req.Credentials,
		BaseURL:         req.BaseURL,
		SCMOrganization: req.SCMOrganization,
	}

	intg, err := h.service.UpdateIntegration(r.Context(), id, tenantID, input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(toIntegrationWithSCMResponse(intg))
}

// Delete handles DELETE /api/v1/integrations/{id}
// @Summary      Delete integration
// @Description  Permanently deletes an integration. This action cannot be undone.
// @Tags         Integrations
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "Integration ID"  format(uuid)
// @Success      204  "No content - successfully deleted"
// @Failure      400  {object}  map[string]string  "Bad request - invalid ID"
// @Failure      401  {object}  map[string]string  "Unauthorized"
// @Failure      403  {object}  map[string]string  "Forbidden - insufficient permissions"
// @Failure      404  {object}  map[string]string  "Not found"
// @Failure      500  {object}  map[string]string  "Internal server error"
// @Security     BearerAuth
// @Router       /integrations/{id} [delete]
func (h *IntegrationHandler) Delete(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	id := r.PathValue("id")
	if id == "" {
		apierror.BadRequest("Integration ID is required").WriteJSON(w)
		return
	}

	if err := h.service.DeleteIntegration(r.Context(), id, tenantID); err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// Test handles POST /api/v1/integrations/{id}/test
// @Summary      Test integration
// @Description  Tests the integration by verifying credentials and connectivity
// @Tags         Integrations
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "Integration ID"  format(uuid)
// @Success      200  {object}  IntegrationResponse  "Connection test result with updated status"
// @Failure      400  {object}  map[string]string    "Bad request - invalid ID"
// @Failure      401  {object}  map[string]string    "Unauthorized"
// @Failure      403  {object}  map[string]string    "Forbidden - insufficient permissions"
// @Failure      404  {object}  map[string]string    "Not found"
// @Failure      500  {object}  map[string]string    "Internal server error"
// @Security     BearerAuth
// @Router       /integrations/{id}/test [post]
func (h *IntegrationHandler) Test(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	id := r.PathValue("id")
	if id == "" {
		apierror.BadRequest("Integration ID is required").WriteJSON(w)
		return
	}

	intg, err := h.service.TestIntegration(r.Context(), id, tenantID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(toIntegrationWithSCMResponse(intg))
}

// TestCredentials handles POST /api/v1/integrations/test-credentials
// @Summary      Test integration credentials without creating
// @Description  Tests integration credentials by verifying connectivity without persisting
// @Tags         Integrations
// @Accept       json
// @Produce      json
// @Param        request  body      TestIntegrationCredentialsRequest   true  "Credentials to test"
// @Success      200      {object}  TestIntegrationCredentialsResponse  "Credentials test result"
// @Failure      400      {object}  map[string]string                   "Bad request - validation error"
// @Failure      401      {object}  map[string]string                   "Unauthorized"
// @Failure      403      {object}  map[string]string                   "Forbidden - insufficient permissions"
// @Failure      500      {object}  map[string]string                   "Internal server error"
// @Security     BearerAuth
// @Router       /integrations/test-credentials [post]
func (h *IntegrationHandler) TestCredentials(w http.ResponseWriter, r *http.Request) {
	var req TestIntegrationCredentialsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(&req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	result, err := h.service.TestIntegrationCredentials(r.Context(), app.TestIntegrationCredentialsInput{
		Category:        req.Category,
		Provider:        req.Provider,
		BaseURL:         req.BaseURL,
		AuthType:        req.AuthType,
		Credentials:     req.Credentials,
		SCMOrganization: req.SCMOrganization,
	})
	if err != nil {
		// Return test failure as success response with success=false
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(TestIntegrationCredentialsResponse{
			Success: false,
			Message: err.Error(),
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(TestIntegrationCredentialsResponse{
		Success:         result.Success,
		Message:         result.Message,
		RepositoryCount: result.RepoCount,
		Organization:    result.Organization,
		Username:        result.Username,
	})
}

// Sync handles POST /api/v1/integrations/{id}/sync
// @Summary      Sync integration
// @Description  Triggers a sync for the integration
// @Tags         Integrations
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "Integration ID"  format(uuid)
// @Success      200  {object}  IntegrationResponse  "Integration with updated sync status"
// @Failure      400  {object}  map[string]string    "Bad request - invalid ID"
// @Failure      401  {object}  map[string]string    "Unauthorized"
// @Failure      403  {object}  map[string]string    "Forbidden - insufficient permissions"
// @Failure      404  {object}  map[string]string    "Not found"
// @Failure      500  {object}  map[string]string    "Internal server error"
// @Security     BearerAuth
// @Router       /integrations/{id}/sync [post]
func (h *IntegrationHandler) Sync(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	id := r.PathValue("id")
	if id == "" {
		apierror.BadRequest("Integration ID is required").WriteJSON(w)
		return
	}

	intg, err := h.service.SyncIntegration(r.Context(), id, tenantID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(toIntegrationWithSCMResponse(intg))
}

// Enable handles POST /api/v1/integrations/{id}/enable
// @Summary      Enable integration
// @Description  Enables a disabled integration
// @Tags         Integrations
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "Integration ID"  format(uuid)
// @Success      200  {object}  IntegrationResponse  "Enabled integration"
// @Failure      400  {object}  map[string]string    "Bad request - invalid ID"
// @Failure      401  {object}  map[string]string    "Unauthorized"
// @Failure      403  {object}  map[string]string    "Forbidden"
// @Failure      404  {object}  map[string]string    "Not found"
// @Failure      500  {object}  map[string]string    "Internal server error"
// @Security     BearerAuth
// @Router       /integrations/{id}/enable [post]
func (h *IntegrationHandler) Enable(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	id := r.PathValue("id")
	if id == "" {
		apierror.BadRequest("Integration ID is required").WriteJSON(w)
		return
	}

	intg, err := h.service.EnableIntegration(r.Context(), id, tenantID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(toIntegrationWithSCMResponse(intg))
}

// Disable handles POST /api/v1/integrations/{id}/disable
// @Summary      Disable integration
// @Description  Disables an active integration
// @Tags         Integrations
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "Integration ID"  format(uuid)
// @Success      200  {object}  IntegrationResponse  "Disabled integration"
// @Failure      400  {object}  map[string]string    "Bad request - invalid ID"
// @Failure      401  {object}  map[string]string    "Unauthorized"
// @Failure      403  {object}  map[string]string    "Forbidden"
// @Failure      404  {object}  map[string]string    "Not found"
// @Failure      500  {object}  map[string]string    "Internal server error"
// @Security     BearerAuth
// @Router       /integrations/{id}/disable [post]
func (h *IntegrationHandler) Disable(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	id := r.PathValue("id")
	if id == "" {
		apierror.BadRequest("Integration ID is required").WriteJSON(w)
		return
	}

	intg, err := h.service.DisableIntegration(r.Context(), id, tenantID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(toIntegrationResponse(intg))
}

// ListRepositories handles GET /api/v1/integrations/{id}/repositories
// @Summary      List repositories from SCM integration
// @Description  Lists repositories accessible through an SCM integration
// @Tags         Integrations
// @Accept       json
// @Produce      json
// @Param        id        path      string  true   "Integration ID"  format(uuid)
// @Param        search    query     string  false  "Search by repository name"
// @Param        page      query     int     false  "Page number"         default(1)  minimum(1)
// @Param        per_page  query     int     false  "Items per page"      default(30) minimum(1) maximum(100)
// @Success      200       {object}  ListSCMRepositoriesResponse  "List of repositories"
// @Failure      400       {object}  map[string]string            "Bad request - invalid ID or not an SCM integration"
// @Failure      401       {object}  map[string]string            "Unauthorized"
// @Failure      403       {object}  map[string]string            "Forbidden - insufficient permissions"
// @Failure      404       {object}  map[string]string            "Not found"
// @Failure      500       {object}  map[string]string            "Internal server error"
// @Security     BearerAuth
// @Router       /integrations/{id}/repositories [get]
func (h *IntegrationHandler) ListRepositories(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	id := r.PathValue("id")
	if id == "" {
		apierror.BadRequest("Integration ID is required").WriteJSON(w)
		return
	}

	query := r.URL.Query()
	input := app.IntegrationListReposInput{
		IntegrationID: id,
		TenantID:      tenantID,
		Search:        query.Get("search"),
		Page:          parseQueryInt(query.Get("page"), 1),
		PerPage:       parseQueryInt(query.Get("per_page"), 30),
	}

	result, err := h.service.ListSCMRepositories(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	// Convert to response format
	repos := make([]SCMRepositoryResponse, len(result.Repositories))
	for i, repo := range result.Repositories {
		repos[i] = SCMRepositoryResponse{
			ID:            repo.ID,
			Name:          repo.Name,
			FullName:      repo.FullName,
			Description:   repo.Description,
			HTMLURL:       repo.HTMLURL,
			CloneURL:      repo.CloneURL,
			SSHURL:        repo.SSHURL,
			DefaultBranch: repo.DefaultBranch,
			IsPrivate:     repo.IsPrivate,
			IsFork:        repo.IsFork,
			IsArchived:    repo.IsArchived,
			Language:      repo.Language,
			Languages:     repo.Languages,
			Topics:        repo.Topics,
			Stars:         repo.Stars,
			Forks:         repo.Forks,
			Size:          repo.Size,
			CreatedAt:     repo.CreatedAt,
			UpdatedAt:     repo.UpdatedAt,
			PushedAt:      repo.PushedAt,
		}
	}

	response := ListSCMRepositoriesResponse{
		Repositories: repos,
		Total:        result.Total,
		HasMore:      result.HasMore,
		NextPage:     result.NextPage,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}

// ============================================
// NOTIFICATION INTEGRATION HANDLERS
// ============================================

// NotificationExtensionResponse represents notification-specific extension data.
// Note: channel_id and channel_name are DEPRECATED. They are now stored in integrations.metadata.
// For Telegram: read metadata.chat_id
// For Slack/Teams: read metadata.channel_name
// For Email: read metadata.smtp_host, metadata.smtp_port, metadata.from_email, etc.
type NotificationExtensionResponse struct {
	ChannelID          string   `json:"channel_id,omitempty" example:"C123456"`            // Deprecated: use metadata.chat_id
	ChannelName        string   `json:"channel_name,omitempty" example:"#security-alerts"` // Deprecated: use metadata.channel_name
	EnabledSeverities  []string `json:"enabled_severities" example:"[\"critical\",\"high\"]"`
	EnabledEventTypes  []string `json:"enabled_event_types" example:"[\"security_alert\",\"new_finding\",\"new_exposure\"]"`
	MessageTemplate    string   `json:"message_template,omitempty"`
	IncludeDetails     bool     `json:"include_details" example:"true"`
	MinIntervalMinutes int      `json:"min_interval_minutes" example:"5"`
}

// IntegrationWithNotificationResponse represents an integration with notification extension.
type IntegrationWithNotificationResponse struct {
	IntegrationResponse
	NotificationExtension *NotificationExtensionResponse `json:"notification_extension,omitempty"`
}

// toIntegrationWithNotificationResponse converts a domain integration with notification to API response.
func toIntegrationWithNotificationResponse(iwn *integration.IntegrationWithNotification) IntegrationWithNotificationResponse {
	resp := IntegrationWithNotificationResponse{
		IntegrationResponse: toIntegrationResponse(iwn.Integration),
	}

	if iwn.Notification != nil {
		// Convert severities to strings
		severities := iwn.Notification.EnabledSeverities()
		enabledSeverities := make([]string, 0, len(severities))
		for _, s := range severities {
			enabledSeverities = append(enabledSeverities, string(s))
		}

		// Convert event types to strings
		eventTypes := iwn.Notification.EnabledEventTypes()
		enabledEventTypes := make([]string, 0, len(eventTypes))
		for _, et := range eventTypes {
			enabledEventTypes = append(enabledEventTypes, string(et))
		}

		resp.NotificationExtension = &NotificationExtensionResponse{
			ChannelID:          iwn.Notification.ChannelID(),
			ChannelName:        iwn.Notification.ChannelName(),
			EnabledSeverities:  enabledSeverities,
			EnabledEventTypes:  enabledEventTypes,
			MessageTemplate:    iwn.Notification.MessageTemplate(),
			IncludeDetails:     iwn.Notification.IncludeDetails(),
			MinIntervalMinutes: iwn.Notification.MinIntervalMinutes(),
		}
	}

	return resp
}

// ListNotifications handles GET /api/v1/integrations/notifications
// @Summary      List notification integrations
// @Description  Returns a list of notification integrations with their extensions
// @Tags         Integrations
// @Accept       json
// @Produce      json
// @Success      200  {object}  map[string][]IntegrationWithNotificationResponse  "List of notification integrations"
// @Failure      401  {object}  map[string]string  "Unauthorized"
// @Failure      403  {object}  map[string]string  "Forbidden"
// @Failure      500  {object}  map[string]string  "Internal server error"
// @Security     BearerAuth
// @Router       /integrations/notifications [get]
func (h *IntegrationHandler) ListNotifications(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	result, err := h.service.ListNotificationIntegrations(r.Context(), tenantID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	data := make([]IntegrationWithNotificationResponse, len(result))
	for i, iwn := range result {
		data[i] = toIntegrationWithNotificationResponse(iwn)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"data": data,
	})
}

// CreateNotificationIntegrationRequest represents the request to create a notification integration.
type CreateNotificationIntegrationRequest struct {
	Name        string `json:"name" validate:"required,min=1,max=255"`
	Description string `json:"description" validate:"max=1000"`
	Provider    string `json:"provider" validate:"required,oneof=slack teams telegram webhook email"`
	AuthType    string `json:"auth_type" validate:"required,oneof=token api_key"`
	Credentials string `json:"credentials" validate:"required"` // Webhook URL or Bot Token

	// Notification-specific fields
	ChannelID          string   `json:"channel_id"`
	ChannelName        string   `json:"channel_name"`
	EnabledSeverities  []string `json:"enabled_severities"`  // Severity levels to notify on (critical, high, medium, low, info, none)
	EnabledEventTypes  []string `json:"enabled_event_types"` // Event types to receive notifications for
	MessageTemplate    string   `json:"message_template"`
	IncludeDetails     *bool    `json:"include_details"`
	MinIntervalMinutes *int     `json:"min_interval_minutes"`
}

// CreateNotification handles POST /api/v1/integrations/notifications
// @Summary      Create notification integration
// @Description  Creates a new notification integration (Slack, Teams, Telegram, Webhook)
// @Tags         Integrations
// @Accept       json
// @Produce      json
// @Param        request  body      CreateNotificationIntegrationRequest  true  "Notification integration details"
// @Success      201      {object}  IntegrationWithNotificationResponse   "Created notification integration"
// @Failure      400      {object}  map[string]string  "Bad request - validation error"
// @Failure      401      {object}  map[string]string  "Unauthorized"
// @Failure      403      {object}  map[string]string  "Forbidden"
// @Failure      409      {object}  map[string]string  "Conflict - integration with same name exists"
// @Failure      500      {object}  map[string]string  "Internal server error"
// @Security     BearerAuth
// @Router       /integrations/notifications [post]
func (h *IntegrationHandler) CreateNotification(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	var req CreateNotificationIntegrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	// Set defaults
	includeDetails := true
	if req.IncludeDetails != nil {
		includeDetails = *req.IncludeDetails
	}
	minInterval := 5
	if req.MinIntervalMinutes != nil && *req.MinIntervalMinutes > 0 {
		minInterval = *req.MinIntervalMinutes
	}

	input := app.CreateNotificationIntegrationInput{
		TenantID:           tenantID,
		Name:               req.Name,
		Description:        req.Description,
		Provider:           req.Provider,
		AuthType:           req.AuthType,
		Credentials:        req.Credentials,
		ChannelID:          req.ChannelID,
		ChannelName:        req.ChannelName,
		EnabledSeverities:  req.EnabledSeverities,
		EnabledEventTypes:  req.EnabledEventTypes,
		MessageTemplate:    req.MessageTemplate,
		IncludeDetails:     includeDetails,
		MinIntervalMinutes: minInterval,
	}

	intg, err := h.service.CreateNotificationIntegration(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(toIntegrationWithNotificationResponse(intg))
}

// UpdateNotificationIntegrationRequest represents the request to update a notification integration.
type UpdateNotificationIntegrationRequest struct {
	Name        *string `json:"name" validate:"omitempty,min=1,max=255"`
	Description *string `json:"description" validate:"omitempty,max=1000"`
	Credentials *string `json:"credentials"` // Webhook URL or Bot Token (optional, leave empty to keep current)

	// Notification-specific fields
	ChannelID          *string  `json:"channel_id"`
	ChannelName        *string  `json:"channel_name"`
	EnabledSeverities  []string `json:"enabled_severities"`  // Severity levels to notify on
	EnabledEventTypes  []string `json:"enabled_event_types"` // Event types to receive notifications for
	MessageTemplate    *string  `json:"message_template"`
	IncludeDetails     *bool    `json:"include_details"`
	MinIntervalMinutes *int     `json:"min_interval_minutes"`
}

// UpdateNotification handles PUT /api/v1/integrations/{id}/notification
// @Summary      Update notification integration
// @Description  Updates an existing notification integration (Slack, Teams, Telegram, Webhook)
// @Tags         Integrations
// @Accept       json
// @Produce      json
// @Param        id       path      string                              true  "Integration ID"  format(uuid)
// @Param        request  body      UpdateNotificationIntegrationRequest  true  "Updated notification integration details"
// @Success      200      {object}  IntegrationWithNotificationResponse   "Updated notification integration"
// @Failure      400      {object}  map[string]string  "Bad request - validation error"
// @Failure      401      {object}  map[string]string  "Unauthorized"
// @Failure      403      {object}  map[string]string  "Forbidden"
// @Failure      404      {object}  map[string]string  "Not found"
// @Failure      500      {object}  map[string]string  "Internal server error"
// @Security     BearerAuth
// @Router       /integrations/{id}/notification [put]
func (h *IntegrationHandler) UpdateNotification(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	id := r.PathValue("id")
	if id == "" {
		apierror.BadRequest("Integration ID is required").WriteJSON(w)
		return
	}

	var req UpdateNotificationIntegrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	input := app.UpdateNotificationIntegrationInput{
		Name:               req.Name,
		Description:        req.Description,
		Credentials:        req.Credentials,
		ChannelID:          req.ChannelID,
		ChannelName:        req.ChannelName,
		EnabledSeverities:  req.EnabledSeverities,
		EnabledEventTypes:  req.EnabledEventTypes,
		MessageTemplate:    req.MessageTemplate,
		IncludeDetails:     req.IncludeDetails,
		MinIntervalMinutes: req.MinIntervalMinutes,
	}

	intg, err := h.service.UpdateNotificationIntegration(r.Context(), id, tenantID, input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(toIntegrationWithNotificationResponse(intg))
}

// TestNotification handles POST /api/v1/integrations/{id}/test-notification
// @Summary      Test notification integration
// @Description  Sends a test notification through the integration
// @Tags         Integrations
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "Integration ID"  format(uuid)
// @Success      200  {object}  map[string]any  "Test result"
// @Failure      400  {object}  map[string]string  "Bad request"
// @Failure      401  {object}  map[string]string  "Unauthorized"
// @Failure      403  {object}  map[string]string  "Forbidden"
// @Failure      404  {object}  map[string]string  "Not found"
// @Failure      500  {object}  map[string]string  "Internal server error"
// @Security     BearerAuth
// @Router       /integrations/{id}/test-notification [post]
func (h *IntegrationHandler) TestNotification(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	userID := middleware.GetUserID(r.Context())

	id := r.PathValue("id")
	if id == "" {
		apierror.BadRequest("Integration ID is required").WriteJSON(w)
		return
	}

	// Check rate limit (5 requests per minute per user+integration)
	allowed, remaining, retryAfter := h.testNotifRateLimiter.allow(userID, id)

	// Set rate limit headers
	w.Header().Set("X-RateLimit-Limit", "5")
	w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))

	if !allowed {
		w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter.Seconds())))
		h.logger.Warn("test notification rate limit exceeded",
			"user_id", userID,
			"integration_id", id,
			"retry_after", retryAfter,
		)
		apierror.New(http.StatusTooManyRequests, apierror.CodeRateLimitExceeded,
			"Rate limit exceeded. Please wait before sending another test notification.").WriteJSON(w)
		return
	}

	intg, err := h.service.TestNotificationIntegration(r.Context(), id, tenantID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	// Build response that frontend expects
	response := map[string]any{
		"success": intg.Integration.Status() == integration.StatusConnected,
	}

	// Include error if test failed
	if intg.Integration.Status() != integration.StatusConnected {
		response["error"] = intg.Integration.StatusMessage()
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}

// SendNotificationRequest represents the request to send a notification.
type SendNotificationRequest struct {
	Title    string            `json:"title" validate:"required,min=1,max=255"`
	Body     string            `json:"body" validate:"required,max=4000"`
	Severity string            `json:"severity" validate:"required,oneof=critical high medium low"`
	URL      string            `json:"url" validate:"omitempty,url"`
	Fields   map[string]string `json:"fields"`
}

// SendNotification handles POST /api/v1/integrations/{id}/send
// @Summary      Send notification
// @Description  Sends a notification through the specified integration
// @Tags         Integrations
// @Accept       json
// @Produce      json
// @Param        id       path      string                   true  "Integration ID"  format(uuid)
// @Param        request  body      SendNotificationRequest  true  "Notification content"
// @Success      200      {object}  map[string]any           "Send result"
// @Failure      400      {object}  map[string]string        "Bad request"
// @Failure      401      {object}  map[string]string        "Unauthorized"
// @Failure      403      {object}  map[string]string        "Forbidden"
// @Failure      404      {object}  map[string]string        "Not found"
// @Failure      500      {object}  map[string]string        "Internal server error"
// @Security     BearerAuth
// @Router       /integrations/{id}/send [post]
func (h *IntegrationHandler) SendNotification(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	id := r.PathValue("id")
	if id == "" {
		apierror.BadRequest("Integration ID is required").WriteJSON(w)
		return
	}

	var req SendNotificationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	result, err := h.service.SendNotification(r.Context(), app.SendNotificationInput{
		IntegrationID: id,
		TenantID:      tenantID,
		Title:         req.Title,
		Body:          req.Body,
		Severity:      req.Severity,
		URL:           req.URL,
		Fields:        req.Fields,
	})
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success":    result.Success,
		"message_id": result.MessageID,
		"error":      result.Error,
	})
}

// GetNotificationEvents handles GET /api/v1/integrations/{id}/notification-events
// @Summary      Get notification events
// @Description  Retrieves notification events for a specific integration from the audit trail
// @Tags         Integrations
// @Accept       json
// @Produce      json
// @Param        id      path      string  true   "Integration ID"  format(uuid)
// @Param        limit   query     int     false  "Maximum number of entries to return"  default(50) minimum(1) maximum(100)
// @Param        offset  query     int     false  "Number of entries to skip"  default(0) minimum(0)
// @Success      200     {object}  app.GetNotificationEventsResult  "Notification events with pagination"
// @Failure      400     {object}  map[string]string  "Bad request"
// @Failure      401     {object}  map[string]string  "Unauthorized"
// @Failure      403     {object}  map[string]string  "Forbidden"
// @Failure      404     {object}  map[string]string  "Not found"
// @Failure      500     {object}  map[string]string  "Internal server error"
// @Security     BearerAuth
// @Router       /integrations/{id}/notification-events [get]
func (h *IntegrationHandler) GetNotificationEvents(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	id := r.PathValue("id")
	if id == "" {
		apierror.BadRequest("Integration ID is required").WriteJSON(w)
		return
	}

	query := r.URL.Query()
	limit := parseQueryInt(query.Get("limit"), 50)
	offset := parseQueryInt(query.Get("offset"), 0)

	result, err := h.service.GetNotificationEvents(r.Context(), app.GetNotificationEventsInput{
		IntegrationID: id,
		TenantID:      tenantID,
		Limit:         limit,
		Offset:        offset,
	})
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(result)
}
