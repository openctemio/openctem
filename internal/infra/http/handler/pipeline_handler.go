package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	pipelinesvc "github.com/openctemio/api/internal/app/pipeline"
	scansvc "github.com/openctemio/api/internal/app/scan"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/domain/pipeline"
	"github.com/openctemio/api/pkg/domain/scanprofile"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/validator"
)

// PipelineHandler handles HTTP requests for pipelines.
type PipelineHandler struct {
	service   *pipelinesvc.Service
	validator *validator.Validator
	logger    *logger.Logger
}

// NewPipelineHandler creates a new PipelineHandler.
func NewPipelineHandler(service *pipelinesvc.Service, v *validator.Validator, log *logger.Logger) *PipelineHandler {
	return &PipelineHandler{
		service:   service,
		validator: v,
		logger:    log.With("handler", "pipeline"),
	}
}

// --- Template Request/Response Types ---

// CreateTemplateRequest represents the request body for creating a pipeline template.
type CreateTemplateRequest struct {
	Name        string                   `json:"name" validate:"required,min=1,max=255"`
	Description string                   `json:"description" validate:"max=1000"`
	Triggers    []TriggerRequest         `json:"triggers" validate:"max=10,dive"`
	Settings    *PipelineSettingsRequest `json:"settings"`
	Tags        []string                 `json:"tags" validate:"max=10,dive,max=50"`
	Steps       []CreateStepRequest      `json:"steps" validate:"max=50,dive"`
}

// TriggerRequest represents a trigger configuration in the request.
type TriggerRequest struct {
	Type     string         `json:"type" validate:"required,oneof=manual schedule webhook api on_asset_discovery"`
	Schedule string         `json:"schedule"`
	Webhook  string         `json:"webhook"`
	Filters  map[string]any `json:"filters"`
}

// PipelineSettingsRequest represents template settings in the request.
type PipelineSettingsRequest struct {
	MaxParallelSteps     int      `json:"max_parallel_steps" validate:"min=0,max=10"`
	FailFast             bool     `json:"fail_fast"`
	RetryFailedSteps     int      `json:"retry_failed_steps" validate:"min=0,max=5"`
	TimeoutSeconds       int      `json:"timeout_seconds" validate:"min=0,max=86400"`
	NotifyOnComplete     bool     `json:"notify_on_complete"`
	NotifyOnFailure      bool     `json:"notify_on_failure"`
	NotificationChannels []string `json:"notification_channels"`
	AgentPreference      string   `json:"agent_preference" validate:"omitempty,oneof=auto tenant platform"`
}

// UIPositionRequest represents a visual position in the workflow builder.
type UIPositionRequest struct {
	X float64 `json:"x"`
	Y float64 `json:"y"`
}

// CreateStepRequest represents a step in the create template request.
// Capabilities are optional - if not provided and tool is specified, they will be derived from the tool.
type CreateStepRequest struct {
	StepKey           string                 `json:"step_key" validate:"required,min=1,max=100"`
	Name              string                 `json:"name" validate:"required,min=1,max=255"`
	Description       string                 `json:"description" validate:"max=1000"`
	Order             int                    `json:"order"`
	UIPosition        *UIPositionRequest     `json:"ui_position"`
	Tool              string                 `json:"tool" validate:"max=100"`
	Capabilities      []string               `json:"capabilities" validate:"omitempty,max=10,dive,max=50"`
	Config            map[string]interface{} `json:"config"`
	TimeoutSeconds    int                    `json:"timeout_seconds"`
	DependsOn         []string               `json:"depends_on" validate:"max=20,dive,max=50"`
	Condition         *StepConditionRequest  `json:"condition"`
	MaxRetries        int                    `json:"max_retries"`
	RetryDelaySeconds int                    `json:"retry_delay_seconds"`
}

// StepConditionRequest represents a step condition in the request.
type StepConditionRequest struct {
	Type  string `json:"type" validate:"oneof=always never asset_type expression step_result"`
	Value string `json:"value" validate:"max=500"`
}

// TemplateResponse represents the response for a pipeline template.
type TemplateResponse struct {
	ID               string                   `json:"id"`
	TenantID         string                   `json:"tenant_id"`
	Name             string                   `json:"name"`
	Description      string                   `json:"description,omitempty"`
	Version          int                      `json:"version"`
	IsActive         bool                     `json:"is_active"`
	IsSystemTemplate bool                     `json:"is_system_template"`
	Triggers         []TriggerResponse        `json:"triggers"`
	Settings         PipelineSettingsResponse `json:"settings"`
	Tags             []string                 `json:"tags,omitempty"`
	Steps            []StepResponse           `json:"steps"`
	UIStartPosition  *UIPositionResponse      `json:"ui_start_position,omitempty"`
	UIEndPosition    *UIPositionResponse      `json:"ui_end_position,omitempty"`
	CreatedAt        string                   `json:"created_at"`
	UpdatedAt        string                   `json:"updated_at"`
}

// TriggerResponse represents a trigger in the response.
type TriggerResponse struct {
	Type     string         `json:"type"`
	Schedule string         `json:"schedule,omitempty"`
	Webhook  string         `json:"webhook,omitempty"`
	Filters  map[string]any `json:"filters,omitempty"`
}

// PipelineSettingsResponse represents template settings in the response.
type PipelineSettingsResponse struct {
	MaxParallelSteps     int      `json:"max_parallel_steps"`
	FailFast             bool     `json:"fail_fast"`
	RetryFailedSteps     int      `json:"retry_failed_steps"`
	TimeoutSeconds       int      `json:"timeout_seconds"`
	NotifyOnComplete     bool     `json:"notify_on_complete"`
	NotifyOnFailure      bool     `json:"notify_on_failure"`
	NotificationChannels []string `json:"notification_channels,omitempty"`
	AgentPreference      string   `json:"agent_preference"`
}

// UIPositionResponse represents a visual position in the workflow builder response.
type UIPositionResponse struct {
	X float64 `json:"x"`
	Y float64 `json:"y"`
}

// StepResponse represents a step in the response.
type StepResponse struct {
	ID                string                 `json:"id"`
	StepKey           string                 `json:"step_key"`
	Name              string                 `json:"name"`
	Description       string                 `json:"description,omitempty"`
	Order             int                    `json:"order"`
	UIPosition        UIPositionResponse     `json:"ui_position"`
	Tool              string                 `json:"tool,omitempty"`
	Capabilities      []string               `json:"capabilities"`
	Config            map[string]interface{} `json:"config,omitempty"`
	TimeoutSeconds    int                    `json:"timeout_seconds,omitempty"`
	DependsOn         []string               `json:"depends_on,omitempty"`
	Condition         *StepConditionResponse `json:"condition,omitempty"`
	MaxRetries        int                    `json:"max_retries"`
	RetryDelaySeconds int                    `json:"retry_delay_seconds"`
}

// StepConditionResponse represents a step condition in the response.
type StepConditionResponse struct {
	Type  string `json:"type"`
	Value string `json:"value,omitempty"`
}

// --- Run Request/Response Types ---

// TriggerRunRequest represents the request body for triggering a pipeline run.
type TriggerRunRequest struct {
	TemplateID  string         `json:"template_id" validate:"required,uuid"`
	AssetID     string         `json:"asset_id" validate:"omitempty,uuid"`
	TriggerType string         `json:"trigger_type" validate:"omitempty,oneof=manual schedule webhook api"`
	Context     map[string]any `json:"context"`
}

// RunResponse represents the response for a pipeline run.
type RunResponse struct {
	ID                string                         `json:"id"`
	TenantID          string                         `json:"tenant_id"`
	PipelineID        string                         `json:"pipeline_id"`
	AssetID           *string                        `json:"asset_id,omitempty"`
	ScanID            *string                        `json:"scan_id,omitempty"`
	ScanProfileID     *string                        `json:"scan_profile_id,omitempty"`
	TriggerType       string                         `json:"trigger_type"`
	TriggeredBy       string                         `json:"triggered_by,omitempty"`
	Status            string                         `json:"status"`
	StartedAt         *string                        `json:"started_at,omitempty"`
	CompletedAt       *string                        `json:"completed_at,omitempty"`
	TotalSteps        int                            `json:"total_steps"`
	CompletedSteps    int                            `json:"completed_steps"`
	FailedSteps       int                            `json:"failed_steps"`
	SkippedSteps      int                            `json:"skipped_steps"`
	TotalFindings     int                            `json:"total_findings"`
	QualityGateResult *scanprofile.QualityGateResult `json:"quality_gate_result,omitempty"`
	StepRuns          []StepRunResponse              `json:"step_runs,omitempty"`
	ErrorMessage      string                         `json:"error_message,omitempty"`
	CreatedAt         string                         `json:"created_at"`
	FilteringResult   *FilteringResultResponse       `json:"filtering_result,omitempty"`
}

// FilteringResultResponse represents smart filtering result in API response.
type FilteringResultResponse struct {
	TotalAssets          int                  `json:"total_assets"`
	ScannedAssets        int                  `json:"scanned_assets"`
	SkippedAssets        int                  `json:"skipped_assets"`
	UnclassifiedAssets   int                  `json:"unclassified_assets"`
	CompatibilityPercent float64              `json:"compatibility_percent"`
	ScannedByType        map[string]int       `json:"scanned_by_type,omitempty"`
	SkippedByType        map[string]int       `json:"skipped_by_type,omitempty"`
	SkipReasons          []SkipReasonResponse `json:"skip_reasons,omitempty"`
	WasFiltered          bool                 `json:"was_filtered"`
	ToolName             string               `json:"tool_name,omitempty"`
	SupportedTargets     []string             `json:"supported_targets,omitempty"`
}

// SkipReasonResponse explains why assets of a certain type were skipped.
type SkipReasonResponse struct {
	AssetType string `json:"asset_type"`
	Count     int    `json:"count"`
	Reason    string `json:"reason"`
}

// StepRunResponse represents a step run in the response.
type StepRunResponse struct {
	ID            string  `json:"id"`
	StepID        string  `json:"step_id"`
	StepKey       string  `json:"step_key"`
	Status        string  `json:"status"`
	StartedAt     *string `json:"started_at,omitempty"`
	CompletedAt   *string `json:"completed_at,omitempty"`
	ErrorMessage  string  `json:"error_message,omitempty"`
	ErrorCode     string  `json:"error_code,omitempty"`
	Attempt       int     `json:"attempt"`
	MaxAttempts   int     `json:"max_attempts"`
	FindingsCount int     `json:"findings_count"`
}

// --- Template Handlers ---

// CreateTemplate handles POST /api/v1/pipelines/templates
func (h *PipelineHandler) CreateTemplate(w http.ResponseWriter, r *http.Request) {
	var req CreateTemplateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	tenantID := middleware.GetTenantID(r.Context())
	userID := middleware.GetUserID(r.Context())

	input := pipelinesvc.CreateTemplateInput{
		TenantID:    tenantID,
		Name:        req.Name,
		Description: req.Description,
		Triggers:    toTriggers(req.Triggers),
		Settings:    toSettings(req.Settings),
		Tags:        req.Tags,
		CreatedBy:   userID,
	}

	template, err := h.service.CreateTemplate(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	// Add steps to template
	steps := make([]*pipeline.Step, 0, len(req.Steps))
	for i, stepReq := range req.Steps {
		stepInput := pipelinesvc.AddStepInput{
			TenantID:          tenantID,
			TemplateID:        template.ID.String(),
			StepKey:           stepReq.StepKey,
			Name:              stepReq.Name,
			Description:       stepReq.Description,
			Order:             stepReq.Order,
			Tool:              stepReq.Tool,
			Capabilities:      stepReq.Capabilities,
			Config:            stepReq.Config,
			TimeoutSeconds:    stepReq.TimeoutSeconds,
			DependsOn:         stepReq.DependsOn,
			Condition:         toCondition(stepReq.Condition),
			MaxRetries:        stepReq.MaxRetries,
			RetryDelaySeconds: stepReq.RetryDelaySeconds,
		}
		if stepReq.UIPosition != nil {
			stepInput.UIPositionX = &stepReq.UIPosition.X
			stepInput.UIPositionY = &stepReq.UIPosition.Y
		}
		if stepInput.Order == 0 {
			stepInput.Order = i + 1
		}
		step, err := h.service.AddStep(r.Context(), stepInput)
		if err != nil {
			h.handleServiceError(w, err)
			return
		}
		steps = append(steps, step)
	}
	template.Steps = steps

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(toTemplateResponse(template))
}

// GetTemplate handles GET /api/v1/pipelines/templates/{id}
func (h *PipelineHandler) GetTemplate(w http.ResponseWriter, r *http.Request) {
	templateID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())

	template, err := h.service.GetTemplate(r.Context(), tenantID, templateID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	// Get steps for template
	steps, err := h.service.GetSteps(r.Context(), templateID)
	if err != nil {
		h.logger.Warn("failed to get steps for template", "error", err, "template_id", templateID)
	} else {
		template.Steps = steps
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toTemplateResponse(template))
}

// ListTemplates handles GET /api/v1/pipelines/templates
func (h *PipelineHandler) ListTemplates(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())

	var isActive *bool
	if activeStr := r.URL.Query().Get("is_active"); activeStr != "" {
		active := activeStr == queryParamTrue
		isActive = &active
	}

	input := pipelinesvc.ListTemplatesInput{
		TenantID: tenantID,
		IsActive: isActive,
		Tags:     parseQueryArray(r.URL.Query().Get("tags")),
		Search:   r.URL.Query().Get("search"),
		Page:     parseQueryInt(r.URL.Query().Get("page"), 1),
		PerPage:  parseQueryInt(r.URL.Query().Get("per_page"), 20),
	}

	result, err := h.service.ListTemplates(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	items := make([]*TemplateResponse, len(result.Data))
	for i, t := range result.Data {
		items[i] = toTemplateResponse(t)
	}

	resp := map[string]interface{}{
		"items":       items,
		"total":       result.Total,
		"page":        result.Page,
		"per_page":    result.PerPage,
		"total_pages": result.TotalPages,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// UpdateTemplateRequest represents the request body for updating a template.
type UpdateTemplateRequest struct {
	Name            string                   `json:"name" validate:"omitempty,min=1,max=255"`
	Description     string                   `json:"description" validate:"max=1000"`
	Triggers        []TriggerRequest         `json:"triggers" validate:"max=10,dive"`
	Settings        *PipelineSettingsRequest `json:"settings"`
	Tags            []string                 `json:"tags" validate:"max=10,dive,max=50"`
	IsActive        *bool                    `json:"is_active"`
	Steps           []CreateStepRequest      `json:"steps" validate:"max=50,dive"`
	UIStartPosition *UIPositionRequest       `json:"ui_start_position"`
	UIEndPosition   *UIPositionRequest       `json:"ui_end_position"`
}

// UpdateTemplate handles PUT /api/v1/pipelines/templates/{id}
func (h *PipelineHandler) UpdateTemplate(w http.ResponseWriter, r *http.Request) {
	templateID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())

	var req UpdateTemplateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	input := pipelinesvc.UpdateTemplateInput{
		TenantID:        tenantID,
		TemplateID:      templateID,
		Name:            req.Name,
		Description:     req.Description,
		Triggers:        toTriggers(req.Triggers),
		Settings:        toSettings(req.Settings),
		Tags:            req.Tags,
		IsActive:        req.IsActive,
		UIStartPosition: toUIPosition(req.UIStartPosition),
		UIEndPosition:   toUIPosition(req.UIEndPosition),
	}

	template, err := h.service.UpdateTemplate(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	// If steps are provided, sync them (delete existing, add new)
	if req.Steps != nil {
		// IMPORTANT: Validate all steps BEFORE deleting to avoid data loss
		// Build step inputs and validate them first
		stepInputs := make([]pipelinesvc.AddStepInput, 0, len(req.Steps))
		for i, stepReq := range req.Steps {
			stepInput := pipelinesvc.AddStepInput{
				TenantID:          tenantID,
				TemplateID:        templateID,
				StepKey:           stepReq.StepKey,
				Name:              stepReq.Name,
				Description:       stepReq.Description,
				Order:             stepReq.Order,
				Tool:              stepReq.Tool,
				Capabilities:      stepReq.Capabilities,
				Config:            stepReq.Config,
				TimeoutSeconds:    stepReq.TimeoutSeconds,
				DependsOn:         stepReq.DependsOn,
				Condition:         toCondition(stepReq.Condition),
				MaxRetries:        stepReq.MaxRetries,
				RetryDelaySeconds: stepReq.RetryDelaySeconds,
			}
			if stepReq.UIPosition != nil {
				stepInput.UIPositionX = &stepReq.UIPosition.X
				stepInput.UIPositionY = &stepReq.UIPosition.Y
			}
			if stepInput.Order == 0 {
				stepInput.Order = i + 1
			}
			stepInputs = append(stepInputs, stepInput)
		}

		// Validate all steps before making any changes
		if err := h.service.ValidateSteps(r.Context(), stepInputs); err != nil {
			h.handleStepError(w, err)
			return
		}

		// Now safe to delete existing steps (validation passed)
		if err := h.service.DeleteStepsByPipelineID(r.Context(), tenantID, templateID); err != nil {
			// Ignore not found errors - there may be no existing steps
			if !errors.Is(err, shared.ErrNotFound) {
				h.handleServiceError(w, err)
				return
			}
		}

		// Add new steps (validation already passed, these should succeed)
		steps := make([]*pipeline.Step, 0, len(stepInputs))
		for _, stepInput := range stepInputs {
			step, err := h.service.AddStep(r.Context(), stepInput)
			if err != nil {
				// This shouldn't happen since we validated, but handle it gracefully
				h.logger.Error("step creation failed after validation",
					"step_key", stepInput.StepKey,
					"error", err)
				h.handleStepError(w, err)
				return
			}
			steps = append(steps, step)
		}
		template.Steps = steps
	} else {
		// Load existing steps for response
		steps, _ := h.service.GetSteps(r.Context(), templateID)
		template.Steps = steps
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toTemplateResponse(template))
}

// DeleteTemplate handles DELETE /api/v1/pipelines/templates/{id}
func (h *PipelineHandler) DeleteTemplate(w http.ResponseWriter, r *http.Request) {
	templateID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())

	if err := h.service.DeleteTemplate(r.Context(), tenantID, templateID); err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ActivateTemplate handles POST /api/v1/pipelines/{id}/activate
func (h *PipelineHandler) ActivateTemplate(w http.ResponseWriter, r *http.Request) {
	templateID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())

	isActive := true
	input := pipelinesvc.UpdateTemplateInput{
		TenantID:   tenantID,
		TemplateID: templateID,
		IsActive:   &isActive,
	}

	template, err := h.service.UpdateTemplate(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toTemplateResponse(template))
}

// DeactivateTemplate handles POST /api/v1/pipelines/{id}/deactivate
func (h *PipelineHandler) DeactivateTemplate(w http.ResponseWriter, r *http.Request) {
	templateID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())

	isActive := false
	input := pipelinesvc.UpdateTemplateInput{
		TenantID:   tenantID,
		TemplateID: templateID,
		IsActive:   &isActive,
	}

	template, err := h.service.UpdateTemplate(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toTemplateResponse(template))
}

// CloneTemplateRequest represents the request body for cloning a template.
type CloneTemplateRequest struct {
	Name string `json:"name" validate:"required,min=1,max=255"`
}

// CloneTemplate handles POST /api/v1/pipelines/{id}/clone
func (h *PipelineHandler) CloneTemplate(w http.ResponseWriter, r *http.Request) {
	templateID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())
	userID := middleware.GetUserID(r.Context())

	var req CloneTemplateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	input := pipelinesvc.CloneTemplateInput{
		TenantID:   tenantID,
		TemplateID: templateID,
		NewName:    req.Name,
		ClonedBy:   userID,
	}

	template, err := h.service.CloneTemplate(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(toTemplateResponse(template))
}

// --- Step Handlers ---

// AddStep handles POST /api/v1/pipelines/templates/{id}/steps
func (h *PipelineHandler) AddStep(w http.ResponseWriter, r *http.Request) {
	templateID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())

	var req CreateStepRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	input := pipelinesvc.AddStepInput{
		TenantID:          tenantID,
		TemplateID:        templateID,
		StepKey:           req.StepKey,
		Name:              req.Name,
		Description:       req.Description,
		Order:             req.Order,
		Tool:              req.Tool,
		Capabilities:      req.Capabilities,
		Config:            req.Config,
		TimeoutSeconds:    req.TimeoutSeconds,
		DependsOn:         req.DependsOn,
		Condition:         toCondition(req.Condition),
		MaxRetries:        req.MaxRetries,
		RetryDelaySeconds: req.RetryDelaySeconds,
	}
	if req.UIPosition != nil {
		input.UIPositionX = &req.UIPosition.X
		input.UIPositionY = &req.UIPosition.Y
	}

	step, err := h.service.AddStep(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(toStepResponse(step))
}

// UpdateStepRequest represents the request body for updating a step.
type UpdateStepRequest struct {
	Name              string                 `json:"name" validate:"omitempty,min=1,max=255"`
	Description       string                 `json:"description" validate:"max=1000"`
	Order             int                    `json:"order"`
	UIPosition        *UIPositionRequest     `json:"ui_position"`
	Tool              string                 `json:"tool" validate:"max=100"`
	Capabilities      []string               `json:"capabilities" validate:"max=10,dive,max=50"`
	Config            map[string]interface{} `json:"config"`
	TimeoutSeconds    int                    `json:"timeout_seconds"`
	DependsOn         []string               `json:"depends_on" validate:"max=20,dive,max=50"`
	Condition         *StepConditionRequest  `json:"condition"`
	MaxRetries        int                    `json:"max_retries"`
	RetryDelaySeconds int                    `json:"retry_delay_seconds"`
}

// UpdateStep handles PUT /api/v1/pipelines/templates/{id}/steps/{stepId}
func (h *PipelineHandler) UpdateStep(w http.ResponseWriter, r *http.Request) {
	stepID := chi.URLParam(r, "stepId")
	tenantID := middleware.GetTenantID(r.Context())
	templateID := chi.URLParam(r, "id")

	var req UpdateStepRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	input := pipelinesvc.AddStepInput{
		TenantID:          tenantID,
		TemplateID:        templateID,
		Name:              req.Name,
		Description:       req.Description,
		Order:             req.Order,
		Tool:              req.Tool,
		Capabilities:      req.Capabilities,
		Config:            req.Config,
		TimeoutSeconds:    req.TimeoutSeconds,
		DependsOn:         req.DependsOn,
		Condition:         toCondition(req.Condition),
		MaxRetries:        req.MaxRetries,
		RetryDelaySeconds: req.RetryDelaySeconds,
	}
	if req.UIPosition != nil {
		input.UIPositionX = &req.UIPosition.X
		input.UIPositionY = &req.UIPosition.Y
	}

	step, err := h.service.UpdateStep(r.Context(), stepID, input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toStepResponse(step))
}

// DeleteStep handles DELETE /api/v1/pipelines/templates/{id}/steps/{stepId}
func (h *PipelineHandler) DeleteStep(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())
	templateID := chi.URLParam(r, "id")
	stepID := chi.URLParam(r, "stepId")

	// Security: First verify template belongs to tenant
	_, err := h.service.GetTemplate(r.Context(), tenantID, templateID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	if err := h.service.DeleteStep(r.Context(), tenantID, stepID); err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// --- Run Handlers ---

// TriggerRun handles POST /api/v1/pipelines/runs
func (h *PipelineHandler) TriggerRun(w http.ResponseWriter, r *http.Request) {
	var req TriggerRunRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	tenantID := middleware.GetTenantID(r.Context())
	userID := middleware.GetUserID(r.Context())

	input := pipelinesvc.TriggerPipelineInput{
		TenantID:    tenantID,
		TemplateID:  req.TemplateID,
		AssetID:     req.AssetID,
		TriggerType: req.TriggerType,
		TriggeredBy: userID,
		Context:     req.Context,
	}

	run, err := h.service.TriggerPipeline(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(toRunResponse(run))
}

// GetRun handles GET /api/v1/pipelines/runs/{id}
func (h *PipelineHandler) GetRun(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())
	runID := chi.URLParam(r, "id")

	run, err := h.service.GetRunWithSteps(r.Context(), runID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	// Security: Verify run belongs to tenant
	if run.TenantID.String() != tenantID {
		h.logger.Warn("SECURITY: cross-tenant run access attempt",
			"tenant_id", tenantID,
			"run_tenant_id", run.TenantID.String())
		apierror.NotFound("pipeline run not found").WriteJSON(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toRunResponse(run))
}

// ListRuns handles GET /api/v1/pipelines/runs
func (h *PipelineHandler) ListRuns(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())

	input := pipelinesvc.ListRunsInput{
		TenantID:   tenantID,
		PipelineID: r.URL.Query().Get("pipeline_id"),
		AssetID:    r.URL.Query().Get("asset_id"),
		Status:     r.URL.Query().Get("status"),
		Page:       parseQueryInt(r.URL.Query().Get("page"), 1),
		PerPage:    parseQueryInt(r.URL.Query().Get("per_page"), 20),
	}

	result, err := h.service.ListRuns(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	items := make([]*RunResponse, len(result.Data))
	for i, run := range result.Data {
		items[i] = toRunResponse(run)
	}

	resp := map[string]interface{}{
		"items":       items,
		"total":       result.Total,
		"page":        result.Page,
		"per_page":    result.PerPage,
		"total_pages": result.TotalPages,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// CancelRun handles POST /api/v1/pipelines/runs/{id}/cancel
func (h *PipelineHandler) CancelRun(w http.ResponseWriter, r *http.Request) {
	runID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())

	if err := h.service.CancelRun(r.Context(), tenantID, runID); err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// --- Conversion Helpers ---

func toTriggers(triggers []TriggerRequest) []pipeline.Trigger {
	result := make([]pipeline.Trigger, len(triggers))
	for i, t := range triggers {
		result[i] = pipeline.Trigger{
			Type:     pipeline.TriggerType(t.Type),
			Schedule: t.Schedule,
			Webhook:  t.Webhook,
			Filters:  t.Filters,
		}
	}
	return result
}

func toSettings(settings *PipelineSettingsRequest) *pipeline.Settings {
	if settings == nil {
		return nil
	}
	s := &pipeline.Settings{
		MaxParallelSteps:     settings.MaxParallelSteps,
		FailFast:             settings.FailFast,
		RetryFailedSteps:     settings.RetryFailedSteps,
		TimeoutSeconds:       settings.TimeoutSeconds,
		NotifyOnComplete:     settings.NotifyOnComplete,
		NotifyOnFailure:      settings.NotifyOnFailure,
		NotificationChannels: settings.NotificationChannels,
	}
	if settings.AgentPreference != "" {
		s.AgentPreference = pipeline.AgentPreference(settings.AgentPreference)
	}
	return s
}

func toCondition(cond *StepConditionRequest) *pipeline.Condition {
	if cond == nil {
		return nil
	}
	return &pipeline.Condition{
		Type:  pipeline.ConditionType(cond.Type),
		Value: cond.Value,
	}
}

func toUIPosition(pos *UIPositionRequest) *pipeline.UIPosition {
	if pos == nil {
		return nil
	}
	return &pipeline.UIPosition{
		X: pos.X,
		Y: pos.Y,
	}
}

func toTemplateResponse(t *pipeline.Template) *TemplateResponse {
	triggers := make([]TriggerResponse, len(t.Triggers))
	for i, tr := range t.Triggers {
		triggers[i] = TriggerResponse{
			Type:     string(tr.Type),
			Schedule: tr.Schedule,
			Webhook:  tr.Webhook,
			Filters:  tr.Filters,
		}
	}

	steps := make([]StepResponse, len(t.Steps))
	for i, s := range t.Steps {
		steps[i] = *toStepResponse(s)
	}

	resp := &TemplateResponse{
		ID:               t.ID.String(),
		TenantID:         t.TenantID.String(),
		Name:             t.Name,
		Description:      t.Description,
		Version:          t.Version,
		IsActive:         t.IsActive,
		IsSystemTemplate: t.IsSystemTemplate,
		Triggers:         triggers,
		Settings: PipelineSettingsResponse{
			MaxParallelSteps:     t.Settings.MaxParallelSteps,
			FailFast:             t.Settings.FailFast,
			RetryFailedSteps:     t.Settings.RetryFailedSteps,
			TimeoutSeconds:       t.Settings.TimeoutSeconds,
			NotifyOnComplete:     t.Settings.NotifyOnComplete,
			NotifyOnFailure:      t.Settings.NotifyOnFailure,
			NotificationChannels: t.Settings.NotificationChannels,
			AgentPreference:      string(t.Settings.AgentPreference),
		},
		Tags:      t.Tags,
		Steps:     steps,
		CreatedAt: t.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt: t.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}

	// Add UI positions for visual builder
	if t.UIStartPosition != nil {
		resp.UIStartPosition = &UIPositionResponse{X: t.UIStartPosition.X, Y: t.UIStartPosition.Y}
	}
	if t.UIEndPosition != nil {
		resp.UIEndPosition = &UIPositionResponse{X: t.UIEndPosition.X, Y: t.UIEndPosition.Y}
	}

	return resp
}

func toStepResponse(s *pipeline.Step) *StepResponse {
	resp := &StepResponse{
		ID:          s.ID.String(),
		StepKey:     s.StepKey,
		Name:        s.Name,
		Description: s.Description,
		Order:       s.StepOrder,
		UIPosition: UIPositionResponse{
			X: s.UIPosition.X,
			Y: s.UIPosition.Y,
		},
		Tool:              s.Tool,
		Capabilities:      s.Capabilities,
		Config:            s.Config,
		TimeoutSeconds:    s.TimeoutSeconds,
		DependsOn:         s.DependsOn,
		MaxRetries:        s.MaxRetries,
		RetryDelaySeconds: s.RetryDelaySeconds,
	}

	if s.Condition.Type != "" {
		resp.Condition = &StepConditionResponse{
			Type:  string(s.Condition.Type),
			Value: s.Condition.Value,
		}
	}

	return resp
}

func toRunResponse(r *pipeline.Run) *RunResponse {
	resp := &RunResponse{
		ID:             r.ID.String(),
		TenantID:       r.TenantID.String(),
		PipelineID:     r.PipelineID.String(),
		TriggerType:    string(r.TriggerType),
		TriggeredBy:    r.TriggeredBy,
		Status:         string(r.Status),
		TotalSteps:     r.TotalSteps,
		CompletedSteps: r.CompletedSteps,
		FailedSteps:    r.FailedSteps,
		SkippedSteps:   r.SkippedSteps,
		TotalFindings:  r.TotalFindings,
		ErrorMessage:   r.ErrorMessage,
		CreatedAt:      r.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}

	if r.AssetID != nil {
		aid := r.AssetID.String()
		resp.AssetID = &aid
	}

	if r.ScanID != nil {
		sid := r.ScanID.String()
		resp.ScanID = &sid
	}

	if r.ScanProfileID != nil {
		spid := r.ScanProfileID.String()
		resp.ScanProfileID = &spid
	}

	if r.QualityGateResult != nil {
		resp.QualityGateResult = r.QualityGateResult
	}

	if r.StartedAt != nil {
		ts := r.StartedAt.Format("2006-01-02T15:04:05Z07:00")
		resp.StartedAt = &ts
	}

	if r.CompletedAt != nil {
		ts := r.CompletedAt.Format("2006-01-02T15:04:05Z07:00")
		resp.CompletedAt = &ts
	}

	if len(r.StepRuns) > 0 {
		resp.StepRuns = make([]StepRunResponse, len(r.StepRuns))
		for i, sr := range r.StepRuns {
			resp.StepRuns[i] = toStepRunResponse(sr)
		}
	}

	// Extract filtering result from context if present
	if r.Context != nil {
		if filteringResult, ok := r.Context["filtering_result"]; ok {
			resp.FilteringResult = toFilteringResultResponse(filteringResult)
		}
	}

	return resp
}

// toFilteringResultResponse converts filtering result from context to response type.
func toFilteringResultResponse(result any) *FilteringResultResponse {
	if result == nil {
		return nil
	}

	// Type assertion - FilteringResult may come from scan package
	// We handle both map[string]any (from JSON) and direct struct
	switch v := result.(type) {
	case map[string]any:
		resp := &FilteringResultResponse{}
		if total, ok := v["total_assets"].(int); ok {
			resp.TotalAssets = total
		}
		if scanned, ok := v["scanned_assets"].(int); ok {
			resp.ScannedAssets = scanned
		}
		if skipped, ok := v["skipped_assets"].(int); ok {
			resp.SkippedAssets = skipped
		}
		if unclassified, ok := v["unclassified_assets"].(int); ok {
			resp.UnclassifiedAssets = unclassified
		}
		if pct, ok := v["compatibility_percent"].(float64); ok {
			resp.CompatibilityPercent = pct
		}
		if filtered, ok := v["was_filtered"].(bool); ok {
			resp.WasFiltered = filtered
		}
		if toolName, ok := v["tool_name"].(string); ok {
			resp.ToolName = toolName
		}
		if targets, ok := v["supported_targets"].([]string); ok {
			resp.SupportedTargets = targets
		}
		if scannedByType, ok := v["scanned_by_type"].(map[string]int); ok {
			resp.ScannedByType = scannedByType
		}
		if skippedByType, ok := v["skipped_by_type"].(map[string]int); ok {
			resp.SkippedByType = skippedByType
		}
		return resp

	default:
		// Try to access fields directly if it's a struct with exported fields
		// This handles the case where FilteringResult struct is passed directly
		return toFilteringResultFromStruct(v)
	}
}

// toFilteringResultFromStruct converts a struct to FilteringResultResponse.
func toFilteringResultFromStruct(v any) *FilteringResultResponse {
	if v == nil {
		return nil
	}

	// Handle the actual FilteringResult type from scan service
	if fr, ok := v.(*scansvc.FilteringResult); ok && fr != nil {
		resp := &FilteringResultResponse{
			TotalAssets:          fr.TotalAssets,
			ScannedAssets:        fr.ScannedAssets,
			SkippedAssets:        fr.SkippedAssets,
			UnclassifiedAssets:   fr.UnclassifiedAssets,
			CompatibilityPercent: fr.CompatibilityPercent,
			ScannedByType:        fr.ScannedByType,
			SkippedByType:        fr.SkippedByType,
			WasFiltered:          fr.WasFiltered,
			ToolName:             fr.ToolName,
			SupportedTargets:     fr.SupportedTargets,
		}

		// Convert skip reasons
		if len(fr.SkipReasons) > 0 {
			resp.SkipReasons = make([]SkipReasonResponse, len(fr.SkipReasons))
			for i, sr := range fr.SkipReasons {
				resp.SkipReasons[i] = SkipReasonResponse{
					AssetType: sr.AssetType,
					Count:     sr.Count,
					Reason:    sr.Reason,
				}
			}
		}

		return resp
	}

	// Return nil for unhandled types
	return nil
}

func toStepRunResponse(sr *pipeline.StepRun) StepRunResponse {
	resp := StepRunResponse{
		ID:            sr.ID.String(),
		StepID:        sr.StepID.String(),
		StepKey:       sr.StepKey,
		Status:        string(sr.Status),
		ErrorMessage:  sr.ErrorMessage,
		ErrorCode:     sr.ErrorCode,
		Attempt:       sr.Attempt,
		MaxAttempts:   sr.MaxAttempts,
		FindingsCount: sr.FindingsCount,
	}

	if sr.StartedAt != nil {
		ts := sr.StartedAt.Format("2006-01-02T15:04:05Z07:00")
		resp.StartedAt = &ts
	}

	if sr.CompletedAt != nil {
		ts := sr.CompletedAt.Format("2006-01-02T15:04:05Z07:00")
		resp.CompletedAt = &ts
	}

	return resp
}

// handleValidationError converts validation errors to API errors.
func (h *PipelineHandler) handleValidationError(w http.ResponseWriter, err error) {
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
func (h *PipelineHandler) handleServiceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Pipeline").WriteJSON(w)
	case errors.Is(err, shared.ErrAlreadyExists):
		apierror.Conflict("Pipeline already exists").WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(err.Error()).WriteJSON(w)
	case errors.Is(err, shared.ErrUnauthorized):
		apierror.Unauthorized("").WriteJSON(w)
	case errors.Is(err, shared.ErrForbidden):
		apierror.Forbidden("").WriteJSON(w)
	default:
		h.logger.Error("service error", "error", err)
		apierror.InternalError(err).WriteJSON(w)
	}
}

// handleStepError converts step-related service errors to API errors.
func (h *PipelineHandler) handleStepError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Step").WriteJSON(w)
	case errors.Is(err, shared.ErrAlreadyExists):
		apierror.Conflict("Step with this key already exists in the pipeline").WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(err.Error()).WriteJSON(w)
	case errors.Is(err, shared.ErrUnauthorized):
		apierror.Unauthorized("").WriteJSON(w)
	case errors.Is(err, shared.ErrForbidden):
		apierror.Forbidden("").WriteJSON(w)
	default:
		h.logger.Error("step service error", "error", err)
		apierror.InternalError(err).WriteJSON(w)
	}
}
