package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/api/internal/app"
	pipelinesvc "github.com/openctemio/api/internal/app/pipeline"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/domain/command"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/validator"
)

// CommandHandler handles command-related HTTP requests.
type CommandHandler struct {
	service         *app.CommandService
	pipelineService *pipelinesvc.Service
	validator       *validator.Validator
	logger          *logger.Logger
}

// NewCommandHandler creates a new command handler.
func NewCommandHandler(svc *app.CommandService, v *validator.Validator, log *logger.Logger) *CommandHandler {
	return &CommandHandler{
		service:   svc,
		validator: v,
		logger:    log,
	}
}

// SetPipelineService sets the pipeline service for triggering pipeline progression.
func (h *CommandHandler) SetPipelineService(svc *pipelinesvc.Service) {
	h.pipelineService = svc
}

// CommandResponse represents a command in API responses.
type CommandResponse struct {
	ID             string          `json:"id"`
	TenantID       string          `json:"tenant_id,omitempty"`
	AgentID        string          `json:"agent_id,omitempty"`
	Type           string          `json:"type"`
	Priority       string          `json:"priority"`
	Payload        json.RawMessage `json:"payload,omitempty"`
	Status         string          `json:"status"`
	ErrorMessage   string          `json:"error_message,omitempty"`
	CreatedAt      time.Time       `json:"created_at"`
	ExpiresAt      *time.Time      `json:"expires_at,omitempty"`
	AcknowledgedAt *time.Time      `json:"acknowledged_at,omitempty"`
	StartedAt      *time.Time      `json:"started_at,omitempty"`
	CompletedAt    *time.Time      `json:"completed_at,omitempty"`
	Result         json.RawMessage `json:"result,omitempty"`
}

// toCommandResponse converts a domain command to API response.
func toCommandResponse(c *command.Command) CommandResponse {
	resp := CommandResponse{
		ID:             c.ID.String(),
		TenantID:       c.TenantID.String(),
		Type:           string(c.Type),
		Priority:       string(c.Priority),
		Payload:        c.Payload,
		Status:         string(c.Status),
		ErrorMessage:   c.ErrorMessage,
		CreatedAt:      c.CreatedAt,
		ExpiresAt:      c.ExpiresAt,
		AcknowledgedAt: c.AcknowledgedAt,
		StartedAt:      c.StartedAt,
		CompletedAt:    c.CompletedAt,
		Result:         c.Result,
	}

	if c.AgentID != nil {
		resp.AgentID = c.AgentID.String()
	}

	return resp
}

// CreateCommandRequest represents the request to create a command.
type CreateCommandRequest struct {
	AgentID   string          `json:"agent_id" validate:"omitempty,uuid"`
	Type      string          `json:"type" validate:"required,oneof=scan collect health_check config_update cancel"`
	Priority  string          `json:"priority" validate:"omitempty,oneof=low normal high critical"`
	Payload   json.RawMessage `json:"payload,omitempty"`
	ExpiresIn int             `json:"expires_in,omitempty"` // Seconds until expiration
}

// UpdateCommandStatusRequest represents the request to update command status.
type UpdateCommandStatusRequest struct {
	Result       json.RawMessage `json:"result,omitempty"`
	ErrorMessage string          `json:"error_message,omitempty"`
}

// Create handles POST /api/v1/commands
// @Summary      Create command
// @Description  Create a new command to be executed by an agent
// @Tags         Commands
// @Accept       json
// @Produce      json
// @Param        body  body      CreateCommandRequest  true  "Command data"
// @Success      201   {object}  CommandResponse
// @Failure      400   {object}  apierror.Error
// @Failure      500   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /commands [post]
func (h *CommandHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req CreateCommandRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	tenantID := middleware.GetTenantID(r.Context())

	cmd, err := h.service.CreateCommand(r.Context(), app.CreateCommandInput{
		TenantID:  tenantID,
		AgentID:   req.AgentID,
		Type:      req.Type,
		Priority:  req.Priority,
		Payload:   req.Payload,
		ExpiresIn: req.ExpiresIn,
	})
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(toCommandResponse(cmd))
}

// Get handles GET /api/v1/commands/{id}
// @Summary      Get command
// @Description  Get a single command by ID
// @Tags         Commands
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "Command ID"
// @Success      200  {object}  CommandResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /commands/{id} [get]
func (h *CommandHandler) Get(w http.ResponseWriter, r *http.Request) {
	commandID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())

	cmd, err := h.service.GetCommand(r.Context(), tenantID, commandID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toCommandResponse(cmd))
}

// List handles GET /api/v1/commands
// @Summary      List commands
// @Description  Get a paginated list of commands
// @Tags         Commands
// @Accept       json
// @Produce      json
// @Param        agent_id   query     string  false  "Filter by agent ID"
// @Param        type       query     string  false  "Filter by type (scan, collect, health_check, config_update, cancel)"
// @Param        status     query     string  false  "Filter by status (pending, running, completed, failed, canceled)"
// @Param        priority   query     string  false  "Filter by priority (low, normal, high, critical)"
// @Param        page       query     int     false  "Page number" default(1)
// @Param        per_page   query     int     false  "Items per page" default(20)
// @Success      200  {object}  ListResponse[CommandResponse]
// @Failure      400  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /commands [get]
func (h *CommandHandler) List(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())

	input := app.ListCommandsInput{
		TenantID: tenantID,
		AgentID:  r.URL.Query().Get("agent_id"),
		Type:     r.URL.Query().Get("type"),
		Status:   r.URL.Query().Get("status"),
		Priority: r.URL.Query().Get("priority"),
		Page:     parseQueryInt(r.URL.Query().Get("page"), 1),
		PerPage:  parseQueryInt(r.URL.Query().Get("per_page"), 20),
	}

	result, err := h.service.ListCommands(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	commands := make([]CommandResponse, len(result.Data))
	for i, c := range result.Data {
		commands[i] = toCommandResponse(c)
	}

	resp := ListResponse[CommandResponse]{
		Data:       commands,
		Total:      result.Total,
		Page:       result.Page,
		PerPage:    result.PerPage,
		TotalPages: result.TotalPages,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// Poll handles GET /api/v1/agent/commands - agent polling endpoint
// @Summary      Poll commands
// @Description  Agent polls for pending commands to execute
// @Tags         Agent
// @Accept       json
// @Produce      json
// @Param        limit  query     int  false  "Max commands to return" default(10)
// @Success      200  {array}   CommandResponse
// @Failure      401  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     ApiKeyAuth
// @Router       /agent/commands [get]
func (h *CommandHandler) Poll(w http.ResponseWriter, r *http.Request) {
	agt := AgentFromContext(r.Context())
	if agt == nil {
		apierror.Unauthorized("Agent not authenticated").WriteJSON(w)
		return
	}

	limit := parseQueryInt(r.URL.Query().Get("limit"), 10)

	commands, err := h.service.PollCommands(r.Context(), app.PollCommandsInput{
		TenantID: agt.TenantID.String(),
		AgentID:  agt.ID.String(),
		Limit:    limit,
	})
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	resp := make([]CommandResponse, len(commands))
	for i, c := range commands {
		resp[i] = toCommandResponse(c)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// Acknowledge handles POST /api/v1/agent/commands/{id}/acknowledge
// @Summary      Acknowledge command
// @Description  Agent acknowledges receipt of a command
// @Tags         Agent
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "Command ID"
// @Success      200  {object}  CommandResponse
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Security     ApiKeyAuth
// @Router       /agent/commands/{id}/acknowledge [post]
func (h *CommandHandler) Acknowledge(w http.ResponseWriter, r *http.Request) {
	agt := AgentFromContext(r.Context())
	if agt == nil {
		apierror.Unauthorized("Agent not authenticated").WriteJSON(w)
		return
	}

	commandID := chi.URLParam(r, "id")

	cmd, err := h.service.AcknowledgeCommand(r.Context(), agt.TenantID.String(), commandID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toCommandResponse(cmd))
}

// Start handles POST /api/v1/agent/commands/{id}/start
// @Summary      Start command
// @Description  Agent reports that command execution has started
// @Tags         Agent
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "Command ID"
// @Success      200  {object}  CommandResponse
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Security     ApiKeyAuth
// @Router       /agent/commands/{id}/start [post]
func (h *CommandHandler) Start(w http.ResponseWriter, r *http.Request) {
	agt := AgentFromContext(r.Context())
	if agt == nil {
		apierror.Unauthorized("Agent not authenticated").WriteJSON(w)
		return
	}

	commandID := chi.URLParam(r, "id")

	cmd, err := h.service.StartCommand(r.Context(), agt.TenantID.String(), commandID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toCommandResponse(cmd))
}

// Complete handles POST /api/v1/agent/commands/{id}/complete
// @Summary      Complete command
// @Description  Agent reports successful command completion with optional result
// @Tags         Agent
// @Accept       json
// @Produce      json
// @Param        id    path      string                      true  "Command ID"
// @Param        body  body      UpdateCommandStatusRequest  false "Completion result"
// @Success      200   {object}  CommandResponse
// @Failure      400   {object}  apierror.Error
// @Failure      401   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Security     ApiKeyAuth
// @Router       /agent/commands/{id}/complete [post]
func (h *CommandHandler) Complete(w http.ResponseWriter, r *http.Request) {
	agt := AgentFromContext(r.Context())
	if agt == nil {
		apierror.Unauthorized("Agent not authenticated").WriteJSON(w)
		return
	}

	commandID := chi.URLParam(r, "id")

	var req UpdateCommandStatusRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// Empty body is ok for completion
		req = UpdateCommandStatusRequest{}
	}

	cmd, err := h.service.CompleteCommand(r.Context(), app.CompleteCommandInput{
		TenantID:  agt.TenantID.String(),
		CommandID: commandID,
		Result:    req.Result,
	})
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	// Trigger pipeline progression if this command is part of a pipeline
	h.triggerPipelineProgression(r.Context(), cmd)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toCommandResponse(cmd))
}

// triggerPipelineProgression triggers pipeline progression when a command completes.
// It extracts pipeline info from the command payload and calls OnStepCompleted.
func (h *CommandHandler) triggerPipelineProgression(ctx context.Context, cmd *command.Command) {
	if h.pipelineService == nil {
		return
	}

	// Parse command payload to get pipeline info
	var payload struct {
		PipelineRunID string `json:"pipeline_run_id"`
		StepRunID     string `json:"step_run_id"`
		StepKey       string `json:"step_key"`
	}

	if err := json.Unmarshal(cmd.Payload, &payload); err != nil {
		return // Not a pipeline command
	}

	if payload.PipelineRunID == "" || payload.StepKey == "" {
		return // Not a pipeline command
	}

	// Parse result to get findings count and output
	var result struct {
		FindingsCount int            `json:"findings_count"`
		Output        map[string]any `json:"output"`
	}

	if cmd.Result != nil {
		_ = json.Unmarshal(cmd.Result, &result)
	}

	// Trigger pipeline progression asynchronously with independent context
	// Use background context since the HTTP request context will be canceled after response
	go func() {
		bgCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := h.pipelineService.OnStepCompleted(bgCtx, payload.PipelineRunID, payload.StepKey, result.FindingsCount, result.Output); err != nil {
			h.logger.Error("failed to trigger pipeline progression",
				"pipeline_run_id", payload.PipelineRunID,
				"step_key", payload.StepKey,
				"error", err,
			)
		}
	}()
}

// Fail handles POST /api/v1/agent/commands/{id}/fail
// @Summary      Fail command
// @Description  Agent reports command execution failure with error message
// @Tags         Agent
// @Accept       json
// @Produce      json
// @Param        id    path      string                      true  "Command ID"
// @Param        body  body      UpdateCommandStatusRequest  false "Error details"
// @Success      200   {object}  CommandResponse
// @Failure      400   {object}  apierror.Error
// @Failure      401   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Security     ApiKeyAuth
// @Router       /agent/commands/{id}/fail [post]
func (h *CommandHandler) Fail(w http.ResponseWriter, r *http.Request) {
	agt := AgentFromContext(r.Context())
	if agt == nil {
		apierror.Unauthorized("Agent not authenticated").WriteJSON(w)
		return
	}

	commandID := chi.URLParam(r, "id")

	var req UpdateCommandStatusRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		req = UpdateCommandStatusRequest{ErrorMessage: "Unknown error"}
	}

	cmd, err := h.service.FailCommand(r.Context(), app.FailCommandInput{
		TenantID:     agt.TenantID.String(),
		CommandID:    commandID,
		ErrorMessage: req.ErrorMessage,
	})
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	// Trigger pipeline failure if this command is part of a pipeline
	h.triggerPipelineFailed(r.Context(), cmd, req.ErrorMessage)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toCommandResponse(cmd))
}

// triggerPipelineFailed triggers pipeline failure when a command fails.
func (h *CommandHandler) triggerPipelineFailed(ctx context.Context, cmd *command.Command, errorMessage string) {
	if h.pipelineService == nil {
		return
	}

	// Parse command payload to get pipeline info
	var payload struct {
		PipelineRunID string `json:"pipeline_run_id"`
		StepKey       string `json:"step_key"`
	}

	if err := json.Unmarshal(cmd.Payload, &payload); err != nil {
		return // Not a pipeline command
	}

	if payload.PipelineRunID == "" || payload.StepKey == "" {
		return // Not a pipeline command
	}

	// Trigger pipeline failure asynchronously with independent context
	go func() {
		bgCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := h.pipelineService.OnStepFailed(bgCtx, payload.PipelineRunID, payload.StepKey, errorMessage, "COMMAND_FAILED"); err != nil {
			h.logger.Error("failed to trigger pipeline failure",
				"pipeline_run_id", payload.PipelineRunID,
				"step_key", payload.StepKey,
				"error", err,
			)
		}
	}()
}

// Cancel handles POST /api/v1/commands/{id}/cancel - admin endpoint
// @Summary      Cancel command
// @Description  Cancel a pending or running command
// @Tags         Commands
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "Command ID"
// @Success      200  {object}  CommandResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /commands/{id}/cancel [post]
func (h *CommandHandler) Cancel(w http.ResponseWriter, r *http.Request) {
	commandID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())

	cmd, err := h.service.CancelCommand(r.Context(), tenantID, commandID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toCommandResponse(cmd))
}

// Delete handles DELETE /api/v1/commands/{id}
// @Summary      Delete command
// @Description  Delete a command
// @Tags         Commands
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "Command ID"
// @Success      204  "No Content"
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /commands/{id} [delete]
func (h *CommandHandler) Delete(w http.ResponseWriter, r *http.Request) {
	commandID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())

	if err := h.service.DeleteCommand(r.Context(), tenantID, commandID); err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleValidationError converts validation errors to API errors.
func (h *CommandHandler) handleValidationError(w http.ResponseWriter, err error) {
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
func (h *CommandHandler) handleServiceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Command").WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(err.Error()).WriteJSON(w)
	default:
		h.logger.Error("service error", "error", err)
		apierror.InternalError(err).WriteJSON(w)
	}
}
