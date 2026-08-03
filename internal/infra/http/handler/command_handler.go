package handler

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/openctemio/api/internal/app/command"

	"github.com/go-chi/chi/v5"

	pipelinesvc "github.com/openctemio/api/internal/app/pipeline"
	"github.com/openctemio/api/internal/app/template"
	"github.com/openctemio/api/internal/app/validation"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/apierror"
	commanddom "github.com/openctemio/api/pkg/domain/command"
	pipelinedom "github.com/openctemio/api/pkg/domain/pipeline"
	"github.com/openctemio/api/pkg/domain/scannertemplate"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/validator"
)

// validationEvidenceIngester records a completed validation job's outcome as
// finding evidence. Implemented by *validation.EvidenceIngestService.
type validationEvidenceIngester interface {
	Ingest(ctx context.Context, tenantID, findingID shared.ID, simRunID *shared.ID, ev validation.Evidence) (validation.IngestResult, error)
}

// simulationRunFinalizer finalizes an attack-simulation run from a completed
// safe-check command's outcome (RFC-012 Phase 1b). Implemented by
// *compliance.SimulationService.
type simulationRunFinalizer interface {
	FinalizeRun(ctx context.Context, tenantID, runID shared.ID, outcome, summary string) error
}

// CommandHandler handles command-related HTTP requests.
type CommandHandler struct {
	service          *command.Service
	pipelineService  *pipelinesvc.Service
	validationIngest validationEvidenceIngester
	simFinalizer     simulationRunFinalizer
	validator        *validator.Validator
	logger           *logger.Logger
}

// NewCommandHandler creates a new command handler.
func NewCommandHandler(svc *command.Service, v *validator.Validator, log *logger.Logger) *CommandHandler {
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

// SetValidationIngest wires the validation evidence ingester used to map a
// completed validate command's result into finding evidence.
func (h *CommandHandler) SetValidationIngest(svc validationEvidenceIngester) {
	h.validationIngest = svc
}

// SetSimulationFinalizer wires the simulation-run finalizer used to complete a
// running attack-simulation from a validate command's safe-check outcome.
func (h *CommandHandler) SetSimulationFinalizer(svc simulationRunFinalizer) {
	h.simFinalizer = svc
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
func toCommandResponse(c *commanddom.Command) CommandResponse {
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

	// A "scan" command may embed custom scanner-template content that the agent
	// writes to disk and executes. The agent only validates template name/size,
	// NOT content, so a CommandsWrite user could smuggle a malicious template
	// (nuclei code:/javascript:/exec, ReDoS matchers) that bypasses the
	// validator applied when templates are stored/synced. Enforce the same
	// authoritative server-side validation on any inline template here.
	if req.Type == "scan" {
		if err := validateInlineScanTemplates(req.Payload); err != nil {
			apierror.BadRequest(err.Error()).WriteJSON(w)
			return
		}
	}

	tenantID := middleware.GetTenantID(r.Context())

	cmd, err := h.service.Create(r.Context(), command.CreateInput{
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

// validateInlineScanTemplates rejects a scan command that embeds custom scanner
// templates with dangerous content. Inline templates travel in the command
// payload as `custom_templates: [{name, template_type, content(base64)}]`; the
// agent decodes and executes them but only checks name/size, so the content
// must pass the same authoritative validator (NucleiValidator etc.) applied at
// template store/sync time.
func validateInlineScanTemplates(payload json.RawMessage) error {
	if len(payload) == 0 {
		return nil
	}
	var p struct {
		CustomTemplates []struct {
			Name         string `json:"name"`
			TemplateType string `json:"template_type"`
			Content      string `json:"content"` // base64-encoded
		} `json:"custom_templates"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		// Unparseable against this shape. If the payload does not mention
		// custom_templates at all, this validator has nothing to say and the
		// shape is handled downstream — that is the ordinary case for every
		// non-template command.
		//
		// If it DOES mention them, refusing is the only safe answer: we cannot
		// see what we would be approving, and the agent decodes and executes
		// whatever it can parse. Passing here on the assumption that the agent's
		// parser is exactly as strict as this one is a parser-differential bet,
		// and this function exists precisely to stop templates reaching an agent
		// unvalidated.
		if bytes.Contains(payload, []byte(`"custom_templates"`)) {
			return fmt.Errorf("payload embeds custom_templates but could not be parsed for validation")
		}
		return nil //nolint:nilerr // nothing to validate; see above
	}
	for i, t := range p.CustomTemplates {
		name := t.Name
		if name == "" {
			name = fmt.Sprintf("#%d", i)
		}
		// Content is base64 (matches how the server embeds and the agent decodes
		// templates). Validate the decoded bytes; if it isn't valid base64, fall
		// back to validating the raw bytes so nothing slips past.
		content := []byte(t.Content)
		if decoded, derr := base64.StdEncoding.DecodeString(t.Content); derr == nil {
			content = decoded
		}
		res := template.ValidateTemplate(scannertemplate.TemplateType(t.TemplateType), content)
		if res == nil || !res.Valid || res.HasErrors() {
			msg := "failed server-side template validation"
			if res != nil && res.HasErrors() {
				msg = res.ErrorMessages()
			}
			return fmt.Errorf("custom template %q rejected: %s", name, msg)
		}
	}
	return nil
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

	cmd, err := h.service.Get(r.Context(), tenantID, commandID)
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

	input := command.ListInput{
		TenantID: tenantID,
		AgentID:  r.URL.Query().Get("agent_id"),
		Type:     r.URL.Query().Get("type"),
		Status:   r.URL.Query().Get("status"),
		Priority: r.URL.Query().Get("priority"),
		Page:     parseQueryInt(r.URL.Query().Get("page"), 1),
		PerPage:  parseQueryIntBounded(r.URL.Query().Get("per_page"), 20, 1, MaxPerPage),
	}

	result, err := h.service.List(r.Context(), input)
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
	if !requireAgentTenant(w, agt) {
		return
	}

	limit := parseQueryInt(r.URL.Query().Get("limit"), 10)

	commands, err := h.service.Poll(r.Context(), command.PollInput{
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
	if !requireAgentTenant(w, agt) {
		return
	}

	commandID := chi.URLParam(r, "id")

	cmd, err := h.service.Acknowledge(r.Context(), agt.TenantID.String(), agt.ID.String(), commandID)
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
	if !requireAgentTenant(w, agt) {
		return
	}

	commandID := chi.URLParam(r, "id")

	cmd, err := h.service.Start(r.Context(), agt.TenantID.String(), agt.ID.String(), commandID)
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
	if !requireAgentTenant(w, agt) {
		return
	}

	commandID := chi.URLParam(r, "id")

	var req UpdateCommandStatusRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// Empty body is ok for completion
		req = UpdateCommandStatusRequest{}
	}

	cmd, err := h.service.Complete(r.Context(), command.CompleteInput{
		TenantID:  agt.TenantID.String(),
		AgentID:   agt.ID.String(),
		CommandID: commandID,
		Result:    req.Result,
	})
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	// Trigger pipeline progression if this command is part of a pipeline
	h.triggerPipelineProgression(r.Context(), cmd)

	// Map a completed validation job's result into finding evidence.
	h.triggerValidationEvidence(cmd)

	// Finalize a running attack-simulation from a completed safe-check (RFC-012).
	h.triggerSimulationFinalize(cmd)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toCommandResponse(cmd))
}

// triggerSimulationFinalize finalizes a running attack-simulation run when the
// completed validate command carries a simulation_run_id (RFC-012 Phase 1b).
// The tenant is taken from the command (authoritative). Best-effort and
// asynchronous; leaves the finding-evidence path (triggerValidationEvidence)
// entirely untouched.
func (h *CommandHandler) triggerSimulationFinalize(cmd *commanddom.Command) {
	if h.simFinalizer == nil || cmd == nil || cmd.Type != commanddom.CommandTypeValidate {
		return
	}

	var payload validation.ValidateCommandPayload
	if err := json.Unmarshal(cmd.Payload, &payload); err != nil || payload.SimulationRunID == "" {
		return
	}
	runID, err := shared.IDFromString(payload.SimulationRunID)
	if err != nil {
		return
	}

	// Extract the verdict (top-level or nested under metadata — the SDK poller
	// path), mirroring triggerValidationEvidence.
	var result struct {
		validation.ValidateResultPayload
		Metadata validation.ValidateResultPayload `json:"metadata"`
	}
	if cmd.Result != nil {
		_ = json.Unmarshal(cmd.Result, &result)
	}
	verdict := result.ValidateResultPayload
	if verdict.Outcome == "" {
		verdict = result.Metadata
	}
	if verdict.Outcome == "" {
		h.logger.Warn("validate command for simulation completed without an outcome",
			"command_id", cmd.ID.String(), "simulation_run_id", payload.SimulationRunID)
		return
	}

	tenantID := cmd.TenantID
	go func() {
		bgCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := h.simFinalizer.FinalizeRun(bgCtx, tenantID, runID, verdict.Outcome, verdict.Summary); err != nil {
			h.logger.Error("failed to finalize simulation run from safe-check",
				"command_id", cmd.ID.String(), "simulation_run_id", payload.SimulationRunID, "error", err)
		}
	}()
}

// triggerValidationEvidence maps a completed CommandTypeValidate command's
// result into finding evidence via the ingest service. The tenant is taken
// from the command itself (authoritative), never from the reporting agent.
// Best-effort and asynchronous — a mapping failure never blocks the agent's
// completion response.
func (h *CommandHandler) triggerValidationEvidence(cmd *commanddom.Command) {
	if h.validationIngest == nil || cmd == nil || cmd.Type != commanddom.CommandTypeValidate {
		return
	}

	var payload validation.ValidateCommandPayload
	if err := json.Unmarshal(cmd.Payload, &payload); err != nil || payload.FindingID == "" {
		return
	}
	findingID, err := shared.IDFromString(payload.FindingID)
	if err != nil {
		return
	}

	// The result may carry the verdict at the top level (a client completing the
	// command directly) OR nested under `metadata` — which is where the SDK
	// command poller places an executor's CommandExecutionResult.Metadata (the
	// real agent path). Accept both.
	var result struct {
		validation.ValidateResultPayload
		Metadata validation.ValidateResultPayload `json:"metadata"`
	}
	if cmd.Result != nil {
		_ = json.Unmarshal(cmd.Result, &result)
	}
	verdict := result.ValidateResultPayload
	if verdict.Outcome == "" {
		verdict = result.Metadata
	}
	if verdict.Outcome == "" {
		// No outcome reported — nothing to reconcile (the run failed to produce
		// a verdict). Leave the finding untouched.
		h.logger.Warn("validate command completed without an outcome",
			"command_id", cmd.ID.String(), "finding_id", payload.FindingID)
		return
	}

	ev := validation.Evidence{
		ExecutorKind: payload.ExecutorKind,
		Technique:    validation.TechniqueID(payload.Technique),
		Target: validation.Target{
			// AssetID was previously dropped here. The detection
			// correlator needs it to scope a telemetry window to the
			// asset that was probed, so carry it through. Parse
			// failures leave it zero, which the correlator treats as
			// "cannot scope" (not_evaluated) rather than guessing.
			AssetID: parseOptionalID(payload.Target.AssetID),
			Type:    payload.Target.Type,
			Address: payload.Target.Address,
		},
		StartedAt: cmd.CreatedAt,
		EndedAt:   time.Now(),
		Outcome:   validation.Outcome(verdict.Outcome),
		Summary:   verdict.Summary,
		RawMeta:   verdict.Evidence,
		// The command id IS the correlation key — it is the identifier a
		// telemetry producer can be told to stamp on events it emits
		// while reacting to this job. See validation/detection.go.
		CorrelationID: cmd.ID,
	}
	tenantID := cmd.TenantID

	go func() {
		bgCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if _, err := h.validationIngest.Ingest(bgCtx, tenantID, findingID, nil, ev); err != nil {
			h.logger.Error("failed to record validation evidence",
				"command_id", cmd.ID.String(),
				"finding_id", payload.FindingID,
				"error", err,
			)
		}
	}()
}

// parseOptionalID parses an id that is legitimately allowed to be absent
// or malformed, returning the zero ID in those cases. Used for payload
// fields where a missing id degrades a feature rather than failing the
// request.
func parseOptionalID(s string) shared.ID {
	if s == "" {
		return shared.ID{}
	}
	id, err := shared.IDFromString(s)
	if err != nil {
		return shared.ID{}
	}
	return id
}

// triggerPipelineProgression triggers pipeline progression when a command completes.
// It extracts pipeline info from the command payload and calls OnStepCompleted.
func (h *CommandHandler) triggerPipelineProgression(ctx context.Context, cmd *commanddom.Command) {
	if h.pipelineService == nil {
		return
	}

	// Parse command payload to get pipeline info. The shape is shared with the
	// dispatcher so the two cannot drift apart again — see
	// pipeline.StepCommandPayload.
	var payload pipelinedom.StepCommandPayload

	if err := json.Unmarshal(cmd.Payload, &payload); err != nil {
		return // Not a pipeline command
	}

	if !payload.IsRoutable() {
		// A command that carries no run/step cannot be reported back. This is
		// legitimate for non-pipeline commands, but it also silently swallowed
		// every scan command for as long as the dispatcher wrote the wrong key,
		// so say so at debug level rather than vanishing.
		h.logger.Debug("command carries no pipeline routing keys; not progressing",
			"command_id", cmd.ID.String())
		return
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
	if !requireAgentTenant(w, agt) {
		return
	}

	commandID := chi.URLParam(r, "id")

	var req UpdateCommandStatusRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		req = UpdateCommandStatusRequest{ErrorMessage: "Unknown error"}
	}

	cmd, err := h.service.Fail(r.Context(), command.FailInput{
		TenantID:     agt.TenantID.String(),
		AgentID:      agt.ID.String(),
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
func (h *CommandHandler) triggerPipelineFailed(ctx context.Context, cmd *commanddom.Command, errorMessage string) {
	if h.pipelineService == nil {
		return
	}

	// Parse command payload to get pipeline info. Same shared shape as the
	// success path — a failure that cannot be routed loses the scanner's real
	// error message, which is how "scanner not found: nuclei" reached users as
	// "scan exceeded configured timeout".
	var payload pipelinedom.StepCommandPayload

	if err := json.Unmarshal(cmd.Payload, &payload); err != nil {
		return // Not a pipeline command
	}

	if !payload.IsRoutable() {
		h.logger.Debug("failed command carries no pipeline routing keys; error will not reach the run",
			"command_id", cmd.ID.String(), "error", errorMessage)
		return
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
