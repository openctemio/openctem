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

	"github.com/openctemio/openctem/api/internal/app/scanrun"
	scanrundom "github.com/openctemio/openctem/api/pkg/domain/scanrun"

	auditsvc "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/command"
	"github.com/openctemio/openctem/api/internal/app/commandlog"
	"github.com/openctemio/openctem/api/internal/app/ingest"
	scanapp "github.com/openctemio/openctem/api/internal/app/scan"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/app/template"
	"github.com/openctemio/openctem/api/internal/app/validation"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scannertemplate"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
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

// scanCommandGate checks the targets of a user-issued scan command the way a
// scan trigger does (exclusions, zones, private-range policy). Implemented by
// *scan.Service.
type scanCommandGate interface {
	GateCommandPayload(ctx context.Context, tenantID shared.ID, sensorID *shared.ID, payload json.RawMessage) (*scanapp.GatedCommand, error)
}

// CommandHandler handles command-related HTTP requests.
type CommandHandler struct {
	service          *command.Service
	scanGate         scanCommandGate
	audit            *auditsvc.AuditService
	scanRunService   *scanrun.Service
	validationIngest validationEvidenceIngester
	retestEvidence   retestEvidenceRecorder
	retestSettler    retestSettler
	simFinalizer     simulationRunFinalizer
	validationRuns   validationRunSettler
	coverage         commandCoverageEvaluator
	validator        *validator.Validator
	logger           *logger.Logger
	// logs keeps the per-task logs sensors send (nil: the logs resource is
	// not served and FeatureLogs is not advertised).
	logs *commandlog.Service
	// findingScope checks the finding a command is about against the
	// caller's data scope (GET /commands/{id}/logs).
	findingScope findingScope
}

// SetCommandLogs serves POST /api/v2/sensor/commands/{id}/logs with svc.
func (h *CommandHandler) SetCommandLogs(svc *commandlog.Service) {
	h.logs = svc
}

// NewCommandHandler creates a new command handler.
func NewCommandHandler(svc *command.Service, v *validator.Validator, log *logger.Logger) *CommandHandler {
	return &CommandHandler{
		service:   svc,
		validator: v,
		logger:    log,
	}
}

// SetAuditService records commands a user issues, cancels or deletes through
// the API in the tenant's audit log. A command makes a sensor run something on
// the tenant's network; the sensor's own poll/ack/complete calls are not
// audited here.
func (h *CommandHandler) SetAuditService(svc *auditsvc.AuditService) {
	h.audit = svc
}

// SetScanCommandGate wires the target checks for scan commands. Without it
// every scan command is refused (fail closed).
func (h *CommandHandler) SetScanCommandGate(g scanCommandGate) {
	h.scanGate = g
}

// SetScanRunService sets the scan run service for triggering scan workflow progression.
func (h *CommandHandler) SetScanRunService(svc *scanrun.Service) {
	h.scanRunService = svc
}

// SetValidationIngest wires the validation evidence ingester used to map a
// completed validate command's result into finding evidence.
func (h *CommandHandler) SetValidationIngest(svc validationEvidenceIngester) {
	h.validationIngest = svc
}

// retestEvidenceRecorder records a retest check's evidence on the finding
// without applying it (validation.EvidenceIngestService.IngestAdvisory): a
// retest's two checks are interpreted together by the retest service, never one
// by one by the validation verdict rule (RFC-039 §6.2).
type retestEvidenceRecorder interface {
	IngestAdvisory(ctx context.Context, tenantID, findingID shared.ID, simRunID *shared.ID, ev validation.Evidence) (validation.IngestResult, error)
}

// validationRunSettler settles the run of a finding validation.
type validationRunSettler interface {
	FinishValidationRun(ctx context.Context, tenantID, runID shared.ID, succeeded bool, message, code string) error
}

// SetValidationRuns settles finding-validation runs when their command ends.
func (h *CommandHandler) SetValidationRuns(s validationRunSettler) { h.validationRuns = s }

// settleValidationRun ends the run of a finding validation (not a retest's:
// the retest service settles those) when its command ends.
func (h *CommandHandler) settleValidationRun(cmd *commanddom.Command, succeeded bool, message, code string) {
	if h.validationRuns == nil || cmd == nil || cmd.Type != commanddom.CommandTypeValidate {
		return
	}
	var payload validation.ValidateCommandPayload
	if err := json.Unmarshal(cmd.Payload, &payload); err != nil || payload.ScanRunID == "" || payload.RetestID != "" {
		return
	}
	runID, err := shared.IDFromString(payload.ScanRunID)
	if err != nil {
		return
	}
	tenantID := cmd.TenantID
	go func() {
		bgCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := h.validationRuns.FinishValidationRun(bgCtx, tenantID, runID, succeeded, message, code); err != nil {
			h.logger.Warn("failed to settle the validation run", "run_id", runID.String(), "error", err)
		}
	}()
}

// retestSettler settles a pending retest when one of its commands finishes.
type retestSettler interface {
	OnCommandFinished(ctx context.Context, tenantID, commandID shared.ID)
}

// SetRetestHooks wires continuous retest (RFC-039) into command completion:
// a validate command that carries a retest_id has its evidence recorded
// advisory-only and its retest settled (on complete and on fail).
func (h *CommandHandler) SetRetestHooks(evidence retestEvidenceRecorder, settler retestSettler) {
	h.retestEvidence = evidence
	h.retestSettler = settler
}

// SetSimulationFinalizer wires the simulation-run finalizer used to complete a
// running attack-simulation from a validate command's safe-check outcome.
func (h *CommandHandler) SetSimulationFinalizer(svc simulationRunFinalizer) {
	h.simFinalizer = svc
}

// commandCoverageEvaluator runs coverage-scoped auto-resolve for a completed
// scan command (ingest.Service).
type commandCoverageEvaluator interface {
	EvaluateCommandCoverage(ctx context.Context, tenantID, commandID shared.ID) ingest.CoverageOutcome
}

// SetCoverageEvaluator wires coverage-scoped auto-resolve, evaluated when a
// scan command completes (and again when its last report is finalized).
func (h *CommandHandler) SetCoverageEvaluator(svc commandCoverageEvaluator) {
	h.coverage = svc
}

// triggerCoverageAutoResolve evaluates a completed scan command's coverage in
// the background; it never delays the sensor's completion response.
func (h *CommandHandler) triggerCoverageAutoResolve(cmd *commanddom.Command) {
	if h.coverage == nil || cmd == nil || !ingest.IsCoverageCommandType(string(cmd.Type)) {
		return
	}
	tenantID, commandID := cmd.TenantID, cmd.ID
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		h.coverage.EvaluateCommandCoverage(ctx, tenantID, commandID)
	}()
}

// CommandResponse represents a command in API responses.
type CommandResponse struct {
	ID       string `json:"id"`
	TenantID string `json:"tenant_id,omitempty"`
	SensorID string `json:"sensor_id,omitempty"`
	// Platform is true for a job of the shared platform sensors (never named).
	Platform       bool            `json:"platform,omitempty"`
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

// commandResponseFor converts a command for a user-facing response. The
// payload of a scan command embeds the scan's scanner_config (as
// scanner_config, config and context.scanner_config), so a caller who may not
// see those values on the scan itself (canSeeScanConfigSecrets) gets the
// payload with secret-looking values masked. Sensors are served by Poll and
// the claim paths, which never go through here.
func commandResponseFor(ctx context.Context, c *commanddom.Command) CommandResponse {
	resp := toCommandResponse(c)
	if !canSeeScanConfigSecrets(ctx) {
		resp.Payload = scan.RedactPayloadSecrets(resp.Payload)
	}
	return resp
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

	// A platform job runs on shared platform sensors: the tenant sees that it
	// is a platform job, never which sensor runs it, nor the sensor's own
	// addresses and paths in what it wrote.
	if c.SensorID != nil && !c.IsPlatformJob {
		resp.SensorID = c.SensorID.String()
	}
	if c.IsPlatformJob {
		resp.Platform = true
		resp.ErrorMessage = sensordom.RedactPlatformText(resp.ErrorMessage)
		resp.Result = redactPlatformJSON(resp.Result)
	}

	return resp
}

// CreateCommandRequest represents the request to create a command.
type CreateCommandRequest struct {
	SensorID  string          `json:"sensor_id" validate:"omitempty,uuid"`
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
// @Description  Create a new command to be executed by a sensor. A `scan` command needs an owner or administrator, and its `target`/`targets` get the checks of a scan trigger (scope exclusions, scan zones, private-range policy); a refused target answers 400.
// @Tags         Commands
// @Accept       json
// @Produce      json
// @Param        body  body      CreateCommandRequest  true  "Command data"
// @Success      201   {object}  CommandResponse
// @Failure      400   {object}  apierror.Error
// @Failure      403   {object}  apierror.Error
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

	// A "scan" command may embed custom scanner-template content that the sensor
	// writes to disk and executes. The sensor only validates template name/size,
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

	// Custom templates are trusted code (owner decision 2026-10-02): a template
	// decides which hosts the sensor contacts and what it sends, so only owners
	// and administrators may author one, here as in /scanner-templates. A
	// member with commands:write still queues commands, and scans pick
	// approved templates by id (scanner_config.custom_template_ids).
	if payloadEmbedsCustomTemplates(req.Payload) && !middleware.IsAdmin(r.Context()) {
		apierror.Forbidden("Only owners and administrators can send custom templates").WriteJSON(w)
		return
	}

	tenantID := middleware.GetTenantID(r.Context())
	input := command.CreateInput{
		TenantID:  tenantID,
		SensorID:  req.SensorID,
		Type:      req.Type,
		Priority:  req.Priority,
		Payload:   req.Payload,
		ExpiresIn: req.ExpiresIn,
	}

	// A scan command makes a sensor scan whatever it names (RFC-040 Q5 (c)):
	// only owners and administrators may send one, and its targets go
	// through the checks of a scan trigger: scope exclusions, scan zones and
	// the private-range policy.
	var targets []string
	if req.Type == string(commanddom.CommandTypeScan) {
		gated, ok := h.gateScanCommand(w, r, tenantID, &input)
		if !ok {
			return
		}
		input.Payload = gated.Payload
		input.ScanZoneID = gated.ScanZoneID
		// The claim re-checks the targets as GateCommandPayload checked
		// them: the caller's act scope, no tier ceiling.
		input.DispatchGate = &commanddom.DispatchGate{ActScope: true, Actor: requestUserID(r.Context())}
		targets = gated.Targets
	}

	cmd, err := h.service.Create(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	event := auditsvc.NewSuccessEvent(audit.ActionCommandCreated, audit.ResourceTypeCommand, cmd.ID.String()).
		WithResourceName(string(cmd.Type)).
		WithMessage("Command " + string(cmd.Type) + " created")
	if cmd.SensorID != nil {
		event = event.WithMetadata("sensor_id", cmd.SensorID.String())
	}
	if cmd.ScanZoneID != nil {
		event = event.WithMetadata("scan_zone_id", cmd.ScanZoneID.String())
	}
	if len(targets) > 0 {
		event = event.WithMetadata("targets", auditTargetList(targets))
	}
	logRequestChange(h.audit, h.logger, r, event)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(commandResponseFor(r.Context(), cmd))
}

// requestUserID is the id of the user who makes the request ("" for none).
func requestUserID(ctx context.Context) string {
	if id := middleware.GetLocalUserID(ctx); !id.IsZero() {
		return id.String()
	}
	if id, err := shared.IDFromString(middleware.GetUserID(ctx)); err == nil && !id.IsZero() {
		return id.String()
	}
	return ""
}

// maxAuditedTargets bounds the target list copied into one audit entry.
const maxAuditedTargets = 50

func auditTargetList(targets []string) []string {
	if len(targets) <= maxAuditedTargets {
		return targets
	}
	out := append([]string(nil), targets[:maxAuditedTargets]...)
	return append(out, fmt.Sprintf("... and %d more", len(targets)-maxAuditedTargets))
}

// gateScanCommand applies the owner/admin rule and the scan target checks to
// a scan command. A refusal is answered and audited here; ok is false then.
func (h *CommandHandler) gateScanCommand(w http.ResponseWriter, r *http.Request, tenantID string, input *command.CreateInput) (*scanapp.GatedCommand, bool) {
	deny := func(reason string) {
		event := auditsvc.NewDeniedEvent(audit.ActionCommandCreated, audit.ResourceTypeCommand, "", reason).
			WithResourceName(input.Type).
			WithMessage("Scan command refused: " + reason)
		if input.SensorID != "" {
			event = event.WithMetadata("sensor_id", input.SensorID)
		}
		logRequestChange(h.audit, h.logger, r, event)
	}

	if !middleware.IsAdmin(r.Context()) {
		deny("only owners and administrators can send scan commands")
		apierror.Forbidden("Only owners and administrators can send scan commands; members start scans through Scans").WriteJSON(w)
		return nil, false
	}
	if h.scanGate == nil {
		h.logger.Error("scan command refused: scan target checks are not wired")
		apierror.InternalServerError("Scan commands are unavailable").WriteJSON(w)
		return nil, false
	}
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		apierror.BadRequest("Invalid tenant").WriteJSON(w)
		return nil, false
	}
	var sensorID *shared.ID
	if input.SensorID != "" {
		id, err := shared.IDFromString(input.SensorID)
		if err != nil {
			apierror.BadRequest("Invalid sensor_id").WriteJSON(w)
			return nil, false
		}
		sensorID = &id
	}

	gated, err := h.scanGate.GateCommandPayload(r.Context(), tid, sensorID, input.Payload)
	if err != nil {
		if errors.Is(err, shared.ErrValidation) {
			deny(err.Error())
			apierror.BadRequest(err.Error()).WriteJSON(w)
			return nil, false
		}
		h.handleServiceError(w, err)
		return nil, false
	}
	return gated, true
}

// validateInlineScanTemplates rejects a scan command that embeds custom scanner
// templates with dangerous content. Inline templates travel in the command
// payload as `custom_templates: [{name, template_type, content(base64)}]`; the
// sensor decodes and executes them but only checks name/size, so the content
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
		// see what we would be approving, and the sensor decodes and executes
		// whatever it can parse. Passing here on the assumption that the sensor's
		// parser is exactly as strict as this one is a parser-differential bet,
		// and this function exists precisely to stop templates reaching a sensor
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
		// Content is base64 (matches how the server embeds and the sensor decodes
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

// payloadEmbedsCustomTemplates reports whether a command payload carries
// inline template content. A payload that mentions custom_templates but does
// not parse into the expected shape counts as embedding them: the sensor
// decodes whatever it can, so an unreadable mention is not assumed harmless.
func payloadEmbedsCustomTemplates(payload json.RawMessage) bool {
	if len(payload) == 0 || !bytes.Contains(payload, []byte(`"custom_templates"`)) {
		return false
	}
	var p struct {
		CustomTemplates []json.RawMessage `json:"custom_templates"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return true
	}
	return len(p.CustomTemplates) > 0
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
	json.NewEncoder(w).Encode(commandResponseFor(r.Context(), cmd))
}

// List handles GET /api/v1/commands
// @Summary      List commands
// @Description  Get a paginated list of commands
// @Tags         Commands
// @Accept       json
// @Produce      json
// @Param        sensor_id   query     string  false  "Filter by sensor ID"
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

	paging, ok := listPage(w, r, 20)
	if !ok {
		return
	}
	input := command.ListInput{
		TenantID: tenantID,
		SensorID: r.URL.Query().Get("sensor_id"),
		Type:     r.URL.Query().Get("type"),
		Status:   r.URL.Query().Get("status"),
		Priority: r.URL.Query().Get("priority"),
		Page:     paging.Page,
		PerPage:  paging.PerPage,
	}

	result, err := h.service.List(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	commands := make([]CommandResponse, len(result.Data))
	for i, c := range result.Data {
		commands[i] = commandResponseFor(r.Context(), c)
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
// from the command itself (authoritative), never from the reporting sensor.
// Best-effort and asynchronous — a mapping failure never blocks the sensor's
// completion response.
func (h *CommandHandler) triggerValidationEvidence(cmd *commanddom.Command) {
	// A tool retest (RFC-039) has no validation evidence: its verdict is read
	// by the retest service, which settles the retest.
	if cmd != nil && cmd.Type == commanddom.CommandTypeRetest {
		h.triggerRetestSettle(cmd)
		return
	}
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
	// real sensor path). Accept both.
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
		// a verdict). Leave the finding untouched. A retest still settles (its
		// check counts as a missing result, so the retest ends unknown).
		h.logger.Warn("validate command completed without an outcome",
			"command_id", cmd.ID.String(), "finding_id", payload.FindingID)
		h.triggerRetestSettle(cmd)
		h.settleValidationRun(cmd, false, "the sensor reported no verdict", "NO_RESULT")
		return
	}
	// The validation produced its answer: its run is done.
	h.settleValidationRun(cmd, true, "", "")

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

	// Carry the simulation link onto the evidence. It was passed as nil here,
	// so every row this path wrote had simulation_run_id NULL — on the live
	// database all 5, all executor_kind=safe-check, i.e. all produced BY a
	// simulation and none traceable back to one. The API exposes the field, so
	// "which evidence did this run produce?" answered empty.
	//
	// The value comes from the command payload, not from the sensor: it is the
	// same field the sibling triggerSimulationFinalize already reads to decide
	// which run to finalize, so the two paths now agree by construction instead
	// of by a sensor remembering to echo it back.
	var simRunID *shared.ID
	if payload.SimulationRunID != "" {
		if id, sErr := shared.IDFromString(payload.SimulationRunID); sErr == nil {
			simRunID = &id
		} else {
			// Don't fail the evidence over it — a malformed id costs the link,
			// not the finding update.
			h.logger.Warn("validate command carries an unparseable simulation_run_id",
				"command_id", cmd.ID.String(),
				"simulation_run_id", payload.SimulationRunID)
		}
	}

	// A retest check (RFC-039): record the evidence without applying it, then
	// let the retest service settle the retest once both of its checks are in.
	if payload.RetestID != "" {
		if h.retestEvidence == nil || h.retestSettler == nil {
			h.logger.Warn("retest command completed but retest hooks are not wired",
				"command_id", cmd.ID.String(), "retest_id", payload.RetestID)
			return
		}
		commandID := cmd.ID
		go func() {
			bgCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if _, err := h.retestEvidence.IngestAdvisory(bgCtx, tenantID, findingID, nil, ev); err != nil {
				h.logger.Warn("failed to record retest evidence", "command_id", commandID.String(),
					"finding_id", payload.FindingID, "error", logger.SanitizeError(err))
			}
			h.retestSettler.OnCommandFinished(bgCtx, tenantID, commandID)
		}()
		return
	}

	go func() {
		bgCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if _, err := h.validationIngest.Ingest(bgCtx, tenantID, findingID, simRunID, ev); err != nil {
			h.logger.Error("failed to record validation evidence",
				"command_id", cmd.ID.String(),
				"finding_id", payload.FindingID,
				"error", logger.SanitizeError(err),
			)
		}
	}()
}

// triggerRetestSettle hands a finished command that belongs to a retest (a
// tool retest command, or a validate command carrying a retest id) to the
// retest service, which settles the retest once its checks have ended. The
// service looks the retest up by the command, in the command's tenant.
// Asynchronous and best-effort: the scheduler's sweep settles anything this
// misses.
func (h *CommandHandler) triggerRetestSettle(cmd *commanddom.Command) {
	if h.retestSettler == nil || cmd == nil {
		return
	}
	switch cmd.Type {
	case commanddom.CommandTypeRetest:
	case commanddom.CommandTypeValidate:
		var payload validation.ValidateCommandPayload
		if err := json.Unmarshal(cmd.Payload, &payload); err != nil || payload.RetestID == "" {
			return
		}
	default:
		return
	}
	tenantID, commandID := cmd.TenantID, cmd.ID
	go func() {
		bgCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		h.retestSettler.OnCommandFinished(bgCtx, tenantID, commandID)
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

// triggerScanRunStarted marks the command's workflow step as running. It runs
// in the request, before the sensor gets its answer: the sensor reports the
// result only after that, so the start is recorded before the asynchronous
// completion can be. Best-effort: a failure is logged and the start stands.
func (h *CommandHandler) triggerScanRunStarted(ctx context.Context, cmd *commanddom.Command) {
	if h.scanRunService == nil || cmd == nil || cmd.SensorID == nil {
		return
	}
	var payload scanrundom.StepCommandPayload
	if err := json.Unmarshal(cmd.Payload, &payload); err != nil || !payload.IsRoutable() {
		return
	}
	if err := h.scanRunService.OnStepStarted(ctx, payload.ScanRunID, payload.StepKey, *cmd.SensorID, cmd.ID); err != nil {
		h.logger.Warn("failed to mark scan workflow step started",
			"scan_run_id", payload.ScanRunID,
			"step_key", payload.StepKey,
			"error", err,
		)
	}
}

// triggerScanRunProgression triggers scan workflow progression when a command completes.
// It extracts scan workflow info from the command payload and calls OnStepCompleted.
func (h *CommandHandler) triggerScanRunProgression(ctx context.Context, cmd *commanddom.Command) {
	if h.scanRunService == nil {
		return
	}

	// Parse command payload to get scan workflow info. The shape is shared with the
	// dispatcher so the two cannot drift apart again — see
	// scanrun.StepCommandPayload.
	var payload scanrundom.StepCommandPayload

	if err := json.Unmarshal(cmd.Payload, &payload); err != nil {
		return // Not a scan workflow command
	}

	if !payload.IsRoutable() {
		// A command that carries no run/step cannot be reported back. This is
		// legitimate for non-scan workflow commands, but it also silently swallowed
		// every scan command for as long as the dispatcher wrote the wrong key,
		// so say so at debug level rather than vanishing.
		h.logger.Debug("command carries no pipeline routing keys; not progressing",
			"command_id", cmd.ID.String())
		return
	}

	// Parse result to get findings count and output, and the targets the
	// sensor's local policy skipped (sensor-supplied: bounded and cleaned).
	var result struct {
		FindingsCount int            `json:"findings_count"`
		Output        map[string]any `json:"output"`
		Metadata      struct {
			RefusedTargets      json.RawMessage `json:"refused_targets"`
			RefusedTargetsTotal int             `json:"refused_targets_total"`
		} `json:"metadata"`
	}

	if cmd.Result != nil {
		_ = json.Unmarshal(cmd.Result, &result)
	}
	skipped, skippedTotal := scanrundom.ParseSkippedTargets(result.Metadata.RefusedTargets, result.Metadata.RefusedTargetsTotal)
	skippedSummary := scanrundom.SkippedSummary(skipped, skippedTotal)

	// Trigger scan workflow progression asynchronously with independent context
	// Use background context since the HTTP request context will be canceled after response
	go func() {
		bgCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := h.scanRunService.OnStepCompletedWithSkips(bgCtx, payload.ScanRunID, payload.StepKey, result.FindingsCount, result.Output, skippedTotal, skippedSummary); err != nil {
			h.logger.Error("failed to trigger pipeline progression",
				"scan_run_id", payload.ScanRunID,
				"step_key", payload.StepKey,
				"error", err,
			)
		}
	}()
}

// triggerScanRunFailed triggers scan workflow failure when a command fails.
func (h *CommandHandler) triggerScanRunFailed(ctx context.Context, cmd *commanddom.Command, errorMessage, errorCode string) {
	if h.scanRunService == nil {
		return
	}

	// Parse command payload to get scan workflow info. Same shared shape as the
	// success path — a failure that cannot be routed loses the scanner's real
	// error message, which is how "scanner not found: nuclei" reached users as
	// "scan exceeded configured timeout".
	var payload scanrundom.StepCommandPayload

	if err := json.Unmarshal(cmd.Payload, &payload); err != nil {
		return // Not a scan workflow command
	}

	if !payload.IsRoutable() {
		h.logger.Debug("failed command carries no pipeline routing keys; error will not reach the run",
			"command_id", cmd.ID.String(), "error", logger.SanitizeText(errorMessage))
		return
	}

	// Trigger scan workflow failure asynchronously with independent context
	go func() {
		bgCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := h.scanRunService.OnStepFailed(bgCtx, payload.ScanRunID, payload.StepKey, errorMessage, errorCode); err != nil {
			h.logger.Error("failed to trigger pipeline failure",
				"scan_run_id", payload.ScanRunID,
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
	logRequestChange(h.audit, h.logger, r, auditsvc.NewSuccessEvent(audit.ActionCommandCanceled, audit.ResourceTypeCommand, cmd.ID.String()).
		WithResourceName(string(cmd.Type)).
		WithMessage("Command "+string(cmd.Type)+" canceled"))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(commandResponseFor(r.Context(), cmd))
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
	logRequestChange(h.audit, h.logger, r, auditsvc.NewSuccessEvent(audit.ActionCommandDeleted, audit.ResourceTypeCommand, commandID).
		WithMessage("Command deleted"))

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
	case errors.Is(err, shared.ErrConflict):
		// Lost claim race / command already finished: a state conflict the
		// sensor should treat as "not mine any more", not a server fault.
		apierror.Conflict(conflictMessage(err)).WriteJSON(w)
	default:
		h.logger.Error("service error", "error", err)
		apierror.InternalError(err).WriteJSON(w)
	}
}

// conflictMessage returns the domain error's own message when it carries one,
// otherwise a generic conflict message.
func conflictMessage(err error) string {
	var de *shared.DomainError
	if errors.As(err, &de) && de.Message != "" {
		return de.Message
	}
	return "Command state conflict"
}
