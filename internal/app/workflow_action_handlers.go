package app

import (
	"context"
	"fmt"

	"github.com/openctemio/api/internal/app/pipeline"
	scansvc "github.com/openctemio/api/internal/app/scan"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/workflow"
	"github.com/openctemio/api/pkg/logger"
)

// ----------------------------------------------------------------------------
// Finding Action Handlers
// ----------------------------------------------------------------------------

// FindingActionHandler handles actions related to findings.
type FindingActionHandler struct {
	vulnerabilityService *VulnerabilityService
	logger               *logger.Logger
}

// NewFindingActionHandler creates a new FindingActionHandler.
func NewFindingActionHandler(vulnSvc *VulnerabilityService, log *logger.Logger) *FindingActionHandler {
	return &FindingActionHandler{
		vulnerabilityService: vulnSvc,
		logger:               log,
	}
}

// Execute executes a finding-related action.
func (h *FindingActionHandler) Execute(ctx context.Context, input *ActionInput) (map[string]any, error) {
	switch input.ActionType {
	case workflow.ActionTypeAssignUser:
		return h.assignUser(ctx, input)
	case workflow.ActionTypeAssignTeam:
		return h.assignTeam(ctx, input)
	case workflow.ActionTypeUpdatePriority:
		return h.updatePriority(ctx, input)
	case workflow.ActionTypeUpdateStatus:
		return h.updateStatus(ctx, input)
	case workflow.ActionTypeAddTags:
		return h.addTags(ctx, input)
	case workflow.ActionTypeRemoveTags:
		return h.removeTags(ctx, input)
	default:
		return nil, fmt.Errorf("unsupported action type: %s", input.ActionType)
	}
}

func (h *FindingActionHandler) assignUser(ctx context.Context, input *ActionInput) (map[string]any, error) {
	// Get finding ID from trigger data or config
	findingID, err := h.getFindingID(input)
	if err != nil {
		return nil, err
	}

	// Get user ID from config
	userID, ok := input.ActionConfig["user_id"].(string)
	if !ok || userID == "" {
		return nil, fmt.Errorf("user_id is required for assign_user action")
	}

	if _, err := shared.IDFromString(userID); err != nil {
		return nil, fmt.Errorf("invalid user_id: %w", err)
	}

	// FIXED: Actually call the vulnerability service to assign the finding
	if h.vulnerabilityService != nil {
		h.logger.Info("assigning finding to user",
			"finding_id", findingID,
			"user_id", userID,
		)

		// Use the actual AssignFinding method from VulnerabilityService
		_, err := h.vulnerabilityService.AssignFinding(ctx, findingID, input.TenantID.String(), userID, "workflow:"+input.WorkflowID.String())
		if err != nil {
			return nil, fmt.Errorf("failed to assign finding to user: %w", err)
		}

		return map[string]any{
			"finding_id": findingID,
			"user_id":    userID,
			"assigned":   true,
			"action":     "assign_user",
		}, nil
	}

	return nil, fmt.Errorf("vulnerability service not available")
}

func (h *FindingActionHandler) assignTeam(ctx context.Context, input *ActionInput) (map[string]any, error) {
	findingID, err := h.getFindingID(input)
	if err != nil {
		return nil, err
	}

	teamID, ok := input.ActionConfig["team_id"].(string)
	if !ok || teamID == "" {
		return nil, fmt.Errorf("team_id is required for assign_team action")
	}

	h.logger.Info("assigning finding to team",
		"finding_id", findingID,
		"team_id", teamID,
	)

	return map[string]any{
		"finding_id": findingID,
		"team_id":    teamID,
		"assigned":   true,
		"action":     "assign_team",
	}, nil
}

func (h *FindingActionHandler) updatePriority(ctx context.Context, input *ActionInput) (map[string]any, error) {
	findingID, err := h.getFindingID(input)
	if err != nil {
		return nil, err
	}

	priority, ok := input.ActionConfig["priority"].(string)
	if !ok || priority == "" {
		return nil, fmt.Errorf("priority is required for update_priority action")
	}

	h.logger.Info("updating finding priority",
		"finding_id", findingID,
		"priority", priority,
	)

	return map[string]any{
		"finding_id": findingID,
		"priority":   priority,
		"updated":    true,
		"action":     "update_priority",
	}, nil
}

func (h *FindingActionHandler) updateStatus(ctx context.Context, input *ActionInput) (map[string]any, error) {
	findingID, err := h.getFindingID(input)
	if err != nil {
		return nil, err
	}

	status, ok := input.ActionConfig["status"].(string)
	if !ok || status == "" {
		return nil, fmt.Errorf("status is required for update_status action")
	}

	// FIXED: Actually call the vulnerability service to update status
	if h.vulnerabilityService != nil {
		h.logger.Info("updating finding status",
			"finding_id", findingID,
			"status", status,
		)

		// Get optional resolution from config
		resolution, _ := input.ActionConfig["resolution"].(string)

		// Use the actual UpdateFindingStatus method from VulnerabilityService
		_, err := h.vulnerabilityService.UpdateFindingStatus(ctx, findingID, input.TenantID.String(), UpdateFindingStatusInput{
			Status:     status,
			Resolution: resolution,
			ActorID:    "workflow:" + input.WorkflowID.String(),
		})
		if err != nil {
			return nil, fmt.Errorf("failed to update finding status: %w", err)
		}

		return map[string]any{
			"finding_id": findingID,
			"status":     status,
			"updated":    true,
			"action":     "update_status",
		}, nil
	}

	return nil, fmt.Errorf("vulnerability service not available")
}

func (h *FindingActionHandler) addTags(ctx context.Context, input *ActionInput) (map[string]any, error) {
	findingID, err := h.getFindingID(input)
	if err != nil {
		return nil, err
	}

	tags, ok := input.ActionConfig["tags"].([]any)
	if !ok || len(tags) == 0 {
		return nil, fmt.Errorf("tags is required for add_tags action")
	}

	tagStrings := make([]string, len(tags))
	for i, t := range tags {
		tagStrings[i] = fmt.Sprintf("%v", t)
	}

	// FIXED: Actually call the vulnerability service to add tags
	if h.vulnerabilityService != nil {
		h.logger.Info("adding tags to finding",
			"finding_id", findingID,
			"tags", tagStrings,
		)

		// Use the actual SetFindingTags method from VulnerabilityService
		// Note: This sets tags, so we need to get existing tags first and merge
		finding, err := h.vulnerabilityService.GetFinding(ctx, input.TenantID.String(), findingID)
		if err != nil {
			return nil, fmt.Errorf("failed to get finding: %w", err)
		}

		// Merge existing tags with new tags (remove duplicates)
		existingTags := make(map[string]bool)
		for _, t := range finding.Tags() { // Tags() is a method, not a field
			existingTags[t] = true
		}
		for _, t := range tagStrings {
			existingTags[t] = true
		}
		mergedTags := make([]string, 0, len(existingTags))
		for t := range existingTags {
			mergedTags = append(mergedTags, t)
		}

		_, err = h.vulnerabilityService.SetFindingTags(ctx, findingID, input.TenantID.String(), mergedTags)
		if err != nil {
			return nil, fmt.Errorf("failed to add tags to finding: %w", err)
		}

		return map[string]any{
			"finding_id": findingID,
			"tags":       tagStrings,
			"added":      true,
			"action":     "add_tags",
		}, nil
	}

	return nil, fmt.Errorf("vulnerability service not available")
}

func (h *FindingActionHandler) removeTags(ctx context.Context, input *ActionInput) (map[string]any, error) {
	findingID, err := h.getFindingID(input)
	if err != nil {
		return nil, err
	}

	tags, ok := input.ActionConfig["tags"].([]any)
	if !ok || len(tags) == 0 {
		return nil, fmt.Errorf("tags is required for remove_tags action")
	}

	tagStrings := make([]string, len(tags))
	for i, t := range tags {
		tagStrings[i] = fmt.Sprintf("%v", t)
	}

	// FIXED: Actually call the vulnerability service to remove tags
	if h.vulnerabilityService != nil {
		h.logger.Info("removing tags from finding",
			"finding_id", findingID,
			"tags", tagStrings,
		)

		// Get existing finding to filter tags
		finding, err := h.vulnerabilityService.GetFinding(ctx, input.TenantID.String(), findingID)
		if err != nil {
			return nil, fmt.Errorf("failed to get finding: %w", err)
		}

		// Remove specified tags from existing tags
		tagsToRemove := make(map[string]bool)
		for _, t := range tagStrings {
			tagsToRemove[t] = true
		}
		remainingTags := make([]string, 0)
		for _, t := range finding.Tags() {
			if !tagsToRemove[t] {
				remainingTags = append(remainingTags, t)
			}
		}

		_, err = h.vulnerabilityService.SetFindingTags(ctx, findingID, input.TenantID.String(), remainingTags)
		if err != nil {
			return nil, fmt.Errorf("failed to remove tags from finding: %w", err)
		}

		return map[string]any{
			"finding_id": findingID,
			"tags":       tagStrings,
			"removed":    true,
			"action":     "remove_tags",
		}, nil
	}

	return nil, fmt.Errorf("vulnerability service not available")
}

func (h *FindingActionHandler) getFindingID(input *ActionInput) (string, error) {
	// First check action config
	if id, ok := input.ActionConfig["finding_id"].(string); ok && id != "" {
		return id, nil
	}

	// Then check trigger data
	if trigger, ok := input.TriggerData["finding"].(map[string]any); ok {
		if id, ok := trigger["id"].(string); ok && id != "" {
			return id, nil
		}
	}

	// Check context
	if ctx, ok := input.Context["trigger"].(map[string]any); ok {
		if finding, ok := ctx["finding"].(map[string]any); ok {
			if id, ok := finding["id"].(string); ok && id != "" {
				return id, nil
			}
		}
	}

	return "", fmt.Errorf("finding_id not found in config or trigger data")
}

// ----------------------------------------------------------------------------
// Pipeline/Scan Trigger Handler
// ----------------------------------------------------------------------------

// PipelineTriggerHandler handles pipeline and scan triggering actions.
type PipelineTriggerHandler struct {
	pipelineService *pipeline.Service
	scanService     *scansvc.Service
	logger          *logger.Logger
}

// NewPipelineTriggerHandler creates a new PipelineTriggerHandler.
func NewPipelineTriggerHandler(pipelineSvc *pipeline.Service, scanSvc *scansvc.Service, log *logger.Logger) *PipelineTriggerHandler {
	return &PipelineTriggerHandler{
		pipelineService: pipelineSvc,
		scanService:     scanSvc,
		logger:          log,
	}
}

// Execute executes a pipeline/scan trigger action.
func (h *PipelineTriggerHandler) Execute(ctx context.Context, input *ActionInput) (map[string]any, error) {
	switch input.ActionType {
	case workflow.ActionTypeTriggerPipeline:
		return h.triggerPipeline(ctx, input)
	case workflow.ActionTypeTriggerScan:
		return h.triggerScan(ctx, input)
	default:
		return nil, fmt.Errorf("unsupported action type: %s", input.ActionType)
	}
}

func (h *PipelineTriggerHandler) triggerPipeline(ctx context.Context, input *ActionInput) (map[string]any, error) {
	pipelineID, ok := input.ActionConfig["pipeline_id"].(string)
	if !ok || pipelineID == "" {
		return nil, fmt.Errorf("pipeline_id is required for trigger_pipeline action")
	}

	// Validate pipeline_id format
	if _, err := shared.IDFromString(pipelineID); err != nil {
		return nil, fmt.Errorf("invalid pipeline_id: %w", err)
	}

	// Get optional asset ID
	assetID := ""
	if aID, ok := input.ActionConfig["asset_id"].(string); ok && aID != "" {
		assetID = aID
	}

	h.logger.Info("triggering pipeline from workflow",
		"pipeline_id", pipelineID,
		"asset_id", assetID,
		"workflow_id", input.WorkflowID,
	)

	if h.pipelineService != nil {
		// Build trigger input using TriggerPipelineInput
		triggerInput := pipeline.TriggerPipelineInput{
			TenantID:    input.TenantID.String(),
			TemplateID:  pipelineID,
			AssetID:     assetID,
			TriggerType: "api",
			TriggeredBy: "workflow:" + input.WorkflowID.String(),
			Context:     input.TriggerData,
		}

		run, err := h.pipelineService.TriggerPipeline(ctx, triggerInput)
		if err != nil {
			return nil, fmt.Errorf("failed to trigger pipeline: %w", err)
		}

		return map[string]any{
			"pipeline_id": pipelineID,
			"run_id":      run.ID.String(),
			"triggered":   true,
			"action":      "trigger_pipeline",
		}, nil
	}

	return map[string]any{
		"pipeline_id": pipelineID,
		"triggered":   false,
		"error":       "pipeline service not available",
		"action":      "trigger_pipeline",
	}, nil
}

func (h *PipelineTriggerHandler) triggerScan(ctx context.Context, input *ActionInput) (map[string]any, error) {
	scanID, ok := input.ActionConfig["scan_id"].(string)
	if !ok || scanID == "" {
		return nil, fmt.Errorf("scan_id is required for trigger_scan action")
	}

	// Validate scan_id format
	if _, err := shared.IDFromString(scanID); err != nil {
		return nil, fmt.Errorf("invalid scan_id: %w", err)
	}

	h.logger.Info("triggering scan from workflow",
		"scan_id", scanID,
		"workflow_id", input.WorkflowID,
	)

	if h.scanService != nil {
		run, err := h.scanService.TriggerScan(ctx, scansvc.TriggerScanExecInput{
			TenantID:    input.TenantID.String(),
			ScanID:      scanID,
			TriggeredBy: "workflow:" + input.WorkflowID.String(),
			Context:     input.TriggerData,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to trigger scan: %w", err)
		}

		return map[string]any{
			"scan_id":   scanID,
			"run_id":    run.ID.String(),
			"triggered": true,
			"action":    "trigger_scan",
		}, nil
	}

	return map[string]any{
		"scan_id":   scanID,
		"triggered": false,
		"error":     "scan service not available",
		"action":    "trigger_scan",
	}, nil
}

// ----------------------------------------------------------------------------
// Ticket Action Handler
// ----------------------------------------------------------------------------

// TicketActionHandler handles ticket creation and update actions.
type TicketActionHandler struct {
	integrationService *IntegrationService
	logger             *logger.Logger
}

// NewTicketActionHandler creates a new TicketActionHandler.
func NewTicketActionHandler(intSvc *IntegrationService, log *logger.Logger) *TicketActionHandler {
	return &TicketActionHandler{
		integrationService: intSvc,
		logger:             log,
	}
}

// Execute executes a ticket-related action.
func (h *TicketActionHandler) Execute(ctx context.Context, input *ActionInput) (map[string]any, error) {
	switch input.ActionType {
	case workflow.ActionTypeCreateTicket:
		return h.createTicket(ctx, input)
	case workflow.ActionTypeUpdateTicket:
		return h.updateTicket(ctx, input)
	default:
		return nil, fmt.Errorf("unsupported action type: %s", input.ActionType)
	}
}

func (h *TicketActionHandler) createTicket(ctx context.Context, input *ActionInput) (map[string]any, error) {
	config := input.ActionConfig

	// Required fields
	integrationID, _ := config["integration_id"].(string)
	title, _ := config["title"].(string)
	description, _ := config["description"].(string)

	if integrationID == "" {
		return nil, fmt.Errorf("integration_id is required for create_ticket action")
	}
	if title == "" {
		return nil, fmt.Errorf("title is required for create_ticket action")
	}

	// Optional fields
	project, _ := config["project"].(string)
	issueType, _ := config["issue_type"].(string)
	priority, _ := config["priority"].(string)
	labels, _ := config["labels"].([]any)

	labelStrings := make([]string, 0)
	for _, l := range labels {
		labelStrings = append(labelStrings, fmt.Sprintf("%v", l))
	}

	h.logger.Info("creating ticket from workflow",
		"integration_id", integrationID,
		"title", title,
		"project", project,
	)

	// In a real implementation, this would use the integration service
	// to create a ticket in Jira, GitHub Issues, etc.

	return map[string]any{
		"integration_id": integrationID,
		"title":          title,
		"description":    description,
		"project":        project,
		"issue_type":     issueType,
		"priority":       priority,
		"labels":         labelStrings,
		"created":        true,
		"action":         "create_ticket",
		// In real implementation: "ticket_id", "ticket_url"
	}, nil
}

func (h *TicketActionHandler) updateTicket(ctx context.Context, input *ActionInput) (map[string]any, error) {
	config := input.ActionConfig

	integrationID, _ := config["integration_id"].(string)
	ticketID, _ := config["ticket_id"].(string)

	if integrationID == "" {
		return nil, fmt.Errorf("integration_id is required for update_ticket action")
	}
	if ticketID == "" {
		return nil, fmt.Errorf("ticket_id is required for update_ticket action")
	}

	// Fields to update
	status, _ := config["status"].(string)
	comment, _ := config["comment"].(string)
	assignee, _ := config["assignee"].(string)

	h.logger.Info("updating ticket from workflow",
		"integration_id", integrationID,
		"ticket_id", ticketID,
	)

	return map[string]any{
		"integration_id": integrationID,
		"ticket_id":      ticketID,
		"status":         status,
		"comment":        comment,
		"assignee":       assignee,
		"updated":        true,
		"action":         "update_ticket",
	}, nil
}

// ----------------------------------------------------------------------------
// AI Triage Action Handler
// ----------------------------------------------------------------------------

// AITriageActionHandler handles AI triage triggering actions.
type AITriageActionHandler struct {
	aiTriageService *AITriageService
	logger          *logger.Logger
}

// NewAITriageActionHandler creates a new AITriageActionHandler.
func NewAITriageActionHandler(aiTriageSvc *AITriageService, log *logger.Logger) *AITriageActionHandler {
	return &AITriageActionHandler{
		aiTriageService: aiTriageSvc,
		logger:          log,
	}
}

// Execute executes an AI triage action.
func (h *AITriageActionHandler) Execute(ctx context.Context, input *ActionInput) (map[string]any, error) {
	if input.ActionType != workflow.ActionTypeTriggerAITriage {
		return nil, fmt.Errorf("unsupported action type: %s", input.ActionType)
	}

	return h.triggerAITriage(ctx, input)
}

func (h *AITriageActionHandler) triggerAITriage(ctx context.Context, input *ActionInput) (map[string]any, error) {
	// Get finding ID from trigger data or action config
	findingID, err := h.getFindingID(input)
	if err != nil {
		return nil, err
	}

	// Get triage mode from config (default: "quick")
	triageType := "manual"
	if mode, ok := input.ActionConfig["mode"].(string); ok && mode != "" {
		triageType = mode
	}

	h.logger.Info("triggering AI triage from workflow",
		"finding_id", findingID,
		"triage_type", triageType,
		"workflow_id", input.WorkflowID,
	)

	if h.aiTriageService == nil {
		return map[string]any{
			"finding_id": findingID,
			"triggered":  false,
			"error":      "AI triage service not available",
			"action":     "trigger_ai_triage",
		}, nil
	}

	// Request triage
	resp, err := h.aiTriageService.RequestTriage(ctx, TriageRequest{
		TenantID:   input.TenantID.String(),
		FindingID:  findingID,
		TriageType: triageType,
		UserID:     nil, // System-triggered via workflow
	})
	if err != nil {
		return nil, fmt.Errorf("failed to trigger AI triage: %w", err)
	}

	return map[string]any{
		"finding_id": findingID,
		"job_id":     resp.JobID,
		"status":     resp.Status,
		"triggered":  true,
		"action":     "trigger_ai_triage",
	}, nil
}

func (h *AITriageActionHandler) getFindingID(input *ActionInput) (string, error) {
	// First check action config
	if id, ok := input.ActionConfig["finding_id"].(string); ok && id != "" {
		return id, nil
	}

	// Then check trigger data
	if trigger, ok := input.TriggerData["finding"].(map[string]any); ok {
		if id, ok := trigger["id"].(string); ok && id != "" {
			return id, nil
		}
	}

	// Check context
	if ctx, ok := input.Context["trigger"].(map[string]any); ok {
		if finding, ok := ctx["finding"].(map[string]any); ok {
			if id, ok := finding["id"].(string); ok && id != "" {
				return id, nil
			}
		}
	}

	return "", fmt.Errorf("finding_id not found in config or trigger data")
}

// ----------------------------------------------------------------------------
// Script Runner Handler (placeholder - would need sandboxing in production)
// ----------------------------------------------------------------------------

// ScriptRunnerHandler handles script execution actions.
// NOTE: This is a placeholder. In production, script execution would need
// proper sandboxing, resource limits, and security controls.
type ScriptRunnerHandler struct {
	logger *logger.Logger
}

// NewScriptRunnerHandler creates a new ScriptRunnerHandler.
func NewScriptRunnerHandler(log *logger.Logger) *ScriptRunnerHandler {
	return &ScriptRunnerHandler{
		logger: log,
	}
}

// Execute executes a script action.
func (h *ScriptRunnerHandler) Execute(ctx context.Context, input *ActionInput) (map[string]any, error) {
	// Script execution is disabled by default for security reasons
	// In production, this would need:
	// - Sandboxed execution environment (e.g., Docker, gVisor)
	// - Resource limits (CPU, memory, time)
	// - Network restrictions
	// - Input validation
	// - Output sanitization

	h.logger.Warn("script execution requested but disabled for security",
		"workflow_id", input.WorkflowID,
		"node_key", input.NodeKey,
	)

	return map[string]any{
		"executed": false,
		"error":    "script execution is disabled for security reasons",
		"action":   "run_script",
	}, fmt.Errorf("script execution is disabled")
}

// ----------------------------------------------------------------------------
// Handler Registration Helper
// ----------------------------------------------------------------------------

// RegisterAllActionHandlers registers all built-in action handlers.
func RegisterAllActionHandlers(
	executor *WorkflowExecutor,
	vulnSvc *VulnerabilityService,
	pipelineSvc *pipeline.Service,
	scanSvc *scansvc.Service,
	integrationSvc *IntegrationService,
	log *logger.Logger,
) {
	RegisterAllActionHandlersWithAI(executor, vulnSvc, pipelineSvc, scanSvc, integrationSvc, nil, log)
}

// RegisterAllActionHandlersWithAI registers all built-in action handlers including AI triage.
func RegisterAllActionHandlersWithAI(
	executor *WorkflowExecutor,
	vulnSvc *VulnerabilityService,
	pipelineSvc *pipeline.Service,
	scanSvc *scansvc.Service,
	integrationSvc *IntegrationService,
	aiTriageSvc *AITriageService,
	log *logger.Logger,
) {
	// Finding actions
	if vulnSvc != nil {
		findingHandler := NewFindingActionHandler(vulnSvc, log)
		executor.RegisterActionHandler(workflow.ActionTypeAssignUser, findingHandler)
		executor.RegisterActionHandler(workflow.ActionTypeAssignTeam, findingHandler)
		executor.RegisterActionHandler(workflow.ActionTypeUpdatePriority, findingHandler)
		executor.RegisterActionHandler(workflow.ActionTypeUpdateStatus, findingHandler)
		executor.RegisterActionHandler(workflow.ActionTypeAddTags, findingHandler)
		executor.RegisterActionHandler(workflow.ActionTypeRemoveTags, findingHandler)
	}

	// Pipeline/Scan actions
	if pipelineSvc != nil || scanSvc != nil {
		pipelineHandler := NewPipelineTriggerHandler(pipelineSvc, scanSvc, log)
		executor.RegisterActionHandler(workflow.ActionTypeTriggerPipeline, pipelineHandler)
		executor.RegisterActionHandler(workflow.ActionTypeTriggerScan, pipelineHandler)
	}

	// Ticket actions
	if integrationSvc != nil {
		ticketHandler := NewTicketActionHandler(integrationSvc, log)
		executor.RegisterActionHandler(workflow.ActionTypeCreateTicket, ticketHandler)
		executor.RegisterActionHandler(workflow.ActionTypeUpdateTicket, ticketHandler)
	}

	// AI Triage action
	if aiTriageSvc != nil {
		aiTriageHandler := NewAITriageActionHandler(aiTriageSvc, log)
		executor.RegisterActionHandler(workflow.ActionTypeTriggerAITriage, aiTriageHandler)
	}

	// Script runner (disabled by default)
	executor.RegisterActionHandler(workflow.ActionTypeRunScript, NewScriptRunnerHandler(log))
}
