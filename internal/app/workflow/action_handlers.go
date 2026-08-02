package workflow

import (
	"context"
	"fmt"
	"strings"

	"github.com/openctemio/api/internal/app/aitriage"
	"github.com/openctemio/api/internal/app/finding"
	"github.com/openctemio/api/internal/app/integration"
	"github.com/openctemio/api/internal/app/pipeline"
	scansvc "github.com/openctemio/api/internal/app/scan"
	"github.com/openctemio/api/pkg/domain/shared"
	workflowdom "github.com/openctemio/api/pkg/domain/workflow"
	"github.com/openctemio/api/pkg/logger"
)

// TicketRef is the minimal created/linked-ticket info a workflow reports back.
type TicketRef struct {
	Key string
	URL string
}

// JiraTicketService is the narrow behavior the ticket action needs from the
// Jira sync service: file a ticket for a finding and push a finding's status to
// its linked ticket. Interface (with primitive params, not jira.* types) so the
// workflow package does not import app/jira — that would form a cycle through
// the app shim. The concrete adapter is wired in cmd/server.
type JiraTicketService interface {
	CreateTicketFromFinding(ctx context.Context, tenantID, findingID, projectKey, issueType string) (TicketRef, error)
	SyncFindingStatus(ctx context.Context, tenantID, findingID shared.ID) error
}

// GitHubTicketService is the narrow behavior the ticket action needs to file a
// GitHub issue for a finding.
type GitHubTicketService interface {
	CreateTicketFromFinding(ctx context.Context, tenantID, findingID, owner, repo string) (TicketRef, error)
}

// ----------------------------------------------------------------------------
// Finding Action Handlers
// ----------------------------------------------------------------------------

// FindingActionHandler handles actions related to findings.
type FindingActionHandler struct {
	vulnerabilityService *finding.VulnerabilityService
	logger               *logger.Logger
}

// NewFindingActionHandler creates a new FindingActionHandler.
func NewFindingActionHandler(vulnSvc *finding.VulnerabilityService, log *logger.Logger) *FindingActionHandler {
	return &FindingActionHandler{
		vulnerabilityService: vulnSvc,
		logger:               log,
	}
}

// Execute executes a finding-related action.
func (h *FindingActionHandler) Execute(ctx context.Context, input *ActionInput) (map[string]any, error) {
	switch input.ActionType {
	case workflowdom.ActionTypeAssignUser:
		return h.assignUser(ctx, input)
	case workflowdom.ActionTypeAssignTeam:
		return h.assignTeam(ctx, input)
	case workflowdom.ActionTypeUpdatePriority:
		return h.updatePriority(ctx, input)
	case workflowdom.ActionTypeUpdateStatus:
		return h.updateStatus(ctx, input)
	case workflowdom.ActionTypeAddTags:
		return h.addTags(ctx, input)
	case workflowdom.ActionTypeRemoveTags:
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

		// Use the actual AssignFinding method from finding.VulnerabilityService
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

	// assign_team has no backing service yet. Fail loudly instead of returning
	// {"assigned": true} — a silent no-op makes operators believe the finding
	// was routed to a team when nothing happened. See updateStatus/assignUser
	// for the wired pattern this should follow once a team-assignment service
	// exists.
	h.logger.Warn("assign_team workflow action is not implemented",
		"finding_id", findingID,
		"team_id", teamID,
	)

	return nil, fmt.Errorf("assign_team workflow action is not implemented")
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

	// update_priority has no backing service yet — fail loudly rather than
	// report a false {"updated": true} success.
	h.logger.Warn("update_priority workflow action is not implemented",
		"finding_id", findingID,
		"priority", priority,
	)

	return nil, fmt.Errorf("update_priority workflow action is not implemented")
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

		// Use the actual UpdateFindingStatus method from finding.VulnerabilityService
		_, err := h.vulnerabilityService.UpdateFindingStatus(ctx, findingID, input.TenantID.String(), finding.UpdateFindingStatusInput{
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

		// Use the actual SetFindingTags method from finding.VulnerabilityService
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
	case workflowdom.ActionTypeTriggerPipeline:
		return h.triggerPipeline(ctx, input)
	case workflowdom.ActionTypeTriggerScan:
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

// TicketActionHandler handles ticket creation and update actions. It routes to
// the same per-tenant Jira / GitHub ticketing services the direct
// POST /findings/{id}/create-ticket route uses, so a workflow files a real
// issue instead of returning a false success.
type TicketActionHandler struct {
	integrationService *integration.IntegrationService
	jira               JiraTicketService
	github             GitHubTicketService
	logger             *logger.Logger
}

// NewTicketActionHandler creates a new TicketActionHandler. jiraSvc and
// githubSvc are optional: when a provider's service is nil, create/update for
// that provider returns a clear "not configured" error rather than a fake OK.
func NewTicketActionHandler(intSvc *integration.IntegrationService, jiraSvc JiraTicketService, githubSvc GitHubTicketService, log *logger.Logger) *TicketActionHandler {
	return &TicketActionHandler{
		integrationService: intSvc,
		jira:               jiraSvc,
		github:             githubSvc,
		logger:             log,
	}
}

// Execute executes a ticket-related action.
func (h *TicketActionHandler) Execute(ctx context.Context, input *ActionInput) (map[string]any, error) {
	switch input.ActionType {
	case workflowdom.ActionTypeCreateTicket:
		return h.createTicket(ctx, input)
	case workflowdom.ActionTypeUpdateTicket:
		return h.updateTicket(ctx, input)
	default:
		return nil, fmt.Errorf("unsupported action type: %s", input.ActionType)
	}
}

// createTicket files a real issue for the workflow's finding via the same
// per-tenant Jira / GitHub ticketing services the direct
// POST /findings/{id}/create-ticket route uses. Provider defaults to jira;
// pass config.provider="github" (with owner/repo) to file a GitHub issue.
func (h *TicketActionHandler) createTicket(ctx context.Context, input *ActionInput) (map[string]any, error) {
	config := input.ActionConfig

	findingID, err := findingIDFromInput(input)
	if err != nil {
		return nil, fmt.Errorf("create_ticket: %w", err)
	}
	tenantID := input.TenantID.String()
	provider, _ := config["provider"].(string)

	if strings.EqualFold(provider, "github") {
		if h.github == nil {
			return nil, fmt.Errorf("create_ticket: github ticketing is not configured")
		}
		owner, _ := config["owner"].(string)
		repo, _ := config["repo"].(string)
		ref, err := h.github.CreateTicketFromFinding(ctx, tenantID, findingID, owner, repo)
		if err != nil {
			return nil, fmt.Errorf("create_ticket (github): %w", err)
		}
		return ticketResult("github", findingID, ref), nil
	}

	if h.jira == nil {
		return nil, fmt.Errorf("create_ticket: jira ticketing is not configured")
	}
	projectKey, _ := config["project_key"].(string)
	if projectKey == "" {
		projectKey, _ = config["project"].(string) // accept either key
	}
	issueType, _ := config["issue_type"].(string)
	ref, err := h.jira.CreateTicketFromFinding(ctx, tenantID, findingID, projectKey, issueType)
	if err != nil {
		return nil, fmt.Errorf("create_ticket (jira): %w", err)
	}
	return ticketResult("jira", findingID, ref), nil
}

// updateTicket pushes the finding's current status to its linked ticket
// (severity/status sync). Jira only for now — GitHub status sync is not exposed
// as a service method yet.
func (h *TicketActionHandler) updateTicket(ctx context.Context, input *ActionInput) (map[string]any, error) {
	findingIDStr, err := findingIDFromInput(input)
	if err != nil {
		return nil, fmt.Errorf("update_ticket: %w", err)
	}
	if h.jira == nil {
		return nil, fmt.Errorf("update_ticket: jira ticketing is not configured")
	}
	findingID, err := shared.IDFromString(findingIDStr)
	if err != nil {
		return nil, fmt.Errorf("update_ticket: invalid finding id: %w", err)
	}
	if err := h.jira.SyncFindingStatus(ctx, input.TenantID, findingID); err != nil {
		return nil, fmt.Errorf("update_ticket (jira): %w", err)
	}
	return map[string]any{
		"finding_id": findingIDStr,
		"synced":     true,
		"action":     "update_ticket",
	}, nil
}

// ticketResult builds the standard create_ticket action result payload.
func ticketResult(provider, findingID string, ref TicketRef) map[string]any {
	return map[string]any{
		"finding_id": findingID,
		"provider":   provider,
		"ticket_key": ref.Key,
		"ticket_url": ref.URL,
		"created":    true,
		"action":     "create_ticket",
	}
}

// findingIDFromInput resolves the target finding ID from an action's config or
// the workflow trigger data. Shared by the ticket and AI-triage handlers.
func findingIDFromInput(input *ActionInput) (string, error) {
	if id, ok := input.ActionConfig["finding_id"].(string); ok && id != "" {
		return id, nil
	}
	if trigger, ok := input.TriggerData["finding"].(map[string]any); ok {
		if id, ok := trigger["id"].(string); ok && id != "" {
			return id, nil
		}
	}
	if c, ok := input.Context["trigger"].(map[string]any); ok {
		if finding, ok := c["finding"].(map[string]any); ok {
			if id, ok := finding["id"].(string); ok && id != "" {
				return id, nil
			}
		}
	}
	return "", fmt.Errorf("finding_id not found in config or trigger data")
}

// ----------------------------------------------------------------------------
// AI Triage Action Handler
// ----------------------------------------------------------------------------

// AITriageActionHandler handles AI triage triggering actions.
type AITriageActionHandler struct {
	aiTriageService *aitriage.AITriageService
	logger          *logger.Logger
}

// NewAITriageActionHandler creates a new AITriageActionHandler.
func NewAITriageActionHandler(aiTriageSvc *aitriage.AITriageService, log *logger.Logger) *AITriageActionHandler {
	return &AITriageActionHandler{
		aiTriageService: aiTriageSvc,
		logger:          log,
	}
}

// Execute executes an AI triage action.
func (h *AITriageActionHandler) Execute(ctx context.Context, input *ActionInput) (map[string]any, error) {
	if input.ActionType != workflowdom.ActionTypeTriggerAITriage {
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
	resp, err := h.aiTriageService.RequestTriage(ctx, aitriage.TriageRequest{
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
	return findingIDFromInput(input)
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
	vulnSvc *finding.VulnerabilityService,
	pipelineSvc *pipeline.Service,
	scanSvc *scansvc.Service,
	integrationSvc *integration.IntegrationService,
	log *logger.Logger,
) {
	RegisterAllActionHandlersWithAI(executor, vulnSvc, pipelineSvc, scanSvc, integrationSvc, nil, nil, nil, log)
}

// RegisterAllActionHandlersWithAI registers all built-in action handlers,
// including AI triage and the Jira/GitHub ticket actions. jiraSvc/githubSvc are
// optional; when both are nil the ticket handler still registers (so the action
// returns a clear "not configured" error rather than an "unsupported action").
func RegisterAllActionHandlersWithAI(
	executor *WorkflowExecutor,
	vulnSvc *finding.VulnerabilityService,
	pipelineSvc *pipeline.Service,
	scanSvc *scansvc.Service,
	integrationSvc *integration.IntegrationService,
	aiTriageSvc *aitriage.AITriageService,
	jiraSvc JiraTicketService,
	githubSvc GitHubTicketService,
	log *logger.Logger,
) {
	// Finding actions
	if vulnSvc != nil {
		findingHandler := NewFindingActionHandler(vulnSvc, log)
		executor.RegisterActionHandler(workflowdom.ActionTypeAssignUser, findingHandler)
		executor.RegisterActionHandler(workflowdom.ActionTypeAssignTeam, findingHandler)
		executor.RegisterActionHandler(workflowdom.ActionTypeUpdatePriority, findingHandler)
		executor.RegisterActionHandler(workflowdom.ActionTypeUpdateStatus, findingHandler)
		executor.RegisterActionHandler(workflowdom.ActionTypeAddTags, findingHandler)
		executor.RegisterActionHandler(workflowdom.ActionTypeRemoveTags, findingHandler)
	}

	// Pipeline/Scan actions
	if pipelineSvc != nil || scanSvc != nil {
		pipelineHandler := NewPipelineTriggerHandler(pipelineSvc, scanSvc, log)
		executor.RegisterActionHandler(workflowdom.ActionTypeTriggerPipeline, pipelineHandler)
		executor.RegisterActionHandler(workflowdom.ActionTypeTriggerScan, pipelineHandler)
	}

	// Ticket actions (Jira / GitHub). Register when any ticketing dependency is
	// present so the action fails with a clear "not configured" error rather
	// than an "unsupported action type".
	if integrationSvc != nil || jiraSvc != nil || githubSvc != nil {
		ticketHandler := NewTicketActionHandler(integrationSvc, jiraSvc, githubSvc, log)
		executor.RegisterActionHandler(workflowdom.ActionTypeCreateTicket, ticketHandler)
		executor.RegisterActionHandler(workflowdom.ActionTypeUpdateTicket, ticketHandler)
	}

	// AI Triage action
	if aiTriageSvc != nil {
		aiTriageHandler := NewAITriageActionHandler(aiTriageSvc, log)
		executor.RegisterActionHandler(workflowdom.ActionTypeTriggerAITriage, aiTriageHandler)
	}

	// Script runner (disabled by default)
	executor.RegisterActionHandler(workflowdom.ActionTypeRunScript, NewScriptRunnerHandler(log))
}
