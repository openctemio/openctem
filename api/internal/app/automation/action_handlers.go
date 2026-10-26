package automation

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/internal/app/scanrun"

	"github.com/openctemio/openctem/api/internal/app/aitriage"
	"github.com/openctemio/openctem/api/internal/app/finding"
	"github.com/openctemio/openctem/api/internal/app/integration"
	scansvc "github.com/openctemio/openctem/api/internal/app/scan"
	automationdom "github.com/openctemio/openctem/api/pkg/domain/automation"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// TicketRef is the minimal created/linked-ticket info a workflow reports back.
type TicketRef struct {
	Key string
	URL string
	// Held: the integration's create policy held the finding back (below
	// its threshold or over its daily cap); nothing was filed.
	Held       bool
	HeldReason string
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
	case automationdom.ActionTypeAssignUser:
		return h.assignUser(ctx, input)
	case automationdom.ActionTypeUpdateStatus:
		return h.updateStatus(ctx, input)
	case automationdom.ActionTypeAddTags:
		return h.addTags(ctx, input)
	case automationdom.ActionTypeRemoveTags:
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

func (h *FindingActionHandler) updateStatus(ctx context.Context, input *ActionInput) (map[string]any, error) {
	findingID, err := h.getFindingID(input)
	if err != nil {
		return nil, err
	}

	status, ok := input.ActionConfig["status"].(string)
	if !ok || status == "" {
		return nil, fmt.Errorf("status is required for update_status action")
	}
	// A stored node may predate the allow-list: it never closes risk.
	if !automationdom.StatusTargetAllowed(status) {
		return nil, shared.NewDomainError(automationdom.ErrCodeStatusNotAllowed,
			fmt.Sprintf("update_status may set only %v, not %q", automationdom.AutomationStatusTargets, status), shared.ErrValidation)
	}

	// FIXED: Actually call the vulnerability service to update status
	if h.vulnerabilityService != nil {
		h.logger.Info("updating finding status",
			"finding_id", findingID,
			"status", status,
		)

		// Get optional resolution from config
		resolution, _ := input.ActionConfig["resolution"].(string)

		// The workflow is the actor, not a person: the move and its timeline
		// entry (actor "workflow:<id>") commit together. Before, the actor id
		// "workflow:<uuid>" was passed as a user id and the entry failed.
		moveCtx := vulnerability.WithStatusTransition(ctx, vulnerability.StatusTransition{
			Source: "workflow", Reason: "workflow_action", ActorName: "workflow:" + input.WorkflowID.String(),
			Message: resolution, Changes: map[string]any{"workflow_id": input.WorkflowID.String()},
		})
		_, err := h.vulnerabilityService.UpdateFindingStatus(moveCtx, findingID, input.TenantID.String(), finding.UpdateFindingStatusInput{
			Status:     status,
			Resolution: resolution,
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

		// Merged with the tags as stored at write time (re-read on a lost
		// race), so a concurrent tag change is kept.
		_, err = h.vulnerabilityService.EditFindingTags(ctx, findingID, input.TenantID.String(), tagStrings, nil)
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

		_, err = h.vulnerabilityService.EditFindingTags(ctx, findingID, input.TenantID.String(), nil, tagStrings)
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
	scanRunService *scanrun.Service
	scanService    *scansvc.Service
	logger         *logger.Logger
}

// NewPipelineTriggerHandler creates a new PipelineTriggerHandler.
func NewPipelineTriggerHandler(scanRunSvc *scanrun.Service, scanSvc *scansvc.Service, log *logger.Logger) *PipelineTriggerHandler {
	return &PipelineTriggerHandler{
		scanRunService: scanRunSvc,
		scanService:    scanSvc,
		logger:         log,
	}
}

// Execute executes a pipeline/scan trigger action.
func (h *PipelineTriggerHandler) Execute(ctx context.Context, input *ActionInput) (map[string]any, error) {
	switch input.ActionType {
	case automationdom.ActionTypeTriggerScan:
		return h.triggerScan(ctx, input)
	default:
		return nil, fmt.Errorf("unsupported action type: %s", input.ActionType)
	}
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
		// The scan acts as the person the step was authorized as (the
		// automation's owner), never as the scan's own owner: a member's
		// automation must not carry an administrator's wider scope. No
		// principal, no scan.
		if input.Principal.IsZero() {
			return nil, fmt.Errorf("trigger_scan: the step has no person to act as")
		}
		run, err := h.scanService.TriggerScan(ctx, scansvc.TriggerScanExecInput{
			TenantID:    input.TenantID.String(),
			ScanID:      scanID,
			TriggeredBy: input.Principal.String(),
			// The run says an automation started it (research/62 P0-11); the
			// cause in its context names the automation, its run and the node
			// (the label reads the cause first).
			TriggerType: scanworkflow.TriggerTypeAutomation,
			Context:     runContextWithCause(ctx, input.TriggerData),
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

	// No service: the step fails. A {"triggered": false} success would show
	// a green run that started nothing.
	return nil, fmt.Errorf("trigger_scan: scan service not available")
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
	case automationdom.ActionTypeCreateTicket:
		return h.createTicket(ctx, input)
	case automationdom.ActionTypeUpdateTicket:
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
	if ref.Held {
		return map[string]any{
			"finding_id":  findingID,
			"provider":    provider,
			"created":     false,
			"held":        true,
			"held_reason": ref.HeldReason,
			"action":      "create_ticket",
		}
	}
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
	if input.ActionType != automationdom.ActionTypeTriggerAITriage {
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
		// No service: the step fails rather than report a run that
		// requested nothing as a success.
		return nil, fmt.Errorf("trigger_ai_triage: AI triage service not available")
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
// Request actions
// ----------------------------------------------------------------------------

// ApprovalRequester creates a finding's false-positive or risk-acceptance
// request (finding.VulnerabilityService).
type ApprovalRequester interface {
	RequestApproval(ctx context.Context, input finding.RequestApprovalInput) (*vulnerability.Approval, error)
}

// RequestActionHandler runs request_false_positive and
// request_risk_acceptance. It only ever creates a request, marked as made by
// an automation, which a person decides: the approvals service never lets
// one person decide such a request, whatever the organization's level.
type RequestActionHandler struct {
	requests ApprovalRequester
	now      func() time.Time
}

// NewRequestActionHandler creates a RequestActionHandler.
func NewRequestActionHandler(requests ApprovalRequester) *RequestActionHandler {
	return &RequestActionHandler{requests: requests, now: time.Now}
}

// Execute creates the request on behalf of the step's principal.
func (h *RequestActionHandler) Execute(ctx context.Context, input *ActionInput) (map[string]any, error) {
	var status vulnerability.FindingStatus
	switch input.ActionType {
	case automationdom.ActionTypeRequestFalsePositive:
		status = vulnerability.FindingStatusFalsePositive
	case automationdom.ActionTypeRequestRiskAcceptance:
		status = vulnerability.FindingStatusAccepted
	default:
		return nil, fmt.Errorf("unsupported action type: %s", input.ActionType)
	}
	if h.requests == nil {
		return nil, fmt.Errorf("%s: the approvals service is not available", input.ActionType)
	}
	if input.Principal.IsZero() {
		return nil, fmt.Errorf("%s: the step has no person to request for", input.ActionType)
	}
	findingID, err := findingIDFromInput(input)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", input.ActionType, err)
	}
	if err := automationdom.ValidateRequestConfigs(automationdom.NodeConfig{ActionType: input.ActionType, ActionConfig: input.ActionConfig}); err != nil {
		return nil, err
	}
	reason, _ := input.ActionConfig["closure_reason"].(string)
	note, _ := input.ActionConfig["justification"].(string)
	req := finding.RequestApprovalInput{
		TenantID: input.TenantID.String(), FindingID: findingID, RequestedStatus: string(status),
		Justification: note, RequestedBy: input.Principal.String(), ClosureReason: reason,
		CanApprove: false, ByAutomation: true,
	}
	if status == vulnerability.FindingStatusAccepted {
		days, _ := input.ActionConfig["expires_in_days"].(float64)
		end := h.now().Add(time.Duration(days) * 24 * time.Hour).UTC().Format(time.RFC3339)
		req.ExpiresAt = &end
	}
	a, err := h.requests.RequestApproval(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", input.ActionType, err)
	}
	return map[string]any{
		"finding_id":  findingID,
		"approval_id": a.ID.String(),
		"status":      string(a.Status),
		"requested":   true,
		"action":      string(input.ActionType),
	}, nil
}

// ----------------------------------------------------------------------------
// Handler Registration Helper
// ----------------------------------------------------------------------------

// RegisterAllActionHandlers registers all built-in action handlers.
func RegisterAllActionHandlers(
	executor *WorkflowExecutor,
	vulnSvc *finding.VulnerabilityService,
	scanRunSvc *scanrun.Service,
	scanSvc *scansvc.Service,
	integrationSvc *integration.IntegrationService,
	log *logger.Logger,
) {
	RegisterAllActionHandlersWithAI(executor, vulnSvc, scanRunSvc, scanSvc, integrationSvc, nil, nil, nil, log)
}

// RegisterAllActionHandlersWithAI registers all built-in action handlers,
// including AI triage and the Jira/GitHub ticket actions. jiraSvc/githubSvc are
// optional; when both are nil the ticket handler still registers (so the action
// returns a clear "not configured" error rather than an "unsupported action").
func RegisterAllActionHandlersWithAI(
	executor *WorkflowExecutor,
	vulnSvc *finding.VulnerabilityService,
	scanRunSvc *scanrun.Service,
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
		executor.RegisterActionHandler(automationdom.ActionTypeAssignUser, findingHandler)
		executor.RegisterActionHandler(automationdom.ActionTypeUpdateStatus, findingHandler)
		executor.RegisterActionHandler(automationdom.ActionTypeAddTags, findingHandler)
		executor.RegisterActionHandler(automationdom.ActionTypeRemoveTags, findingHandler)
		requestHandler := NewRequestActionHandler(vulnSvc)
		executor.RegisterActionHandler(automationdom.ActionTypeRequestFalsePositive, requestHandler)
		executor.RegisterActionHandler(automationdom.ActionTypeRequestRiskAcceptance, requestHandler)
	}

	// Pipeline/Scan actions
	if scanRunSvc != nil || scanSvc != nil {
		pipelineHandler := NewPipelineTriggerHandler(scanRunSvc, scanSvc, log)
		executor.RegisterActionHandler(automationdom.ActionTypeTriggerScan, pipelineHandler)
	}

	// Ticket actions (Jira / GitHub). Register when any ticketing dependency is
	// present so the action fails with a clear "not configured" error rather
	// than an "unsupported action type".
	if integrationSvc != nil || jiraSvc != nil || githubSvc != nil {
		ticketHandler := NewTicketActionHandler(integrationSvc, jiraSvc, githubSvc, log)
		executor.RegisterActionHandler(automationdom.ActionTypeCreateTicket, ticketHandler)
		executor.RegisterActionHandler(automationdom.ActionTypeUpdateTicket, ticketHandler)
	}

	// AI Triage action
	if aiTriageSvc != nil {
		aiTriageHandler := NewAITriageActionHandler(aiTriageSvc, log)
		executor.RegisterActionHandler(automationdom.ActionTypeTriggerAITriage, aiTriageHandler)
	}
}

// runContextWithCause is the context of a scan an automation step starts:
// the step's trigger data, with the step's cause replacing the trigger's,
// so the scan_completed event of that scan counts as caused by this run
// (loop_guard.go).
func runContextWithCause(ctx context.Context, triggerData map[string]any) map[string]any {
	c, ok := AutomationCauseFrom(ctx)
	if !ok {
		return triggerData
	}
	return withCause(triggerData, &c)
}
