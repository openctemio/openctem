package app

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/domain/workflow"
	"github.com/openctemio/api/pkg/logger"
)

// Dispatcher configuration constants
const (
	// maxFindingsPerDispatch limits the number of findings processed in a single dispatch
	// to prevent memory exhaustion and ensure reasonable processing times.
	maxFindingsPerDispatch = 500

	// dispatchTimeout is the maximum time allowed for dispatching workflow events.
	dispatchTimeout = 60 * time.Second
)

// WorkflowEventDispatcher dispatches events to matching workflows.
// It evaluates trigger configurations to determine which workflows should run.
type WorkflowEventDispatcher struct {
	workflowRepo workflow.WorkflowRepository
	nodeRepo     workflow.NodeRepository
	service      *WorkflowService
	logger       *logger.Logger
}

// NewWorkflowEventDispatcher creates a new workflow event dispatcher.
func NewWorkflowEventDispatcher(
	workflowRepo workflow.WorkflowRepository,
	nodeRepo workflow.NodeRepository,
	service *WorkflowService,
	log *logger.Logger,
) *WorkflowEventDispatcher {
	return &WorkflowEventDispatcher{
		workflowRepo: workflowRepo,
		nodeRepo:     nodeRepo,
		service:      service,
		logger:       log.With("component", "workflow_event_dispatcher"),
	}
}

// FindingEvent represents a finding-related event.
type FindingEvent struct {
	TenantID  shared.ID
	Finding   *vulnerability.Finding
	EventType workflow.TriggerType // finding_created, finding_updated
	Changes   map[string]any       // For finding_updated: which fields changed
}

// DispatchFindingEvent dispatches a finding event to matching workflows.
// It evaluates all active workflows with matching trigger types and filters.
func (d *WorkflowEventDispatcher) DispatchFindingEvent(ctx context.Context, event FindingEvent) error {
	// Find all active workflows for the tenant with matching trigger type
	workflows, err := d.findMatchingWorkflows(ctx, event.TenantID, event.EventType)
	if err != nil {
		return fmt.Errorf("failed to find matching workflows: %w", err)
	}

	if len(workflows) == 0 {
		d.logger.Debug("no matching workflows found",
			"tenant_id", event.TenantID,
			"event_type", event.EventType,
		)
		return nil
	}

	// Build trigger data from finding
	triggerData := d.buildFindingTriggerData(event)

	// Trigger matching workflows
	triggeredCount := 0
	for _, wf := range workflows {
		// Check if finding matches the trigger config filters
		if !d.matchesTriggerFilters(wf, event) {
			continue
		}

		// Trigger the workflow
		_, err := d.service.TriggerWorkflow(ctx, TriggerWorkflowInput{
			TenantID:    event.TenantID,
			WorkflowID:  wf.ID,
			TriggerType: event.EventType,
			TriggerData: triggerData,
		})
		if err != nil {
			d.logger.Error("failed to trigger workflow",
				"workflow_id", wf.ID,
				"workflow_name", wf.Name,
				"error", err,
			)
			continue
		}

		triggeredCount++
		d.logger.Info("workflow triggered by event",
			"workflow_id", wf.ID,
			"workflow_name", wf.Name,
			"event_type", event.EventType,
			"finding_id", event.Finding.ID(),
		)
	}

	d.logger.Debug("finding event dispatched",
		"event_type", event.EventType,
		"finding_id", event.Finding.ID(),
		"workflows_matched", len(workflows),
		"workflows_triggered", triggeredCount,
	)

	return nil
}

// findMatchingWorkflows finds all active workflows with matching trigger type.
// Uses optimized batch query to avoid N+1 database calls.
func (d *WorkflowEventDispatcher) findMatchingWorkflows(
	ctx context.Context,
	tenantID shared.ID,
	triggerType workflow.TriggerType,
) ([]*workflow.Workflow, error) {
	// Use optimized batch query - single query returns workflows with their full graph
	workflows, err := d.workflowRepo.ListActiveWithTriggerType(ctx, tenantID, triggerType)
	if err != nil {
		return nil, fmt.Errorf("failed to list workflows with trigger type: %w", err)
	}

	return workflows, nil
}

// matchesTriggerFilters checks if the finding matches the workflow's trigger filters.
func (d *WorkflowEventDispatcher) matchesTriggerFilters(wf *workflow.Workflow, event FindingEvent) bool {
	// Find the trigger node
	var triggerNode *workflow.Node
	for _, node := range wf.Nodes {
		if node.NodeType == workflow.NodeTypeTrigger &&
			node.Config.TriggerType == event.EventType {
			triggerNode = node
			break
		}
	}

	if triggerNode == nil {
		return false
	}

	config := triggerNode.Config.TriggerConfig
	if config == nil {
		// No filters configured - match all
		return true
	}

	// Check severity_filter
	if !d.matchesSeverityFilter(config, event.Finding) {
		return false
	}

	// Check tool_filter
	if !d.matchesToolFilter(config, event.Finding) {
		return false
	}

	// Check source_filter
	if !d.matchesSourceFilter(config, event.Finding) {
		return false
	}

	return true
}

// matchesSeverityFilter checks if finding severity matches the filter.
func (d *WorkflowEventDispatcher) matchesSeverityFilter(config map[string]any, finding *vulnerability.Finding) bool {
	severityFilter, ok := config["severity_filter"]
	if !ok {
		return true // No filter - match all
	}

	severities, ok := severityFilter.([]interface{})
	if !ok || len(severities) == 0 {
		return true
	}

	findingSeverity := string(finding.Severity())
	for _, s := range severities {
		if str, ok := s.(string); ok && str == findingSeverity {
			return true
		}
	}
	return false
}

// matchesToolFilter checks if finding tool matches the filter.
func (d *WorkflowEventDispatcher) matchesToolFilter(config map[string]any, finding *vulnerability.Finding) bool {
	toolFilter, ok := config["tool_filter"]
	if !ok {
		return true // No filter - match all
	}

	tools, ok := toolFilter.([]interface{})
	if !ok || len(tools) == 0 {
		return true
	}

	findingTool := finding.ToolName()
	for _, t := range tools {
		if str, ok := t.(string); ok && str == findingTool {
			return true
		}
	}
	return false
}

// matchesSourceFilter checks if finding source matches the filter.
func (d *WorkflowEventDispatcher) matchesSourceFilter(config map[string]any, finding *vulnerability.Finding) bool {
	sourceFilter, ok := config["source_filter"]
	if !ok {
		return true // No filter - match all
	}

	sources, ok := sourceFilter.([]interface{})
	if !ok || len(sources) == 0 {
		return true
	}

	findingSource := string(finding.Source())
	for _, s := range sources {
		if str, ok := s.(string); ok && str == findingSource {
			return true
		}
	}
	return false
}

// buildFindingTriggerData builds trigger data from a finding event.
func (d *WorkflowEventDispatcher) buildFindingTriggerData(event FindingEvent) map[string]any {
	finding := event.Finding
	data := map[string]any{
		"event_type": string(event.EventType),
		"finding": map[string]any{
			"id":        finding.ID().String(),
			"title":     finding.Title(),
			"severity":  string(finding.Severity()),
			"status":    string(finding.Status()),
			"source":    string(finding.Source()),
			"tool_name": finding.ToolName(),
			"asset_id":  finding.AssetID().String(),
		},
	}

	if event.Changes != nil {
		data["changes"] = event.Changes
	}

	return data
}

// DispatchFindingsCreated dispatches finding_created events for a batch of newly created findings.
// This is called by the ingest service when findings are created during ingestion.
// Events are dispatched asynchronously to avoid blocking the ingestion pipeline.
//
// Optimizations applied:
// - Batch workflow matching: finds workflows once for all findings instead of per-finding
// - Limits findings per dispatch to prevent memory exhaustion
// - Proper goroutine recovery to prevent panics from crashing the service
// - Deduplication: each workflow is triggered once per batch (not per finding)
func (d *WorkflowEventDispatcher) DispatchFindingsCreated(ctx context.Context, tenantID shared.ID, findings []*vulnerability.Finding) {
	if len(findings) == 0 {
		return
	}

	// Limit findings to prevent memory exhaustion
	if len(findings) > maxFindingsPerDispatch {
		d.logger.Warn("truncating findings batch for dispatch",
			"original_count", len(findings),
			"max_allowed", maxFindingsPerDispatch,
		)
		findings = findings[:maxFindingsPerDispatch]
	}

	d.logger.Debug("dispatching finding_created events",
		"tenant_id", tenantID,
		"count", len(findings),
	)

	// Dispatch events asynchronously to avoid blocking ingestion
	go func() {
		// Recover from panics to prevent crashing the service
		defer func() {
			if r := recover(); r != nil {
				d.logger.Error("panic recovered in workflow dispatch",
					"tenant_id", tenantID,
					"panic", r,
				)
			}
		}()

		dispatchCtx, cancel := context.WithTimeout(context.Background(), dispatchTimeout)
		defer cancel()

		// OPTIMIZATION: Find matching workflows ONCE for all findings
		// Instead of querying per-finding, we query once and filter locally
		workflows, err := d.findMatchingWorkflows(dispatchCtx, tenantID, workflow.TriggerTypeFindingCreated)
		if err != nil {
			d.logger.Error("failed to find matching workflows",
				"tenant_id", tenantID,
				"error", err,
			)
			return
		}

		if len(workflows) == 0 {
			d.logger.Debug("no matching workflows for finding_created events",
				"tenant_id", tenantID,
				"findings_count", len(findings),
			)
			return
		}

		// OPTIMIZATION: Group findings by matching workflow to deduplicate triggers
		// Each workflow should only be triggered once per batch, with aggregated data
		triggeredWorkflows := make(map[string]bool) // workflow ID -> already triggered
		triggeredCount := 0
		findingsProcessed := 0

		for _, finding := range findings {
			event := FindingEvent{
				TenantID:  tenantID,
				Finding:   finding,
				EventType: workflow.TriggerTypeFindingCreated,
			}

			for _, wf := range workflows {
				// Skip if this workflow was already triggered in this batch
				if triggeredWorkflows[wf.ID.String()] {
					continue
				}

				// Check if finding matches the trigger config filters
				if !d.matchesTriggerFilters(wf, event) {
					continue
				}

				// Build trigger data from finding
				triggerData := d.buildFindingTriggerData(event)

				// Add batch context to trigger data
				triggerData["batch_size"] = len(findings)
				triggerData["batch_index"] = findingsProcessed

				// Trigger the workflow
				_, err := d.service.TriggerWorkflow(dispatchCtx, TriggerWorkflowInput{
					TenantID:    tenantID,
					WorkflowID:  wf.ID,
					TriggerType: workflow.TriggerTypeFindingCreated,
					TriggerData: triggerData,
				})
				if err != nil {
					d.logger.Error("failed to trigger workflow",
						"workflow_id", wf.ID,
						"workflow_name", wf.Name,
						"error", err,
					)
					continue
				}

				// Mark workflow as triggered for this batch
				triggeredWorkflows[wf.ID.String()] = true
				triggeredCount++

				d.logger.Info("workflow triggered by finding_created event",
					"workflow_id", wf.ID,
					"workflow_name", wf.Name,
					"finding_id", finding.ID(),
					"batch_size", len(findings),
				)
			}
			findingsProcessed++
		}

		d.logger.Info("finding_created events dispatched",
			"tenant_id", tenantID,
			"findings_count", len(findings),
			"workflows_matched", len(workflows),
			"workflows_triggered", triggeredCount,
		)
	}()
}

// =============================================================================
// AI Triage Events
// =============================================================================

// AITriageEvent represents an AI triage completion/failure event.
type AITriageEvent struct {
	TenantID   shared.ID
	FindingID  shared.ID
	TriageID   shared.ID
	EventType  workflow.TriggerType // ai_triage_completed or ai_triage_failed
	TriageData map[string]any       // Triage result data
}

// DispatchAITriageEvent dispatches an AI triage event to matching workflows.
func (d *WorkflowEventDispatcher) DispatchAITriageEvent(ctx context.Context, event AITriageEvent) error {
	// Find all active workflows for the tenant with matching trigger type
	workflows, err := d.findMatchingWorkflows(ctx, event.TenantID, event.EventType)
	if err != nil {
		return fmt.Errorf("failed to find matching workflows: %w", err)
	}

	if len(workflows) == 0 {
		d.logger.Debug("no matching workflows found for AI triage event",
			"tenant_id", event.TenantID,
			"event_type", event.EventType,
			"triage_id", event.TriageID,
		)
		return nil
	}

	// Build trigger data from triage event
	triggerData := d.buildAITriageTriggerData(event)

	// Trigger matching workflows
	triggeredCount := 0
	for _, wf := range workflows {
		// Check if triage matches the trigger config filters
		if !d.matchesAITriageTriggerFilters(wf, event) {
			continue
		}

		// Trigger the workflow
		_, err := d.service.TriggerWorkflow(ctx, TriggerWorkflowInput{
			TenantID:    event.TenantID,
			WorkflowID:  wf.ID,
			TriggerType: event.EventType,
			TriggerData: triggerData,
		})
		if err != nil {
			d.logger.Error("failed to trigger workflow for AI triage event",
				"workflow_id", wf.ID,
				"workflow_name", wf.Name,
				"error", err,
			)
			continue
		}

		triggeredCount++
		d.logger.Info("workflow triggered by AI triage event",
			"workflow_id", wf.ID,
			"workflow_name", wf.Name,
			"event_type", event.EventType,
			"triage_id", event.TriageID,
			"finding_id", event.FindingID,
		)
	}

	d.logger.Debug("AI triage event dispatched",
		"event_type", event.EventType,
		"triage_id", event.TriageID,
		"workflows_matched", len(workflows),
		"workflows_triggered", triggeredCount,
	)

	return nil
}

// buildAITriageTriggerData builds trigger data from an AI triage event.
func (d *WorkflowEventDispatcher) buildAITriageTriggerData(event AITriageEvent) map[string]any {
	data := map[string]any{
		"event_type": string(event.EventType),
		"triage_id":  event.TriageID.String(),
		"finding_id": event.FindingID.String(),
	}

	// Include triage result data
	if event.TriageData != nil {
		for k, v := range event.TriageData {
			data[k] = v
		}
	}

	// Ensure finding object exists for downstream actions
	if _, ok := data["finding"]; !ok {
		data["finding"] = map[string]any{
			"id": event.FindingID.String(),
		}
	}

	return data
}

// matchesAITriageTriggerFilters checks if the triage event matches the workflow's trigger filters.
func (d *WorkflowEventDispatcher) matchesAITriageTriggerFilters(wf *workflow.Workflow, event AITriageEvent) bool {
	// Find the trigger node
	var triggerNode *workflow.Node
	for _, node := range wf.Nodes {
		if node.NodeType == workflow.NodeTypeTrigger &&
			node.Config.TriggerType == event.EventType {
			triggerNode = node
			break
		}
	}

	if triggerNode == nil {
		return false
	}

	config := triggerNode.Config.TriggerConfig
	if config == nil {
		// No filters configured - match all
		return true
	}

	// Check severity_filter (from triage result)
	if !d.matchesAITriageSeverityFilter(config, event.TriageData) {
		return false
	}

	// Check risk_score_min filter
	if !d.matchesRiskScoreFilter(config, event.TriageData) {
		return false
	}

	return true
}

// matchesAITriageSeverityFilter checks if triage severity matches the filter.
func (d *WorkflowEventDispatcher) matchesAITriageSeverityFilter(config map[string]any, triageData map[string]any) bool {
	severityFilter, ok := config["severity_filter"]
	if !ok {
		return true // No filter - match all
	}

	severities, ok := severityFilter.([]interface{})
	if !ok || len(severities) == 0 {
		return true
	}

	triageSeverity, _ := triageData["severity_assessment"].(string)
	if triageSeverity == "" {
		return false
	}

	for _, s := range severities {
		if str, ok := s.(string); ok && str == triageSeverity {
			return true
		}
	}
	return false
}

// matchesRiskScoreFilter checks if triage risk score is above minimum threshold.
func (d *WorkflowEventDispatcher) matchesRiskScoreFilter(config map[string]any, triageData map[string]any) bool {
	minScore, ok := config["risk_score_min"]
	if !ok {
		return true // No filter - match all
	}

	minScoreFloat, ok := minScore.(float64)
	if !ok {
		return true
	}

	riskScore, ok := triageData["risk_score"].(float64)
	if !ok {
		return false
	}

	return riskScore >= minScoreFloat
}

// DispatchAITriageCompleted is a convenience method for dispatching ai_triage_completed events.
func (d *WorkflowEventDispatcher) DispatchAITriageCompleted(
	ctx context.Context,
	tenantID, findingID, triageID shared.ID,
	triageData map[string]any,
) {
	// Dispatch asynchronously to avoid blocking
	go func() {
		defer func() {
			if r := recover(); r != nil {
				d.logger.Error("panic recovered in AI triage completed dispatch",
					"triage_id", triageID,
					"panic", r,
				)
			}
		}()

		dispatchCtx, cancel := context.WithTimeout(context.Background(), dispatchTimeout)
		defer cancel()

		event := AITriageEvent{
			TenantID:   tenantID,
			FindingID:  findingID,
			TriageID:   triageID,
			EventType:  workflow.TriggerTypeAITriageCompleted,
			TriageData: triageData,
		}

		if err := d.DispatchAITriageEvent(dispatchCtx, event); err != nil {
			d.logger.Error("failed to dispatch AI triage completed event",
				"triage_id", triageID,
				"error", err,
			)
		}
	}()
}

// DispatchAITriageFailed is a convenience method for dispatching ai_triage_failed events.
func (d *WorkflowEventDispatcher) DispatchAITriageFailed(
	ctx context.Context,
	tenantID, findingID, triageID shared.ID,
	errorMessage string,
) {
	// Dispatch asynchronously to avoid blocking
	go func() {
		defer func() {
			if r := recover(); r != nil {
				d.logger.Error("panic recovered in AI triage failed dispatch",
					"triage_id", triageID,
					"panic", r,
				)
			}
		}()

		dispatchCtx, cancel := context.WithTimeout(context.Background(), dispatchTimeout)
		defer cancel()

		event := AITriageEvent{
			TenantID:  tenantID,
			FindingID: findingID,
			TriageID:  triageID,
			EventType: workflow.TriggerTypeAITriageFailed,
			TriageData: map[string]any{
				"error_message": errorMessage,
			},
		}

		if err := d.DispatchAITriageEvent(dispatchCtx, event); err != nil {
			d.logger.Error("failed to dispatch AI triage failed event",
				"triage_id", triageID,
				"error", err,
			)
		}
	}()
}

// =============================================================================
// Source Filter Validation
// =============================================================================

// ValidateSourceFilter validates that source codes in the filter are valid.
// Uses the FindingSourceCacheService to check against active sources.
func ValidateSourceFilter(ctx context.Context, config map[string]any, cacheService *FindingSourceCacheService) error {
	sourceFilter, ok := config["source_filter"]
	if !ok {
		return nil
	}

	sources, ok := sourceFilter.([]interface{})
	if !ok {
		return fmt.Errorf("source_filter must be an array")
	}

	for _, src := range sources {
		srcStr, ok := src.(string)
		if !ok {
			return fmt.Errorf("source_filter values must be strings")
		}

		valid, err := cacheService.IsValidCode(ctx, srcStr)
		if err != nil {
			return fmt.Errorf("failed to validate source '%s': %w", srcStr, err)
		}
		if !valid {
			// Get valid sources for error message
			allSources, _ := cacheService.GetAll(ctx)
			var validCodes []string
			if allSources != nil {
				for code := range allSources.ByCode {
					validCodes = append(validCodes, code)
				}
			}
			slices.Sort(validCodes)
			return fmt.Errorf("invalid source '%s'; valid sources: %v", srcStr, validCodes)
		}
	}

	return nil
}
