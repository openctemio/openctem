package app

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/logger"
)

// JiraClient defines the interface for Jira REST API operations.
type JiraClient interface {
	CreateIssue(ctx context.Context, input JiraCreateIssueInput) (*JiraCreateIssueResult, error)
	TestConnection(ctx context.Context) error
}

// JiraCreateIssueInput contains fields for creating a Jira issue.
type JiraCreateIssueInput struct {
	ProjectKey  string
	Summary     string
	Description string
	IssueType   string
	Priority    string
	Labels      []string
}

// JiraCreateIssueResult contains the response from creating a Jira issue.
type JiraCreateIssueResult struct {
	ID        string
	Key       string
	BrowseURL string
}

// JiraSyncService handles bidirectional sync between findings and Jira tickets.
//
// Capabilities:
//  1. POST /findings/{id}/link-ticket     — manually link a Jira ticket to a finding
//  2. POST /findings/{id}/create-ticket   — auto-create Jira ticket from finding
//  3. POST /webhooks/incoming/jira        — receive Jira status-change webhooks
type JiraSyncService struct {
	findingRepo vulnerability.FindingRepository
	jiraClient  JiraClient
	logger      *logger.Logger
}

// NewJiraSyncService creates a new JiraSyncService.
func NewJiraSyncService(findingRepo vulnerability.FindingRepository, jiraClient JiraClient, log *logger.Logger) *JiraSyncService {
	return &JiraSyncService{
		findingRepo: findingRepo,
		jiraClient:  jiraClient,
		logger:      log.With("service", "jira-sync"),
	}
}

// CreateTicketInput is the payload for auto-creating a Jira ticket from a finding.
type CreateTicketInput struct {
	TenantID   string `json:"tenant_id"`
	FindingID  string `json:"finding_id"`
	ProjectKey string `json:"project_key"` // e.g. "SEC"
	IssueType  string `json:"issue_type"`  // e.g. "Bug"
}

// CreateTicketFromFinding auto-creates a Jira ticket from a finding and links it.
func (s *JiraSyncService) CreateTicketFromFinding(ctx context.Context, input CreateTicketInput) (*JiraTicketInfo, error) {
	if s.jiraClient == nil {
		return nil, fmt.Errorf("%w: Jira integration not configured", shared.ErrValidation)
	}
	if input.ProjectKey == "" {
		return nil, fmt.Errorf("%w: project_key is required", shared.ErrValidation)
	}

	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant ID", shared.ErrValidation)
	}
	findingID, err := shared.IDFromString(input.FindingID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid finding ID", shared.ErrValidation)
	}

	finding, err := s.findingRepo.GetByID(ctx, tenantID, findingID)
	if err != nil {
		return nil, fmt.Errorf("get finding: %w", err)
	}

	// Map finding severity to Jira priority
	priority := mapSeverityToJiraPriority(string(finding.Severity()))

	issueType := input.IssueType
	if issueType == "" {
		issueType = "Bug"
	}

	description := fmt.Sprintf("**Finding:** %s\n**Severity:** %s\n**Status:** %s\n\n%s",
		finding.Title(), finding.Severity(), finding.Status(), finding.Description())

	result, err := s.jiraClient.CreateIssue(ctx, JiraCreateIssueInput{
		ProjectKey:  input.ProjectKey,
		Summary:     fmt.Sprintf("[%s] %s", finding.Severity(), finding.Title()),
		Description: description,
		IssueType:   issueType,
		Priority:    priority,
		Labels:      []string{"openctem", "security", string(finding.Severity())},
	})
	if err != nil {
		return nil, fmt.Errorf("create jira ticket: %w", err)
	}

	// Auto-link the created ticket to the finding
	finding.AddWorkItemURI(result.BrowseURL)
	if err := s.findingRepo.UpdateWorkItemURIs(ctx, tenantID, findingID, finding.WorkItemURIs()); err != nil {
		s.logger.Error("failed to link created ticket to finding", "error", err, "ticket_key", result.Key)
	}

	s.logger.Info("jira ticket created from finding",
		"finding_id", findingID.String(),
		"ticket_key", result.Key,
		"ticket_url", result.BrowseURL,
	)

	return &JiraTicketInfo{
		FindingID: findingID.String(),
		TicketKey: result.Key,
		TicketURL: result.BrowseURL,
		LinkedAt:  time.Now().UTC(),
	}, nil
}

// mapSeverityToJiraPriority maps finding severity to Jira priority name.
func mapSeverityToJiraPriority(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "Highest"
	case "high":
		return "High"
	case "medium":
		return "Medium"
	case "low":
		return "Low"
	default:
		return "Medium"
	}
}

// LinkTicketInput is the payload for linking a Jira ticket to a finding.
type LinkTicketInput struct {
	TenantID  string `json:"tenant_id"`
	FindingID string `json:"finding_id"`
	TicketKey string `json:"ticket_key"` // e.g. "PROJ-123"
	TicketURL string `json:"ticket_url"` // e.g. "https://myorg.atlassian.net/browse/PROJ-123"
}

// LinkTicket adds a Jira ticket reference to a finding's work_item_uris.
// Idempotent — re-adding the same URL is a no-op at the domain level.
func (s *JiraSyncService) LinkTicket(ctx context.Context, input LinkTicketInput) error {
	if strings.TrimSpace(input.TicketKey) == "" {
		return fmt.Errorf("%w: ticket_key is required", shared.ErrValidation)
	}
	if strings.TrimSpace(input.TicketURL) == "" {
		return fmt.Errorf("%w: ticket_url is required", shared.ErrValidation)
	}

	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return fmt.Errorf("%w: invalid tenant ID", shared.ErrValidation)
	}

	findingID, err := shared.IDFromString(input.FindingID)
	if err != nil {
		return fmt.Errorf("%w: invalid finding ID", shared.ErrValidation)
	}

	finding, err := s.findingRepo.GetByID(ctx, tenantID, findingID)
	if err != nil {
		return fmt.Errorf("get finding: %w", err)
	}

	// Add only if not already present (domain method is idempotent).
	finding.AddWorkItemURI(input.TicketURL)

	if err := s.findingRepo.UpdateWorkItemURIs(ctx, tenantID, findingID, finding.WorkItemURIs()); err != nil {
		return fmt.Errorf("persist ticket link: %w", err)
	}

	s.logger.Info("jira ticket linked to finding",
		"finding_id", findingID.String(),
		"ticket_key", input.TicketKey,
		"ticket_url", input.TicketURL,
	)
	return nil
}

// UnlinkTicket removes a Jira ticket reference from a finding.
func (s *JiraSyncService) UnlinkTicket(ctx context.Context, tenantIDStr, findingIDStr, ticketURL string) error {
	tenantID, err := shared.IDFromString(tenantIDStr)
	if err != nil {
		return fmt.Errorf("%w: invalid tenant ID", shared.ErrValidation)
	}
	findingID, err := shared.IDFromString(findingIDStr)
	if err != nil {
		return fmt.Errorf("%w: invalid finding ID", shared.ErrValidation)
	}

	finding, err := s.findingRepo.GetByID(ctx, tenantID, findingID)
	if err != nil {
		return fmt.Errorf("get finding: %w", err)
	}

	existing := finding.WorkItemURIs()
	updated := make([]string, 0, len(existing))
	for _, u := range existing {
		if u != ticketURL {
			updated = append(updated, u)
		}
	}

	if err := s.findingRepo.UpdateWorkItemURIs(ctx, tenantID, findingID, updated); err != nil {
		return fmt.Errorf("persist ticket unlink: %w", err)
	}

	s.logger.Info("jira ticket unlinked from finding",
		"finding_id", findingID.String(),
		"ticket_url", ticketURL,
	)
	return nil
}

// JiraWebhookPayload is the envelope sent by Jira issue-updated webhooks.
// See https://developer.atlassian.com/cloud/jira/platform/webhooks/
type JiraWebhookPayload struct {
	WebhookEvent string            `json:"webhookEvent"` // "jira:issue_updated"
	Issue        JiraWebhookIssue  `json:"issue"`
	Changelog    *JiraChangelog    `json:"changelog,omitempty"`
}

// JiraWebhookIssue represents the issue block inside a Jira webhook payload.
type JiraWebhookIssue struct {
	Key    string                 `json:"key"`  // e.g. "PROJ-123"
	Self   string                 `json:"self"` // e.g. "https://myorg.atlassian.net/rest/api/2/issue/10001"
	Fields map[string]interface{} `json:"fields"`
}

// JiraChangelog carries the before/after values of changed fields.
type JiraChangelog struct {
	Items []JiraChangeItem `json:"items"`
}

// JiraChangeItem is one entry in the changelog.
type JiraChangeItem struct {
	Field      string `json:"field"`
	FromString string `json:"fromString"`
	ToString   string `json:"toString"`
}

// HandleJiraWebhook processes an inbound Jira webhook and syncs finding status.
//
// Status mapping:
//
//	Jira "In Progress"  → finding "in_progress"
//	Jira "In Review"    → finding "in_progress"
//	Jira "Done"         → finding "fix_applied"  (triggers verification flow)
//	Jira "Resolved"     → finding "fix_applied"
//	Jira "Closed"       → finding "fix_applied"
func (s *JiraSyncService) HandleJiraWebhook(ctx context.Context, tenantID shared.ID, payload JiraWebhookPayload) error {
	if payload.Changelog == nil {
		// No changes — nothing to sync.
		return nil
	}

	// Find the status transition in the changelog.
	newJiraStatus := ""
	for _, item := range payload.Changelog.Items {
		if strings.EqualFold(item.Field, "status") {
			newJiraStatus = item.ToString
			break
		}
	}
	if newJiraStatus == "" {
		// Webhook is for a non-status change (field update, comment, etc.) — ignore.
		return nil
	}

	newFindingStatus, ok := mapJiraStatusToFinding(newJiraStatus)
	if !ok {
		s.logger.Debug("jira status has no finding mapping — ignored",
			"jira_status", newJiraStatus,
			"issue_key", payload.Issue.Key,
		)
		return nil
	}

	// Derive the ticket URL from the issue self link or fallback to Atlassian browse URL.
	ticketURL := deriveJiraTicketURL(payload.Issue)

	// Look up finding by work item URI.
	finding, err := s.findingRepo.GetByWorkItemURI(ctx, tenantID, ticketURL)
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			// No finding linked to this ticket — silently ignore.
			s.logger.Debug("no finding linked to jira ticket",
				"ticket_url", ticketURL,
				"issue_key", payload.Issue.Key,
			)
			return nil
		}
		return fmt.Errorf("lookup finding by work item URI: %w", err)
	}

	// Apply the status transition if valid.
	if err := finding.TransitionStatus(newFindingStatus, "", nil); err != nil {
		s.logger.Warn("jira webhook: finding status transition not allowed",
			"finding_id", finding.ID().String(),
			"current_status", finding.Status(),
			"target_status", newFindingStatus,
			"jira_status", newJiraStatus,
			"error", err,
		)
		// Not a hard error — the transition might be blocked (e.g., false_positive).
		return nil
	}

	if err := s.findingRepo.Update(ctx, finding); err != nil {
		return fmt.Errorf("update finding status from jira webhook: %w", err)
	}

	s.logger.Info("jira webhook synced finding status",
		"finding_id", finding.ID().String(),
		"issue_key", payload.Issue.Key,
		"jira_status", newJiraStatus,
		"finding_status", newFindingStatus,
	)
	return nil
}

// mapJiraStatusToFinding maps a Jira status name to a FindingStatus.
// Returns (status, true) when a mapping exists, (_, false) otherwise.
func mapJiraStatusToFinding(jiraStatus string) (vulnerability.FindingStatus, bool) {
	normalized := strings.ToLower(strings.TrimSpace(jiraStatus))
	switch normalized {
	case "in progress", "in review", "in development", "open":
		return vulnerability.FindingStatusInProgress, true
	case "done", "resolved", "closed", "completed", "fixed":
		return vulnerability.FindingStatusFixApplied, true
	case "to do", "backlog", "reopened":
		return vulnerability.FindingStatusConfirmed, true
	default:
		return "", false
	}
}

// deriveJiraTicketURL builds the canonical browse URL for a Jira issue.
// It prefers payload.Issue.Self (REST API URL) but converts it to the browse URL
// so it matches what users paste when linking tickets.
func deriveJiraTicketURL(issue JiraWebhookIssue) string {
	if issue.Self != "" {
		// Convert REST API URL to browse URL:
		// https://myorg.atlassian.net/rest/api/2/issue/10001 →
		// https://myorg.atlassian.net/browse/PROJ-123
		//
		// Split on "/rest/" and reconstruct.
		if idx := strings.Index(issue.Self, "/rest/"); idx > 0 && issue.Key != "" {
			base := issue.Self[:idx]
			return base + "/browse/" + issue.Key
		}
	}
	return issue.Key
}

// JiraTicketInfo is returned by LinkTicket to the HTTP handler for the response body.
type JiraTicketInfo struct {
	FindingID  string    `json:"finding_id"`
	TicketKey  string    `json:"ticket_key"`
	TicketURL  string    `json:"ticket_url"`
	LinkedAt   time.Time `json:"linked_at"`
}
