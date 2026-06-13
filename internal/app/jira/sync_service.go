package jira

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/logger"
)

// secretPatterns are masked out of any text pushed to a third-party ticket
// (defense-in-depth, on top of suppressing the raw description for secret
// findings). Conservative, low-false-positive patterns only.
var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),                                                                // AWS access key id
	regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`),                      // JWT
	regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----`), // PEM private key block
}

// secretAssignment matches `password: xxx` / `api_key=xxx` style assignments,
// keeping the key name and redacting only the value.
var secretAssignment = regexp.MustCompile(`(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|authorization|bearer)\b(\s*[:=]\s*|\s+)\S+`)

// redactSecrets masks common secret material in free text before it leaves the
// platform for a third-party ticketing system.
func redactSecrets(text string) string {
	for _, re := range secretPatterns {
		text = re.ReplaceAllString(text, "[REDACTED]")
	}
	text = secretAssignment.ReplaceAllString(text, "$1$2[REDACTED]")
	return text
}

// isSecretFinding reports whether a finding is a leaked-secret/credential
// finding, whose raw description must never be copied verbatim into an external
// ticket (it can contain the secret itself).
func isSecretFinding(f *vulnerability.Finding) bool {
	return f.Source() == vulnerability.FindingSourceSecret ||
		f.FindingType() == vulnerability.FindingTypeSecret
}

// ticketDescription builds the Jira description for a finding. For secret
// findings it deliberately omits the raw finding description (which may embed
// the leaked secret), surfacing only the masked value + location and pointing
// the reader back to the platform. For all other findings it runs the
// description through redactSecrets as defense-in-depth.
func ticketDescription(f *vulnerability.Finding) string {
	var b strings.Builder
	fmt.Fprintf(&b, "**Finding:** %s\n**Severity:** %s\n**Status:** %s\n",
		f.Title(), f.Severity(), f.Status())
	if f.FilePath() != "" {
		fmt.Fprintf(&b, "**Location:** %s:%d\n", f.FilePath(), f.StartLine())
	}

	if isSecretFinding(f) {
		b.WriteString("\nA secret was detected. The value is redacted here for safety — open the finding in the platform for full details.")
		if mv := f.SecretMaskedValue(); mv != "" {
			fmt.Fprintf(&b, "\n**Masked value:** %s", mv)
		}
		return b.String()
	}

	b.WriteString("\n")
	b.WriteString(f.Description())
	return redactSecrets(b.String())
}

// Client defines the interface for Jira REST API operations.
type Client interface {
	CreateIssue(ctx context.Context, input CreateIssueInput) (*CreateIssueResult, error)
	// GetIssueStatus returns the issue's current status name (echo-guard).
	GetIssueStatus(ctx context.Context, issueKey string) (string, error)
	// TransitionToStatus moves the issue to a target status NAME, attaching an
	// optional comment. Returns ErrNoMatchingTransition when the workflow offers
	// no transition to that status (caller falls back to AddComment).
	TransitionToStatus(ctx context.Context, issueKey, targetStatus, comment string) error
	// AddComment posts a comment on the issue.
	AddComment(ctx context.Context, issueKey, body string) error
	TestConnection(ctx context.Context) error
}

// ErrNoMatchingTransition mirrors the infra client's sentinel at the app layer
// (the adapter maps the infra error to this one) so SyncService can fall back to
// a comment without importing the infra package.
var ErrNoMatchingTransition = errors.New("no jira transition to target status")

// ClientResolver builds a Jira Client for a given tenant from that tenant's
// configured ticketing integration (base URL + decrypted credentials). It is
// the outbound counterpart to the inbound webhook path: without a resolver the
// SyncService has no client and CreateTicketFromFinding is inert.
//
// Implementations live in the infra layer (they decrypt credentials and open
// HTTP clients). Returning ErrNoTicketingIntegration means the tenant has no
// usable Jira integration — callers surface that as a 4xx, not a 5xx.
type ClientResolver interface {
	Resolve(ctx context.Context, tenantID shared.ID) (Client, error)
}

// MappingResolver loads a tenant's ticketing MappingConfig (status maps +
// sync_enabled) from its integration config. Counterpart to ClientResolver,
// used by outbound status sync to decide whether/where to push. Returning
// ErrNoTicketingIntegration means the tenant has no Jira integration.
type MappingResolver interface {
	ResolveMapping(ctx context.Context, tenantID shared.ID) (MappingConfig, error)
}

// ErrNoTicketingIntegration is returned by a ClientResolver when the tenant has
// no connected Jira integration to create tickets against. It wraps
// ErrValidation so the HTTP layer maps it to a 400 rather than a 500.
var ErrNoTicketingIntegration = fmt.Errorf("%w: no connected Jira integration configured for this tenant", shared.ErrValidation)

// CreateIssueInput contains fields for creating a Jira issue.
type CreateIssueInput struct {
	ProjectKey  string
	Summary     string
	Description string
	IssueType   string
	Priority    string
	Labels      []string
}

// CreateIssueResult contains the response from creating a Jira issue.
type CreateIssueResult struct {
	ID        string
	Key       string
	BrowseURL string
}

// SyncService handles bidirectional sync between findings and Jira tickets.
//
// Capabilities:
//  1. POST /findings/{id}/link-ticket     — manually link a Jira ticket to a finding
//  2. POST /findings/{id}/create-ticket   — auto-create Jira ticket from finding
//  3. POST /webhooks/incoming/jira        — receive Jira status-change webhooks
type SyncService struct {
	findingRepo vulnerability.FindingRepository
	jiraClient  Client
	logger      *logger.Logger

	// clientResolver builds a per-tenant Jira client on demand. When set, it
	// takes precedence over the static jiraClient (which exists mainly so tests
	// can inject a stub). In production jiraClient is nil and the resolver loads
	// the tenant's integration credentials per request.
	clientResolver ClientResolver

	// mappingResolver loads the per-tenant status maps + sync_enabled flag for
	// outbound sync (SyncFindingStatus). nil → outbound sync is inert.
	mappingResolver MappingResolver

	// B3: optional hook fired when a Jira webhook transitions
	// a finding into `fix_applied`. Wired to the verification-scan
	// trigger to close the "Jira Done → auto rescan" feedback edge
	// without a manual Verify button click.
	postFixHook FixAppliedHook
}

// FixAppliedHook is called when a Jira webhook transitions a finding
// into the fix_applied state. Typical implementation: enqueue a
// verification scan on the finding's asset. Wired via
// SetPostFixAppliedHook; nil → no action (legacy behaviour).
//
// Implementations MUST be idempotent — the B3 rate-limiting guard in
// the implementation layer decides whether to actually enqueue a scan
// (e.g. max one per finding per 24h).
type FixAppliedHook func(ctx context.Context, tenantID, findingID shared.ID) error

// NewSyncService creates a new SyncService.
func NewSyncService(findingRepo vulnerability.FindingRepository, jiraClient Client, log *logger.Logger) *SyncService {
	return &SyncService{
		findingRepo: findingRepo,
		jiraClient:  jiraClient,
		logger:      log.With("service", "jira-sync"),
	}
}

// SetPostFixAppliedHook wires the verification-scan trigger. Safe to
// call after construction; nil value disables the hook.
func (s *SyncService) SetPostFixAppliedHook(h FixAppliedHook) {
	s.postFixHook = h
}

// SetClientResolver wires the per-tenant Jira client resolver. Safe to call
// after construction. Once set, CreateTicketFromFinding resolves a client from
// the tenant's integration instead of relying on the static client.
func (s *SyncService) SetClientResolver(r ClientResolver) {
	s.clientResolver = r
}

// SetMappingResolver wires the per-tenant mapping resolver for outbound status
// sync. Safe to call after construction; nil disables outbound sync.
func (s *SyncService) SetMappingResolver(r MappingResolver) {
	s.mappingResolver = r
}

// SyncFindingStatus is the async entrypoint for outbound status sync: it
// resolves the tenant's mapping then pushes the finding's status to its linked
// Jira issue. No-op when no mapping resolver is wired or the tenant has no Jira
// integration. Called by the jira-sync asynq handler.
func (s *SyncService) SyncFindingStatus(ctx context.Context, tenantID, findingID shared.ID) error {
	if s.mappingResolver == nil {
		return nil
	}
	mapping, err := s.mappingResolver.ResolveMapping(ctx, tenantID)
	if err != nil {
		if errors.Is(err, ErrNoTicketingIntegration) {
			return nil // tenant has no Jira integration — nothing to sync
		}
		return err
	}
	return s.SyncFindingStatusToTicket(ctx, tenantID, findingID, mapping)
}

// resolveClient returns the Jira client to use for a tenant. A statically
// injected client (tests) wins; otherwise the resolver loads the tenant's
// integration. Returns ErrNoTicketingIntegration when neither is available.
func (s *SyncService) resolveClient(ctx context.Context, tenantID shared.ID) (Client, error) {
	if s.jiraClient != nil {
		return s.jiraClient, nil
	}
	if s.clientResolver != nil {
		return s.clientResolver.Resolve(ctx, tenantID)
	}
	return nil, ErrNoTicketingIntegration
}

// CreateTicketInput is the payload for auto-creating a Jira ticket from a finding.
type CreateTicketInput struct {
	TenantID   string `json:"tenant_id"`
	FindingID  string `json:"finding_id"`
	ProjectKey string `json:"project_key"` // e.g. "SEC"
	IssueType  string `json:"issue_type"`  // e.g. "Bug"
}

// jiraBrowseKeyRe extracts a Jira issue key from a browse URL,
// e.g. "https://org.atlassian.net/browse/SEC-123" → "SEC-123".
var jiraBrowseKeyRe = regexp.MustCompile(`/browse/([A-Z][A-Z0-9_]+-\d+)`)

// firstJiraIssueKey returns the first Jira issue key found among a finding's
// work-item URIs, or "" if none is a Jira browse URL.
func firstJiraIssueKey(uris []string) string {
	for _, u := range uris {
		if m := jiraBrowseKeyRe.FindStringSubmatch(u); m != nil {
			return m[1]
		}
	}
	return ""
}

// SyncFindingStatusToTicket pushes a finding's status to its linked Jira issue
// (the outbound half of bidirectional sync — RFC-006 Phase 3). It is a no-op
// unless the integration opted in (mapping.SyncEnabled) and the finding status
// maps to a target Jira status. Echo-safe: it only acts on the OpenCTEM-initiated
// status-change path (the inbound webhook updates findings directly, bypassing
// this), and additionally skips when the issue is already at the target.
//
// On a workflow with no transition to the target, it falls back to a comment so
// the change is visible to a human rather than failing.
func (s *SyncService) SyncFindingStatusToTicket(ctx context.Context, tenantID, findingID shared.ID, mapping MappingConfig) error {
	if !mapping.SyncEnabled {
		return nil // outbound sync is opt-in per integration (default off)
	}

	finding, err := s.findingRepo.GetByID(ctx, tenantID, findingID)
	if err != nil {
		return fmt.Errorf("get finding: %w", err)
	}

	target, ok := mapping.JiraStatusForFinding(string(finding.Status()))
	if !ok {
		return nil // this finding status intentionally does not move the ticket
	}

	issueKey := firstJiraIssueKey(finding.WorkItemURIs())
	if issueKey == "" {
		return nil // finding isn't linked to a Jira issue
	}

	client, err := s.resolveClient(ctx, tenantID)
	if err != nil {
		return err
	}

	// Echo-guard / idempotency: if Jira is already at the target, do nothing.
	if cur, err := client.GetIssueStatus(ctx, issueKey); err == nil && strings.EqualFold(cur, target) {
		return nil
	}

	comment := fmt.Sprintf("OpenCTEM set this finding to %q.", finding.Status())
	if err := client.TransitionToStatus(ctx, issueKey, target, comment); err != nil {
		if errors.Is(err, ErrNoMatchingTransition) {
			// Workflow can't reach the target from its current status — leave a
			// note instead of failing so a human can move the card.
			body := fmt.Sprintf("OpenCTEM marked this finding %q, but no Jira transition to %q is available from its current status — please move it manually.",
				finding.Status(), target)
			if cErr := client.AddComment(ctx, issueKey, body); cErr != nil {
				return fmt.Errorf("comment fallback after no transition: %w", cErr)
			}
			s.logger.Info("jira outbound: no transition to target, commented instead",
				"finding_id", findingID.String(), "issue_key", issueKey, "target", target)
			return nil
		}
		return fmt.Errorf("transition jira issue: %w", err)
	}

	s.logger.Info("jira outbound: synced finding status to ticket",
		"finding_id", findingID.String(), "issue_key", issueKey,
		"finding_status", finding.Status(), "jira_status", target)
	return nil
}

// CreateTicketFromFinding auto-creates a Jira ticket from a finding and links it.
func (s *SyncService) CreateTicketFromFinding(ctx context.Context, input CreateTicketInput) (*TicketInfo, error) {
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

	jiraClient, err := s.resolveClient(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	finding, err := s.findingRepo.GetByID(ctx, tenantID, findingID)
	if err != nil {
		return nil, fmt.Errorf("get finding: %w", err)
	}

	// Idempotency: if this finding already has a ticket in the target project,
	// return it instead of creating a duplicate. Without this, a re-scan,
	// workflow re-trigger, or retry that calls CreateTicketFromFinding again
	// would open a second Jira issue for the same finding. Jira browse URLs are
	// ".../browse/<PROJECT>-<n>", so an existing work-item URL containing
	// "/browse/<ProjectKey>-" means this finding is already ticketed here.
	browseMarker := "/browse/" + input.ProjectKey + "-"
	for _, uri := range finding.WorkItemURIs() {
		if strings.Contains(uri, browseMarker) {
			key := uri[strings.LastIndex(uri, "/")+1:]
			s.logger.Info("jira ticket already exists for finding; skipping create",
				"finding_id", findingID.String(), "ticket_key", key, "project", input.ProjectKey)
			return &TicketInfo{
				FindingID: findingID.String(),
				TicketKey: key,
				TicketURL: uri,
				LinkedAt:  time.Now().UTC(),
			}, nil
		}
	}

	// Map finding severity to Jira priority
	priority := mapSeverityToJiraPriority(string(finding.Severity()))

	issueType := input.IssueType
	if issueType == "" {
		issueType = "Bug"
	}

	result, err := jiraClient.CreateIssue(ctx, CreateIssueInput{
		ProjectKey:  input.ProjectKey,
		Summary:     redactSecrets(fmt.Sprintf("[%s] %s", finding.Severity(), finding.Title())),
		Description: ticketDescription(finding),
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

	return &TicketInfo{
		FindingID: findingID.String(),
		TicketKey: result.Key,
		TicketURL: result.BrowseURL,
		LinkedAt:  time.Now().UTC(),
	}, nil
}

// CreateEpic creates a Jira epic for the given tenant and returns its key and
// browse URL. It is provider-plumbing only — campaign-agnostic — so the
// remediation campaign service can own the "campaign -> epic" orchestration
// (idempotency + persistence) without coupling the jira package to the
// remediation domain. Summary/description are secret-redacted defensively. The
// signature uses primitives so callers can depend on a narrow interface without
// importing the jira package.
func (s *SyncService) CreateEpic(ctx context.Context, tenantID shared.ID, projectKey, summary, description string, labels []string) (issueKey, issueURL string, err error) {
	if projectKey == "" {
		return "", "", fmt.Errorf("%w: project_key is required", shared.ErrValidation)
	}
	client, err := s.resolveClient(ctx, tenantID)
	if err != nil {
		return "", "", err
	}
	result, err := client.CreateIssue(ctx, CreateIssueInput{
		ProjectKey:  projectKey,
		Summary:     redactSecrets(summary),
		Description: redactSecrets(description),
		IssueType:   "Epic",
		Labels:      labels,
	})
	if err != nil {
		return "", "", fmt.Errorf("create jira epic: %w", err)
	}
	s.logger.Info("jira epic created", "tenant_id", tenantID.String(), "issue_key", result.Key, "project", projectKey)
	return result.Key, result.BrowseURL, nil
}

// TransitionEpic moves a campaign's linked Jira epic to a target status NAME,
// best-effort and echo-safe: it skips when the epic is already at the target,
// and falls back to a comment when the workflow offers no transition (so the
// change is visible to a human rather than failing). Campaign-agnostic plumbing
// — the caller decides when/where to call it.
func (s *SyncService) TransitionEpic(ctx context.Context, tenantID shared.ID, issueKey, targetStatus, comment string) error {
	if issueKey == "" || targetStatus == "" {
		return nil
	}
	client, err := s.resolveClient(ctx, tenantID)
	if err != nil {
		return err
	}

	// Echo-guard: already at the target -> nothing to do.
	if cur, gerr := client.GetIssueStatus(ctx, issueKey); gerr == nil && strings.EqualFold(cur, targetStatus) {
		return nil
	}

	if terr := client.TransitionToStatus(ctx, issueKey, targetStatus, comment); terr != nil {
		if errors.Is(terr, ErrNoMatchingTransition) {
			body := fmt.Sprintf("OpenCTEM wanted to move this epic to %q but no transition is available from its current status — please move it manually.", targetStatus)
			if cerr := client.AddComment(ctx, issueKey, body); cerr != nil {
				return fmt.Errorf("comment fallback after no transition: %w", cerr)
			}
			s.logger.Info("jira epic outbound: no transition to target, commented instead", "issue_key", issueKey, "target", targetStatus)
			return nil
		}
		return fmt.Errorf("transition jira epic: %w", terr)
	}
	s.logger.Info("jira epic outbound: synced campaign status to epic", "issue_key", issueKey, "target", targetStatus)
	return nil
}

// mapSeverityToJiraPriority maps finding severity to Jira priority name using
// the default mapping. Per-integration overrides are applied via MappingConfig
// (see mapping.go); this keeps callers that have no integration context working.
func mapSeverityToJiraPriority(severity string) string {
	return DefaultMappingConfig().PriorityForSeverity(severity)
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
func (s *SyncService) LinkTicket(ctx context.Context, input LinkTicketInput) error {
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
func (s *SyncService) UnlinkTicket(ctx context.Context, tenantIDStr, findingIDStr, ticketURL string) error {
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

// WebhookPayload is the envelope sent by Jira issue-updated webhooks.
// See https://developer.atlassian.com/cloud/jira/platform/webhooks/
type WebhookPayload struct {
	WebhookEvent string       `json:"webhookEvent"` // "jira:issue_updated"
	Issue        WebhookIssue `json:"issue"`
	Changelog    *Changelog   `json:"changelog,omitempty"`
}

// WebhookIssue represents the issue block inside a Jira webhook payload.
type WebhookIssue struct {
	Key    string                 `json:"key"`  // e.g. "PROJ-123"
	Self   string                 `json:"self"` // e.g. "https://myorg.atlassian.net/rest/api/2/issue/10001"
	Fields map[string]interface{} `json:"fields"`
}

// Changelog carries the before/after values of changed fields.
type Changelog struct {
	Items []ChangeItem `json:"items"`
}

// ChangeItem is one entry in the changelog.
type ChangeItem struct {
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
func (s *SyncService) HandleJiraWebhook(ctx context.Context, tenantID shared.ID, payload WebhookPayload) error {
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

	// B3: fire the verification-scan hook on transition to
	// fix_applied. This closes the "Jira Done → auto rescan" feedback
	// edge. Hook errors are logged but not propagated — the Jira ACK
	// must succeed regardless (Jira retries aggressively on non-2xx).
	if newFindingStatus == vulnerability.FindingStatusFixApplied && s.postFixHook != nil {
		if err := s.postFixHook(ctx, tenantID, finding.ID()); err != nil {
			s.logger.Warn("post-fix hook failed; finding status still updated",
				"finding_id", finding.ID().String(), "error", err)
		}
	}
	return nil
}

// mapJiraStatusToFinding maps a Jira status name to a FindingStatus using the
// default mapping. Per-integration overrides are applied via MappingConfig (see
// mapping.go); this keeps callers without integration context working.
// Returns (status, true) when a mapping exists, (_, false) otherwise.
func mapJiraStatusToFinding(jiraStatus string) (vulnerability.FindingStatus, bool) {
	return DefaultMappingConfig().FindingStatusForJira(jiraStatus)
}

// deriveJiraTicketURL builds the canonical browse URL for a Jira issue.
// It prefers payload.Issue.Self (REST API URL) but converts it to the browse URL
// so it matches what users paste when linking tickets.
func deriveJiraTicketURL(issue WebhookIssue) string {
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

// TicketInfo is returned by LinkTicket to the HTTP handler for the response body.
type TicketInfo struct {
	FindingID string    `json:"finding_id"`
	TicketKey string    `json:"ticket_key"`
	TicketURL string    `json:"ticket_url"`
	LinkedAt  time.Time `json:"linked_at"`
}
