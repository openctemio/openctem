package ticketing

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/internal/infra/scm"
	"github.com/openctemio/openctem/api/pkg/brand"
	"github.com/openctemio/openctem/api/pkg/crypto"
	"github.com/openctemio/openctem/api/pkg/domain/integration"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/safetext"
)

// ErrNoGitHubIntegration is returned when the tenant has no connected GitHub
// integration whose credentials can be used to create issues. It wraps
// shared.ErrValidation so the HTTP layer maps it to 400.
var ErrNoGitHubIntegration = fmt.Errorf("%w: no connected GitHub integration is configured for this tenant", shared.ErrValidation)

// TicketInfo describes a ticket linked to a finding. Mirrors the Jira
// SyncService.TicketInfo so the HTTP response shape is identical across
// providers.
type TicketInfo struct {
	FindingID string    `json:"finding_id"`
	TicketKey string    `json:"ticket_key"`
	TicketURL string    `json:"ticket_url"`
	LinkedAt  time.Time `json:"linked_at"`
}

// GitHubTicketInput is the payload for auto-creating a GitHub issue from a finding.
type GitHubTicketInput struct {
	TenantID  string
	FindingID string
	Owner     string
	Repo      string
	// Route is the path the request came by (set by server callers only);
	// the zero value is the generic finding route.
	Route Route
}

// issueCreator is the minimal slice of the SCM GitHub client the service needs.
// Defining it here (rather than depending on the concrete *scm.GitHubClient)
// keeps CreateTicketFromFinding unit-testable without real HTTP: tests inject a
// fake creator via clientFactory. The production factory builds an
// *scm.GitHubClient, which satisfies this interface.
type issueCreator interface {
	CreateIssue(ctx context.Context, owner, repo, title, body string, labels []string) (int, string, error)
	// UpdateIssueState sets an issue's state ("open"/"closed") for outbound
	// finding→issue status sync.
	UpdateIssueState(ctx context.Context, owner, repo string, number int, state string) error
}

// githubIssueURLRe extracts owner/repo/number from a GitHub issue browse URL,
// e.g. "https://github.com/octo/repo/issues/42" → octo, repo, 42. Works for
// GitHub Enterprise hosts too (it only anchors on the /{owner}/{repo}/issues/N tail).
var githubIssueURLRe = regexp.MustCompile(`/([^/]+)/([^/]+)/issues/(\d+)(?:[/#?].*)?$`)

// GitHubTicketService creates GitHub issues from findings and links them.
//
// This is the GitHub analog of jira.SyncService.CreateTicketFromFinding:
// resolve the tenant's GitHub integration → load finding → idempotency via
// work_item_uris → create issue → link the issue URL back onto the finding.
//
// Inbound issue events (HandleIssueEvent) move linked findings through the
// finding service rules; see docs/architecture/github-issue-ticketing.md.
type GitHubTicketService struct {
	findingRepo     vulnerability.FindingRepository
	integrationRepo integration.Repository
	decrypt         func(string) (string, error)
	logger          *logger.Logger

	// clientFactory builds an issueCreator from a resolved access token and
	// base URL. Overridable in tests; defaults to the real SCM client.
	clientFactory func(token, baseURL string) (issueCreator, error)

	// applier moves linked findings through the finding service rules;
	// workItems finds them; fixClaimHook queues the proof of fix.
	applier      inboundApplier
	workItems    workItemFindingLister
	fixClaimHook FixClaimHook

	// egress is the outbound gate (egress.go); nil refuses pentest content.
	egress *EgressGate
}

// SetEgressGate wires the outbound gate.
func (s *GitHubTicketService) SetEgressGate(g *EgressGate) { s.egress = g }

// NewGitHubTicketService constructs a GitHubTicketService.
//
// The encryptor is used to decrypt the integration's stored credential the
// same way the SCM integration layer does (IntegrationService.decryptCredentials):
// encryptor.DecryptString; a value that does not decrypt is skipped, never
// used as is. If encryptor is nil, credentials are treated as plaintext.
func NewGitHubTicketService(
	findingRepo vulnerability.FindingRepository,
	integrationRepo integration.Repository,
	encryptor crypto.Encryptor,
	log *logger.Logger,
) *GitHubTicketService {
	decrypt := func(s string) (string, error) { return s, nil }
	if encryptor != nil {
		decrypt = encryptor.DecryptString
	}
	return &GitHubTicketService{
		findingRepo:     findingRepo,
		integrationRepo: integrationRepo,
		decrypt:         decrypt,
		logger:          log.With("service", "github-ticket"),
		clientFactory: func(token, baseURL string) (issueCreator, error) {
			return scm.NewGitHubClient(scm.Config{
				Provider:    scm.ProviderGitHub,
				AccessToken: token,
				BaseURL:     baseURL,
				AuthType:    scm.AuthTypeToken,
			})
		},
	}
}

// CreateTicketFromFinding creates a GitHub issue from a finding and links it.
func (s *GitHubTicketService) CreateTicketFromFinding(ctx context.Context, in GitHubTicketInput) (*TicketInfo, error) {
	owner := strings.TrimSpace(in.Owner)
	repo := strings.TrimSpace(in.Repo)
	if owner == "" {
		return nil, fmt.Errorf("%w: owner is required", shared.ErrValidation)
	}
	if repo == "" {
		return nil, fmt.Errorf("%w: repo is required", shared.ErrValidation)
	}

	tenantID, err := shared.IDFromString(in.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant ID", shared.ErrValidation)
	}
	findingID, err := shared.IDFromString(in.FindingID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid finding ID", shared.ErrValidation)
	}

	// Resolve the tenant's GitHub integration credential (tenant-scoped).
	token, baseURL, err := s.resolveCredential(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	finding, err := s.findingRepo.GetByID(ctx, tenantID, findingID)
	if err != nil {
		return nil, fmt.Errorf("get finding: %w", err)
	}
	if err := s.egress.Check(ctx, tenantID, in.Route, finding); err != nil {
		return nil, err
	}

	// Idempotency: if a GitHub issue for THIS repo is already linked, return it
	// instead of creating a duplicate.
	marker := fmt.Sprintf("/%s/%s/issues/", owner, repo)
	for _, uri := range finding.WorkItemURIs() {
		if strings.Contains(uri, marker) {
			s.logger.Info("github issue already linked to finding; returning existing link",
				"finding_id", findingID.String(), "ticket_url", uri)
			return &TicketInfo{
				FindingID: findingID.String(),
				TicketKey: issueKeyFromURL(uri),
				TicketURL: uri,
				LinkedAt:  time.Now().UTC(),
			}, nil
		}
	}

	client, err := s.clientFactory(token, baseURL)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to build GitHub client: %v", shared.ErrValidation, err)
	}

	title := issueTitle(finding)
	body := buildIssueBody(finding)
	labels := []string{"openctem", "security", string(finding.Severity())}

	number, htmlURL, err := client.CreateIssue(ctx, owner, repo, title, body, labels)
	if err != nil {
		return nil, fmt.Errorf("create github issue: %w", err)
	}

	// Auto-link the created issue back onto the finding. A persist failure is
	// logged but does NOT fail the operation — the issue already exists, and
	// re-running is idempotent (matches jira.SyncService behaviour).
	finding.AddWorkItemURI(htmlURL)
	if err := s.findingRepo.UpdateWorkItemURIs(ctx, tenantID, findingID, finding.WorkItemURIs()); err != nil {
		s.logger.Error("failed to link created github issue to finding",
			"error", err, "finding_id", findingID.String(), "ticket_url", htmlURL)
	}

	s.logger.Info("github issue created from finding",
		"finding_id", findingID.String(),
		"ticket_url", htmlURL,
	)

	return &TicketInfo{
		FindingID: findingID.String(),
		TicketKey: fmt.Sprintf("#%d", number),
		TicketURL: htmlURL,
		LinkedAt:  time.Now().UTC(),
	}, nil
}

// SyncFindingStatus is the outbound half of GitHub Issues sync: when a finding's
// status changes in OpenCTEM, close (resolved/closed-category) or reopen
// (active) its linked GitHub issue. No-op when the finding has no linked GitHub
// issue. Best-effort; enqueued from the same status-change hook as Jira and
// runs in the background worker.
func (s *GitHubTicketService) SyncFindingStatus(ctx context.Context, tenantID, findingID shared.ID) error {
	finding, err := s.findingRepo.GetByID(ctx, tenantID, findingID)
	if err != nil {
		return fmt.Errorf("get finding: %w", err)
	}

	owner, repo, number, issueURL, ok := firstGitHubIssue(finding.WorkItemURIs())
	if !ok {
		return nil // finding isn't linked to a GitHub issue — nothing to sync
	}
	if err := s.egress.Check(ctx, tenantID, RouteStatusSync, finding); err != nil {
		var refused *EgressRefusedError
		if errors.As(err, &refused) {
			s.logger.Info("github outbound: push skipped by the outbound gate",
				"finding_id", findingID.String(), "reason", string(refused.Reason))
			return nil
		}
		return err
	}

	desired := "open"
	if finding.Status().IsClosed() {
		desired = "closed"
	}

	token, baseURL, err := s.resolveCredential(ctx, tenantID)
	if err != nil {
		return err
	}
	client, err := s.clientFactory(token, baseURL)
	if err != nil {
		return fmt.Errorf("build github client: %w", err)
	}
	if err := client.UpdateIssueState(ctx, owner, repo, number, desired); err != nil {
		return fmt.Errorf("update github issue state: %w", err)
	}
	s.logger.Info("github outbound: synced finding status to issue",
		"finding_id", findingID.String(), "issue_url", issueURL, "state", desired)
	return nil
}

// firstGitHubIssue returns the owner/repo/number of the first GitHub issue URL
// among a finding's work-item URIs, or ok=false when none is a GitHub issue.
func firstGitHubIssue(uris []string) (owner, repo string, number int, url string, ok bool) {
	for _, u := range uris {
		m := githubIssueURLRe.FindStringSubmatch(u)
		if m == nil {
			continue
		}
		n, err := strconv.Atoi(m[3])
		if err != nil {
			continue
		}
		return m[1], m[2], n, u, true
	}
	return "", "", 0, "", false
}

// resolveCredential lists the tenant's GitHub integrations, picks the first
// connected one, and decrypts its stored credential. This mirrors how the SCM
// layer resolves the access token (IntegrationService.decryptCredentials):
// intg.CredentialsEncrypted() → decrypt; an undecryptable value is skipped.
func (s *GitHubTicketService) resolveCredential(ctx context.Context, tenantID shared.ID) (token, baseURL string, err error) {
	intgs, err := s.integrationRepo.ListByProvider(ctx, tenantID, integration.ProviderGitHub)
	if err != nil {
		return "", "", fmt.Errorf("list github integrations: %w", err)
	}

	for _, intg := range intgs {
		if intg.Status() != integration.StatusConnected {
			continue
		}
		encrypted := intg.CredentialsEncrypted()
		if encrypted == "" {
			continue
		}
		decrypted, decErr := s.decrypt(encrypted)
		if decErr != nil {
			// Fail closed: never send an undecryptable value upstream.
			s.logger.Warn("github credential cannot be decrypted; skipping the integration",
				"tenant_id", tenantID.String(), "integration_id", intg.ID().String())
			continue
		}
		if strings.TrimSpace(decrypted) == "" {
			continue
		}
		return decrypted, intg.BaseURL(), nil
	}

	return "", "", ErrNoGitHubIntegration
}

// issueTitle is the GitHub issue title (plain text, at most 256 characters):
// secret-redacted, cleaned of control and bidi characters, one line, capped.
func issueTitle(finding *vulnerability.Finding) string {
	return safetext.SingleLine(safetext.RedactSecrets(fmt.Sprintf("[%s] %s", finding.Severity(), OutboundTitle(finding))), safetext.MaxTitleRunes)
}

// buildIssueBody renders the markdown body of the issue, mirroring the
// semantics of the Jira description. What text may leave is the outbound
// gate's decision (FindingContent): a secret finding sends its location only
// (no description, preview, snippet, fingerprint or commit context), a
// finding that exposes data sends no free text at all.
//
// Every value from the finding is attacker-influenced (a scanned page, a file
// path, a sensor report). One-line values go into code spans and the
// description into a fenced code block, inside which GitHub renders no links,
// images, HTML, @mentions or #references (RFC-040 §5.4).
func buildIssueBody(finding *vulnerability.Finding) string {
	var b strings.Builder

	// Severity and status are domain enums, not scanner text.
	fmt.Fprintf(&b, "**Severity:** %s\n", finding.Severity())
	fmt.Fprintf(&b, "**Status:** %s\n", finding.Status())

	if loc := findingLocation(finding); loc != "" {
		fmt.Fprintf(&b, "**Location:** %s\n", safetext.MarkdownInline(safetext.RedactSecrets(loc), safetext.MaxInlineRunes))
	}
	b.WriteString("\n")

	switch FindingContent(finding) {
	case ContentSecret:
		b.WriteString("> A secret/credential was detected. Its value is not sent to trackers.\n\n")
		b.WriteString("Open the finding in " + brand.Name() + " for full details.\n")
		appendMobilizationBrief(&b, finding)
		return b.String()
	case ContentPersonalData:
		b.WriteString("> This finding exposes data. Its details are not sent to trackers.\n\n")
		b.WriteString("Open the finding in " + brand.Name() + " for full details.\n")
		return b.String()
	case ContentFull:
	}

	if desc := strings.TrimSpace(finding.Description()); desc != "" {
		b.WriteString(safetext.MarkdownBlock(safetext.RedactSecrets(desc), safetext.MaxDescriptionRunes))
		b.WriteString("\n")
	}

	appendMobilizationBrief(&b, finding)
	return b.String()
}

// appendMobilizationBrief appends the CTEM Mobilization brief (definition of
// done + acceptable fixes) to the issue body when the finding carries one. The
// brief is written by people with write access, so it is treated like any
// other text that leaves the platform: secret-redacted, capped, and placed in a
// fenced block so it cannot add links, images, HTML or @mentions.
func appendMobilizationBrief(b *strings.Builder, finding *vulnerability.Finding) {
	brief := strings.TrimSpace(finding.Remediation().MobilizationBrief())
	if brief == "" {
		return
	}
	b.WriteString("\n")
	b.WriteString(safetext.MarkdownBlock(safetext.RedactSecrets(brief), safetext.MaxBriefRunes))
	b.WriteString("\n")
}

// findingLocation builds a "file:line" location string when available.
func findingLocation(finding *vulnerability.Finding) string {
	path := strings.TrimSpace(finding.FilePath())
	if path == "" {
		return ""
	}
	if line := finding.StartLine(); line > 0 {
		return fmt.Sprintf("%s:%d", path, line)
	}
	return path
}

// issueKeyFromURL extracts a "#<number>" key from a GitHub issue URL, falling
// back to the raw URL when the trailing segment is not numeric.
func issueKeyFromURL(uri string) string {
	idx := strings.LastIndex(uri, "/")
	if idx < 0 || idx == len(uri)-1 {
		return uri
	}
	num := uri[idx+1:]
	if num == "" {
		return uri
	}
	for _, r := range num {
		if r < '0' || r > '9' {
			return uri
		}
	}
	return "#" + num
}

// compile-time assurance that the real SCM client satisfies issueCreator.
var _ issueCreator = (*scm.GitHubClient)(nil)

// GitHubIssueEvent is the part of a verified GitHub "issues" delivery the
// inbound sync uses.
type GitHubIssueEvent struct {
	// Action is the delivery's action ("closed", "reopened", ...).
	Action string
	// IssueURL is the issue's browse URL (issue.html_url), the key findings
	// are linked by.
	IssueURL string
	// StateReason is issue.state_reason on a close: "completed",
	// "not_planned" or "duplicate" ("" from a server that does not send it).
	StateReason string
	// Sender is the GitHub login that made the change (sender.login),
	// recorded as the tracker account in the timeline.
	Sender string
}

// inboundApplier applies a linked ticket's status, or its request for a
// disposition, through the finding service rules: tenant and data scope,
// the transition map, the pentest and approval gates, "mark fixed" with the
// integration as the actor (the server wires an adapter over
// *finding.VulnerabilityService; this package cannot import the finding
// service, which reaches the integration service and so this package).
type inboundApplier interface {
	ApplyTicketStatus(ctx context.Context, tenantID shared.ID, findingIDs []shared.ID,
		target vulnerability.FindingStatus, integration, ref, externalActor string) (*InboundStatusOutcome, error)
	RequestTicketDisposition(ctx context.Context, tenantID shared.ID, findingIDs []shared.ID,
		target vulnerability.FindingStatus, integration, ref, externalActor string) (*InboundRequestOutcome, error)
}

// InboundRefusal is a linked finding the rules kept where it is, with the
// reason.
type InboundRefusal struct {
	FindingID string
	Reason    string
}

// InboundStatusOutcome is the result of applying an issue's status.
type InboundStatusOutcome struct {
	Applied []shared.ID
	Refused []InboundRefusal
}

// InboundRequestOutcome is the result of requesting a disposition.
type InboundRequestOutcome struct {
	Requested []shared.ID
	Pending   []shared.ID
	Refused   []InboundRefusal
}

// workItemFindingLister lists every finding of the tenant linked to an
// issue URL (one issue may track several findings).
type workItemFindingLister interface {
	ListIDsByWorkItemURI(ctx context.Context, tenantID shared.ID, uri string, limit int) ([]shared.ID, error)
}

// FixClaimHook is called for each finding a GitHub close claimed fixed; it
// queues the proof of fix (a retest or a covered scan). It must be
// idempotent.
type FixClaimHook func(ctx context.Context, tenantID, findingID shared.ID) error

// maxInboundFindings bounds the findings one issue event moves.
const maxInboundFindings = 500

// githubTicketIntegration is the integration name recorded as the actor.
const githubTicketIntegration = "github"

// SetInboundApplier wires the finding service path for inbound issue
// events. Without it inbound events change nothing (fail closed).
func (s *GitHubTicketService) SetInboundApplier(a inboundApplier) { s.applier = a }

// SetWorkItemFindingLister wires the lookup of every finding linked to an
// issue.
func (s *GitHubTicketService) SetWorkItemFindingLister(l workItemFindingLister) { s.workItems = l }

// SetFixClaimHook wires the proof-of-fix request after a fix claim.
func (s *GitHubTicketService) SetFixClaimHook(h FixClaimHook) { s.fixClaimHook = h }

// HandleIssueEvent is the inbound half of GitHub Issues sync. A verified
// issues delivery for an issue linked to findings goes through the same
// rules as a Jira status change (finding.ApplyTicketStatus):
//
//   - closed as completed: a fix claim for every linked open finding, then
//     the proof of fix is queued. A ticket never closes a finding;
//   - closed as not planned: a pending risk-acceptance request per finding
//     (finding.RequestTicketDisposition), decided by an approver;
//   - closed as duplicate: nothing changes (the work lives in another issue);
//   - reopened: the linked findings go back to in progress.
//
// Other actions, and issues no finding is linked to, are ignored. Refusals
// (a closed or pentest finding, a move the lifecycle does not allow) are
// logged; nothing is written for them.
func (s *GitHubTicketService) HandleIssueEvent(ctx context.Context, tenantID shared.ID, ev GitHubIssueEvent) error {
	intent := issueIntent(ev.Action, ev.StateReason)
	if intent == intentNone || strings.TrimSpace(ev.IssueURL) == "" {
		return nil
	}
	if intent == intentDuplicate {
		s.logger.Info("github webhook: issue closed as duplicate; linked findings unchanged",
			"issue_url", logger.SanitizeValue(ev.IssueURL))
		return nil
	}
	if s.applier == nil || s.workItems == nil {
		// Fail closed: without the finding service path nothing is applied.
		s.logger.Error("github webhook: inbound status applier not wired; change not applied",
			"issue_url", logger.SanitizeValue(ev.IssueURL))
		return nil
	}
	ids, err := s.workItems.ListIDsByWorkItemURI(ctx, tenantID, ev.IssueURL, maxInboundFindings)
	if err != nil {
		return fmt.Errorf("lookup findings by issue url: %w", err)
	}
	if len(ids) == 0 {
		return nil
	}
	ref := issueKeyFromURL(ev.IssueURL)
	actor := githubLogin(ev.Sender)

	if intent == intentRiskRequest {
		out, err := s.applier.RequestTicketDisposition(ctx, tenantID, ids, vulnerability.FindingStatusAccepted, githubTicketIntegration, ref, actor)
		if err != nil {
			return fmt.Errorf("request risk acceptance from github issue: %w", err)
		}
		s.logger.Info("github webhook: issue closed as not planned; risk acceptance requested",
			"issue_url", logger.SanitizeValue(ev.IssueURL), "linked", len(ids),
			"requested", len(out.Requested), "pending", len(out.Pending), "refused", len(out.Refused))
		s.logRefusals(ev.IssueURL, out.Refused)
		return nil
	}

	target := vulnerability.FindingStatusFixApplied
	if intent == intentReopen {
		target = vulnerability.FindingStatusInProgress
	}
	out, err := s.applier.ApplyTicketStatus(ctx, tenantID, ids, target, githubTicketIntegration, ref, actor)
	if err != nil {
		return fmt.Errorf("apply github issue status to linked findings: %w", err)
	}
	s.logger.Info("github webhook applied issue status",
		"issue_url", logger.SanitizeValue(ev.IssueURL), "finding_status", target,
		"linked", len(ids), "applied", len(out.Applied), "refused", len(out.Refused))
	s.logRefusals(ev.IssueURL, out.Refused)

	// A fix claim asks for the proof of fix of each claimed finding. Hook
	// errors are logged: the claim stands and a scan still verifies it.
	if target == vulnerability.FindingStatusFixApplied && s.fixClaimHook != nil {
		for _, id := range out.Applied {
			if herr := s.fixClaimHook(ctx, tenantID, id); herr != nil {
				s.logger.Warn("github webhook: proof-of-fix request failed; the claim stands",
					"finding_id", id.String(), "error", herr)
			}
		}
	}
	return nil
}

func (s *GitHubTicketService) logRefusals(issueURL string, refused []InboundRefusal) {
	for _, r := range refused {
		s.logger.Info("github webhook: linked finding not moved",
			"issue_url", logger.SanitizeValue(issueURL), "finding_id", r.FindingID, "reason", r.Reason)
	}
}

// inboundIntent is what a GitHub issues action means for linked findings.
type inboundIntent int

const (
	intentNone inboundIntent = iota
	intentFixClaim
	intentRiskRequest
	intentDuplicate
	intentReopen
)

// issueIntent maps an issues action and its state_reason to an intent.
// Only a close as completed (or a close without a reason, from a server
// that does not send one) is a fix claim; a reason it does not know
// changes nothing.
func issueIntent(action, stateReason string) inboundIntent {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "closed":
		switch strings.ToLower(strings.TrimSpace(stateReason)) {
		case "", "completed":
			return intentFixClaim
		case "not_planned":
			return intentRiskRequest
		case "duplicate":
			return intentDuplicate
		default:
			return intentNone
		}
	case "reopened":
		return intentReopen
	default:
		return intentNone
	}
}

// githubLoginRe is the shape of a GitHub login (an app's bot account ends in
// "[bot]").
var githubLoginRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,38}(\[bot\])?$`)

// githubLogin returns the sender login when it has a login's shape, else ""
// (the timeline then names the integration only).
func githubLogin(login string) string {
	if githubLoginRe.MatchString(login) {
		return login
	}
	return ""
}
