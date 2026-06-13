package ticketing

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/api/internal/infra/scm"
	"github.com/openctemio/api/pkg/crypto"
	"github.com/openctemio/api/pkg/domain/integration"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/logger"
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
}

// issueCreator is the minimal slice of the SCM GitHub client the service needs.
// Defining it here (rather than depending on the concrete *scm.GitHubClient)
// keeps CreateTicketFromFinding unit-testable without real HTTP: tests inject a
// fake creator via clientFactory. The production factory builds an
// *scm.GitHubClient, which satisfies this interface.
type issueCreator interface {
	CreateIssue(ctx context.Context, owner, repo, title, body string, labels []string) (int, string, error)
}

// GitHubTicketService creates GitHub issues from findings and links them.
//
// This is the GitHub analog of jira.SyncService.CreateTicketFromFinding:
// resolve the tenant's GitHub integration → load finding → idempotency via
// work_item_uris → create issue → link the issue URL back onto the finding.
//
// CREATE + link only. Inbound status sync (webhooks) is a documented
// follow-up; see docs/architecture/github-issue-ticketing.md.
type GitHubTicketService struct {
	findingRepo     vulnerability.FindingRepository
	integrationRepo integration.Repository
	decrypt         func(string) (string, error)
	logger          *logger.Logger

	// clientFactory builds an issueCreator from a resolved access token and
	// base URL. Overridable in tests; defaults to the real SCM client.
	clientFactory func(token, baseURL string) (issueCreator, error)
}

// NewGitHubTicketService constructs a GitHubTicketService.
//
// The encryptor is used to decrypt the integration's stored credential the
// same way the SCM integration layer does (IntegrationService.decryptCredentials):
// encryptor.DecryptString, falling back to the stored value as plaintext when
// decryption fails. If encryptor is nil, credentials are treated as plaintext.
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

	title := RedactSecrets(fmt.Sprintf("[%s] %s", finding.Severity(), finding.Title()))
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

// resolveCredential lists the tenant's GitHub integrations, picks the first
// connected one, and decrypts its stored credential. This mirrors how the SCM
// layer resolves the access token (IntegrationService.decryptCredentials):
// intg.CredentialsEncrypted() → decrypt, with plaintext fallback on failure.
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
			// Decryption failed — assume the stored value is plaintext
			// (backward compatibility), matching IntegrationService.
			s.logger.Debug("github credential not encrypted, using plaintext",
				"integration_id", intg.ID().String())
			decrypted = encrypted
		}
		if strings.TrimSpace(decrypted) == "" {
			continue
		}
		return decrypted, intg.BaseURL(), nil
	}

	return "", "", ErrNoGitHubIntegration
}

// buildIssueBody renders the markdown body of the issue, mirroring the
// semantics of the Jira description. For secret findings the raw description is
// OMITTED — only the masked value and a pointer to the platform are included,
// so the credential is never written into a third-party ticket.
func buildIssueBody(finding *vulnerability.Finding) string {
	var b strings.Builder

	fmt.Fprintf(&b, "**Severity:** %s\n", finding.Severity())
	fmt.Fprintf(&b, "**Status:** %s\n", finding.Status())

	if loc := findingLocation(finding); loc != "" {
		fmt.Fprintf(&b, "**Location:** %s\n", loc)
	}
	b.WriteString("\n")

	if isSecretFinding(finding) {
		b.WriteString("> A secret/credential was detected. The raw value is intentionally omitted from this issue.\n\n")
		if masked := finding.SecretMaskedValue(); masked != "" {
			fmt.Fprintf(&b, "**Masked value:** `%s`\n\n", masked)
		}
		b.WriteString("Open the finding in the OpenCTEM platform for full details.\n")
		return b.String()
	}

	if desc := strings.TrimSpace(finding.Description()); desc != "" {
		b.WriteString(RedactSecrets(desc))
		b.WriteString("\n")
	}

	return b.String()
}

// isSecretFinding reports whether a finding represents an exposed secret.
func isSecretFinding(finding *vulnerability.Finding) bool {
	return finding.Source() == vulnerability.FindingSourceSecret ||
		finding.FindingType() == vulnerability.FindingTypeSecret
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
