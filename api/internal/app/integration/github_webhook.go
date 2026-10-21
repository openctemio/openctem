package integration

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	integrationdom "github.com/openctemio/openctem/api/pkg/domain/integration"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ErrNoGitHubIntegration is returned when a tenant has no GitHub integration to
// anchor a webhook secret to.
var ErrNoGitHubIntegration = fmt.Errorf("%w: no GitHub integration configured for this tenant", shared.ErrNotFound)

// GitHubPushEvent is the subset of a GitHub `push` webhook payload we use.
type GitHubPushEvent struct {
	Ref          string // e.g. "refs/heads/main"
	Branch       string // ref with refs/heads/ stripped
	After        string // SHA after the push (HEAD)
	RepoFullName string // "owner/repo"
	Deleted      bool   // branch deletion push
}

// VerifyGitHubSignature reports whether sigHeader (the GitHub
// "X-Hub-Signature-256: sha256=<hex>" header) is a valid HMAC-SHA256 of body
// under secret. Constant-time comparison. Returns false on any malformed input.
func VerifyGitHubSignature(body []byte, sigHeader, secret string) bool {
	return VerifyHubSignature(body, sigHeader, secret)
}

// VerifyHubSignature checks a "sha256=<hex>" HMAC-SHA256 signature of the raw
// body (the X-Hub-Signature format GitHub and Jira both send) in constant
// time.
func VerifyHubSignature(body []byte, sigHeader, secret string) bool {
	const prefix = "sha256="
	if secret == "" || !strings.HasPrefix(sigHeader, prefix) {
		return false
	}
	provided := strings.ToLower(strings.TrimSpace(sigHeader[len(prefix):]))
	if _, err := hex.DecodeString(provided); err != nil {
		return false
	}
	m := hmac.New(sha256.New, []byte(secret))
	_, _ = m.Write(body)
	expected := hex.EncodeToString(m.Sum(nil))
	return subtle.ConstantTimeCompare([]byte(expected), []byte(provided)) == 1
}

// ParseGitHubPush parses a GitHub `push` webhook body. A zero After SHA
// ("000...0") marks a branch deletion.
func ParseGitHubPush(body []byte) (*GitHubPushEvent, error) {
	var p struct {
		Ref        string `json:"ref"`
		After      string `json:"after"`
		Deleted    bool   `json:"deleted"`
		Repository struct {
			FullName string `json:"full_name"`
		} `json:"repository"`
	}
	if err := json.Unmarshal(body, &p); err != nil {
		return nil, fmt.Errorf("invalid push payload: %w", err)
	}
	const zeroSHA = "0000000000000000000000000000000000000000"
	return &GitHubPushEvent{
		Ref:          p.Ref,
		Branch:       strings.TrimPrefix(p.Ref, "refs/heads/"),
		After:        p.After,
		RepoFullName: p.Repository.FullName,
		Deleted:      p.Deleted || p.After == zeroSHA || p.After == "",
	}, nil
}

// --- per-integration GitHub webhook secret (same model as the Jira one) ---

// ErrGitHubWebhookUnauthorized refuses an inbound delivery. One error for
// every cause (unknown integration, another provider, disabled, no secret, a
// bad or missing signature), so a caller cannot probe which integrations
// exist.
var ErrGitHubWebhookUnauthorized = fmt.Errorf("%w: invalid webhook signature", shared.ErrUnauthorized)

// githubIntegrationOf returns the tenant's GitHub integration with this id,
// or not found (another tenant's integration, or a non-GitHub one, is not
// found).
func (s *IntegrationService) githubIntegrationOf(ctx context.Context, tenantID, integrationID shared.ID) (*integrationdom.Integration, error) {
	intg, err := s.repo.GetByTenantAndID(ctx, tenantID, integrationID)
	if err != nil {
		return nil, err
	}
	if intg.Provider() != integrationdom.ProviderGitHub {
		return nil, ErrNoGitHubIntegration
	}
	return intg, nil
}

// GitHubWebhookHasSecret reports whether the tenant's GitHub integration has
// an inbound webhook secret. The secret itself is never returned after it
// is generated: it is shown once, on rotation.
func (s *IntegrationService) GitHubWebhookHasSecret(ctx context.Context, tenantID, integrationID shared.ID) (bool, error) {
	intg, err := s.githubIntegrationOf(ctx, tenantID, integrationID)
	if err != nil {
		return false, err
	}
	return s.secretFromIntegration(intg) != "", nil
}

// RotateGitHubWebhookSecret generates a new inbound webhook secret for one of
// the tenant's GitHub integrations and returns it, the only time it is
// shown. The previous secret stops verifying immediately.
func (s *IntegrationService) RotateGitHubWebhookSecret(ctx context.Context, tenantID, integrationID shared.ID) (string, error) {
	intg, err := s.githubIntegrationOf(ctx, tenantID, integrationID)
	if err != nil {
		return "", err
	}
	secret, err := generateWebhookSecret()
	if err != nil {
		return "", err
	}
	if err := s.storeSecretOnIntegration(ctx, intg, secret); err != nil {
		return "", err
	}
	s.logger.Info("rotated GitHub webhook secret", "tenant_id", tenantID.String(), "integration_id", intg.ID().String())
	return secret, nil
}

// GitHubDelivery is the verified origin of an inbound GitHub delivery.
type GitHubDelivery struct {
	TenantID      shared.ID
	IntegrationID shared.ID
	// Organization is the GitHub organization (or user) the integration is
	// bound to; "" when the integration names none.
	Organization string
}

// RepositoryAllowed reports whether an event for the repository
// "owner/name" may be applied through this integration: when the
// integration is bound to an organization, the repository must belong to
// it.
func (d GitHubDelivery) RepositoryAllowed(fullName string) bool {
	if d.Organization == "" {
		return true
	}
	owner, _, ok := strings.Cut(fullName, "/")
	return ok && strings.EqualFold(owner, d.Organization)
}

// VerifyGitHubDelivery authenticates an inbound GitHub webhook delivered to
// the per-integration URL. The integration id in the URL names exactly one
// integration and so one tenant; the delivery must carry
// X-Hub-Signature-256: sha256=<hex HMAC-SHA256 of the raw body> under that
// integration's own secret. Every failure is ErrGitHubWebhookUnauthorized.
func (s *IntegrationService) VerifyGitHubDelivery(ctx context.Context, integrationID shared.ID, body []byte, signature string) (GitHubDelivery, error) {
	// Unscoped by design: the URL is the only identity an unauthenticated
	// sender has, and the secret of that one integration is the proof.
	intg, err := s.repo.GetByID(ctx, integrationID)
	if err != nil || intg == nil ||
		intg.Provider() != integrationdom.ProviderGitHub ||
		intg.Status() == integrationdom.StatusDisabled {
		return GitHubDelivery{}, ErrGitHubWebhookUnauthorized
	}
	secret := s.secretFromIntegration(intg)
	if secret == "" || !VerifyGitHubSignature(body, signature, secret) {
		return GitHubDelivery{}, ErrGitHubWebhookUnauthorized
	}
	d := GitHubDelivery{TenantID: intg.TenantID(), IntegrationID: intg.ID()}
	if s.scmExtRepo != nil {
		ext, err := s.scmExtRepo.GetByIntegrationID(ctx, intg.ID())
		switch {
		case err == nil && ext != nil:
			d.Organization = strings.TrimSpace(ext.SCMOrganization())
		case err != nil && !errors.Is(err, shared.ErrNotFound):
			// Fail closed: the repository binding cannot be checked.
			return GitHubDelivery{}, fmt.Errorf("load the integration's organization: %w", err)
		}
	}
	return d, nil
}

// HandleGitHubPush applies a verified GitHub push event for a tenant: it refreshes
// the pushed branch's last-commit metadata on the matching repository asset (no-op
// if the repo isn't imported or the branch isn't tracked, or on a branch delete).
// Returns whether a branch was updated. Best-effort, idempotent.
func (s *IntegrationService) HandleGitHubPush(ctx context.Context, tenantID shared.ID, ev *GitHubPushEvent) (bool, error) {
	if s.repoExtRepo == nil || s.branchRepo == nil || ev == nil {
		return false, nil
	}
	if ev.Deleted || ev.RepoFullName == "" || ev.Branch == "" {
		return false, nil
	}
	ext, err := s.repoExtRepo.GetByFullName(ctx, tenantID, ev.RepoFullName)
	if err != nil || ext == nil {
		return false, nil // repo not imported — nothing to update
	}
	br, err := s.branchRepo.GetByName(ctx, ext.AssetID(), ev.Branch)
	if err != nil || br == nil {
		return false, nil // branch not tracked yet
	}
	if ev.After != "" && ev.After != br.LastCommitSHA() {
		br.UpdateLastCommit(ev.After, "", "", "", time.Now().UTC())
		if err := s.branchRepo.Update(ctx, br); err != nil {
			return false, fmt.Errorf("update branch on push: %w", err)
		}
		return true, nil
	}
	return false, nil
}
