package integration

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	integrationdom "github.com/openctemio/api/pkg/domain/integration"
	"github.com/openctemio/api/pkg/domain/shared"
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

// --- per-tenant GitHub webhook secret (mirrors the Jira flow, provider=GitHub) ---

func (s *IntegrationService) primaryGitHubIntegration(ctx context.Context, tenantID shared.ID) (*integrationdom.Integration, error) {
	intgs, err := s.repo.ListByProvider(ctx, tenantID, integrationdom.ProviderGitHub)
	if err != nil {
		return nil, fmt.Errorf("list github integrations: %w", err)
	}
	if len(intgs) == 0 {
		return nil, ErrNoGitHubIntegration
	}
	return intgs[0], nil
}

// EnsureGitHubWebhookSecret returns the tenant's GitHub webhook secret, lazily
// generating one on the tenant's primary GitHub integration if none exists.
func (s *IntegrationService) EnsureGitHubWebhookSecret(ctx context.Context, tenantID shared.ID) (string, error) {
	intg, err := s.primaryGitHubIntegration(ctx, tenantID)
	if err != nil {
		return "", err
	}
	if existing := s.secretFromIntegration(intg); existing != "" {
		return existing, nil
	}
	secret, err := generateWebhookSecret()
	if err != nil {
		return "", err
	}
	if err := s.storeSecretOnIntegration(ctx, intg, secret); err != nil {
		return "", err
	}
	s.logger.Info("generated GitHub webhook secret", "tenant_id", tenantID.String(), "integration_id", intg.ID().String())
	return secret, nil
}

// RotateGitHubWebhookSecret generates a fresh secret and returns it.
func (s *IntegrationService) RotateGitHubWebhookSecret(ctx context.Context, tenantID shared.ID) (string, error) {
	intg, err := s.primaryGitHubIntegration(ctx, tenantID)
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

// ListGitHubWebhookSecrets returns the decrypted webhook secrets configured on
// the tenant's (non-disabled) GitHub integrations — the candidates used to
// verify an inbound GitHub webhook. Tenant-scoped.
func (s *IntegrationService) ListGitHubWebhookSecrets(ctx context.Context, tenantID shared.ID) ([]string, error) {
	intgs, err := s.repo.ListByProvider(ctx, tenantID, integrationdom.ProviderGitHub)
	if err != nil {
		return nil, fmt.Errorf("list github integrations: %w", err)
	}
	secrets := make([]string, 0, len(intgs))
	for _, intg := range intgs {
		if intg.Status() == integrationdom.StatusDisabled {
			continue
		}
		if secret := s.secretFromIntegration(intg); secret != "" {
			secrets = append(secrets, secret)
		}
	}
	return secrets, nil
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
