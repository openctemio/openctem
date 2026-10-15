package scmapp

// GitLab group access tokens for CI commit statuses and merge request notes
// (docs/rfcs/RFC-077-ci-enforced-gate-and-pr-feedback.md). A token is
// accepted only when GitLab says it is active, has the api scope, acts as a
// bot user (a group or project access token, never a person's own token)
// and that bot is a direct member of the group. It is stored encrypted and
// never returned.

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/infra/scm/gitlabapi"
	"github.com/openctemio/openctem/api/pkg/crypto"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/scmapp"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// GitLabAPI is the part of the GitLab client the service and the decoration
// use (gitlabapi.Client).
type GitLabAPI interface {
	Token(ctx context.Context) (*gitlabapi.TokenInfo, error)
	CurrentUser(ctx context.Context) (*gitlabapi.User, error)
	Group(ctx context.Context, pathOrID string) (*gitlabapi.Group, error)
	GroupMember(ctx context.Context, groupID, userID int64) (bool, error)
	MergeRequest(ctx context.Context, projectPath string, iid int) (*gitlabapi.MergeRequest, error)
	SetCommitStatus(ctx context.Context, projectPath, sha, state, name, targetURL, description string, pipelineID int64) error
	UpsertMergeRequestNote(ctx context.Context, projectPath string, iid int, authorID int64, marker, body string) error
}

// GitLabFactory builds a client for a host and token.
type GitLabFactory func(host, token string) (GitLabAPI, error)

// DefaultGitLabFactory uses the SSRF-guarded client.
func DefaultGitLabFactory(host, token string) (GitLabAPI, error) {
	return gitlabapi.New(host, token, nil)
}

// SetGitLab enables GitLab connections: the encryptor seals tokens.
func (s *Service) SetGitLab(repo scmapp.GitLabRepository, enc crypto.Encryptor, factory GitLabFactory) {
	s.gitlabRepo, s.enc, s.gitlabFactory = repo, enc, factory
}

// ErrInvalidGitLabToken: GitLab did not confirm the token for the group.
var ErrInvalidGitLabToken = fmt.Errorf("%w: GitLab did not accept the token for this group: it must be an active group access token with the api scope", shared.ErrValidation)

var (
	hostRE      = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?(:[0-9]{1,5})?$`)
	groupPathRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*(/[A-Za-z0-9][A-Za-z0-9_.-]*){0,19}$`)
)

// ConnectGitLabInput is a token to store.
type ConnectGitLabInput struct {
	Host  string
	Group string
	Token string
}

// ConnectGitLab checks a group access token with GitLab and stores it
// encrypted (audited; the token is never logged or returned).
func (s *Service) ConnectGitLab(ctx context.Context, tenantID shared.ID, in ConnectGitLabInput, a Actor) (*scmapp.GitLabConnection, error) {
	if s.gitlabRepo == nil || s.enc == nil || s.gitlabFactory == nil {
		return nil, errors.New("GitLab connections are not enabled")
	}
	host := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(in.Host, "https://"), "http://")))
	host = strings.TrimRight(host, "/")
	group := strings.Trim(strings.TrimSpace(in.Group), "/")
	token := strings.TrimSpace(in.Token)
	if host == "" {
		host = "gitlab.com"
	}
	if !hostRE.MatchString(host) || !groupPathRE.MatchString(group) || token == "" || len(token) > 512 {
		return nil, fmt.Errorf("%w: a GitLab host, a group path and a token are required", shared.ErrValidation)
	}
	api, err := s.gitlabFactory(host, token)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", shared.ErrValidation, "the GitLab host is not allowed")
	}
	info, err := api.Token(ctx)
	if err != nil || !info.Active || info.Revoked || !slices.Contains(info.Scopes, "api") || info.UserID <= 0 {
		return nil, ErrInvalidGitLabToken
	}
	// A person's own token would post the gate as that person and keep
	// working with all of their access after they leave the group: only a
	// group or project access token's bot user is accepted.
	user, err := api.CurrentUser(ctx)
	if err != nil || !user.Bot || user.ID != info.UserID {
		return nil, ErrInvalidGitLabToken
	}
	g, err := api.Group(ctx, group)
	if err != nil || g.ID <= 0 {
		return nil, ErrInvalidGitLabToken
	}
	member, err := api.GroupMember(ctx, g.ID, info.UserID)
	if err != nil || !member {
		return nil, ErrInvalidGitLabToken
	}
	sealed, err := s.enc.EncryptString(token)
	if err != nil {
		return nil, fmt.Errorf("seal token: %w", err)
	}
	var createdBy *shared.ID
	if id, err := shared.IDFromString(a.UserID); err == nil {
		createdBy = &id
	}
	c := &scmapp.GitLabConnection{ID: shared.NewID(), TenantID: tenantID, Host: host, GroupPath: g.FullPath, GroupID: g.ID,
		TokenEncrypted: sealed, TokenUserID: info.UserID, CreatedBy: createdBy}
	if t, err := time.Parse("2006-01-02", info.ExpiresAt); err == nil {
		c.TokenExpiresAt = &t
	}
	if err := s.gitlabRepo.CreateGitLab(ctx, c); err != nil {
		return nil, err
	}
	s.logAudit(ctx, tenantID, a, auditapp.NewSuccessEvent(auditdom.ActionSCMAppInstalled, auditdom.ResourceTypeSCMApp, c.ID.String()).
		WithResourceName(host+"/"+c.GroupPath).
		WithMessage(fmt.Sprintf("GitLab group %s on %s connected for CI statuses and merge request notes", c.GroupPath, host)).
		WithMetadata("provider", scmapp.ProviderGitLab))
	return c, nil
}

// ListGitLab returns the tenant's GitLab connections.
func (s *Service) ListGitLab(ctx context.Context, tenantID shared.ID) ([]scmapp.GitLabConnection, error) {
	if s.gitlabRepo == nil {
		return []scmapp.GitLabConnection{}, nil
	}
	return s.gitlabRepo.ListGitLab(ctx, tenantID)
}

// RemoveGitLab deletes a connection and its token (audited).
func (s *Service) RemoveGitLab(ctx context.Context, tenantID, id shared.ID, a Actor) error {
	if s.gitlabRepo == nil {
		return scmapp.ErrNotFound
	}
	c, err := s.gitlabRepo.DeleteGitLab(ctx, tenantID, id)
	if err != nil {
		return err
	}
	s.logAudit(ctx, tenantID, a, auditapp.NewSuccessEvent(auditdom.ActionSCMAppRemoved, auditdom.ResourceTypeSCMApp, id.String()).
		WithResourceName(c.Host+"/"+c.GroupPath).
		WithMessage(fmt.Sprintf("GitLab group %s on %s disconnected", c.GroupPath, c.Host)).
		WithMetadata("provider", scmapp.ProviderGitLab))
	return nil
}

// GitLabClientFor returns a client for the tenant's connection holding the
// project, and the token user's id (to find its own notes). ErrNotFound when
// the tenant connected no group holding it.
func (s *Service) GitLabClientFor(ctx context.Context, tenantID shared.ID, host, projectPath string) (GitLabAPI, int64, error) {
	if s.gitlabRepo == nil || s.enc == nil || s.gitlabFactory == nil {
		return nil, 0, scmapp.ErrNotFound
	}
	c, err := s.gitlabRepo.GitLabForProject(ctx, tenantID, host, projectPath)
	if err != nil {
		return nil, 0, err
	}
	token, err := s.enc.DecryptString(c.TokenEncrypted)
	if err != nil {
		return nil, 0, fmt.Errorf("open GitLab token: %w", err)
	}
	api, err := s.gitlabFactory(c.Host, token)
	if err != nil {
		return nil, 0, err
	}
	return api, c.TokenUserID, nil
}
