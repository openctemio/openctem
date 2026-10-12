package scmapp

import (
	"context"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ProviderGitLab names GitLab connections.
const ProviderGitLab = "gitlab"

// GitLabConnection is a GitLab group access token an organization stored to
// post the CI gate as a commit status and a merge request note. The token
// stays encrypted; TokenEncrypted is never returned by the API.
type GitLabConnection struct {
	ID             shared.ID
	TenantID       shared.ID
	Host           string
	GroupPath      string
	GroupID        int64
	TokenEncrypted string
	TokenUserID    int64
	TokenExpiresAt *time.Time
	Status         string
	CreatedBy      *shared.ID
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// Covers reports whether a project path ("group/sub/project") on host is in
// the connection's group.
func (c *GitLabConnection) Covers(host, projectPath string) bool {
	return strings.EqualFold(c.Host, host) && strings.HasPrefix(strings.ToLower(projectPath), strings.ToLower(c.GroupPath)+"/")
}

// GitLabRepository stores GitLab connections; every call is tenant-scoped.
type GitLabRepository interface {
	CreateGitLab(ctx context.Context, c *GitLabConnection) error
	ListGitLab(ctx context.Context, tenantID shared.ID) ([]GitLabConnection, error)
	DeleteGitLab(ctx context.Context, tenantID, id shared.ID) (*GitLabConnection, error)
	// GitLabForProject returns the tenant's active connection whose group
	// holds the project (the deepest group wins), or ErrNotFound.
	GitLabForProject(ctx context.Context, tenantID shared.ID, host, projectPath string) (*GitLabConnection, error)
}
