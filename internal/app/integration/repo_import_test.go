package integration

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/openctemio/api/internal/infra/scm"
	assetdom "github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/shared"
)

func TestApplyRepoFields(t *testing.T) {
	ext, err := assetdom.NewRepositoryExtension(shared.NewID(), "acme/widgets", assetdom.RepoVisibilityPublic)
	require.NoError(t, err)

	r := scm.Repository{
		ID:            "gh-999",
		FullName:      "acme/widgets",
		HTMLURL:       "https://github.com/acme/widgets",
		CloneURL:      "https://github.com/acme/widgets.git",
		SSHURL:        "git@github.com:acme/widgets.git",
		DefaultBranch: "main",
		Language:      "Go",
		Topics:        []string{"security", "ctem"},
		Stars:         12,
		Forks:         3,
		Size:          2048,
	}

	applyRepoFields(ext, r, assetdom.RepoVisibilityPrivate)

	require.Equal(t, "gh-999", ext.RepoID())
	require.Equal(t, "https://github.com/acme/widgets", ext.WebURL())
	require.Equal(t, "https://github.com/acme/widgets.git", ext.CloneURL())
	require.Equal(t, "main", ext.DefaultBranch())
	require.Equal(t, assetdom.RepoVisibilityPrivate, ext.Visibility())
	require.Equal(t, "acme", ext.SCMOrganization())
}

func TestApplyRepoFields_NoOwnerInFullName(t *testing.T) {
	ext, err := assetdom.NewRepositoryExtension(shared.NewID(), "widgets", assetdom.RepoVisibilityPublic)
	require.NoError(t, err)
	// FullName without a "/" must not panic or set a bogus organization.
	applyRepoFields(ext, scm.Repository{FullName: "widgets"}, assetdom.RepoVisibilityPublic)
	require.Equal(t, "", ext.SCMOrganization())
}
