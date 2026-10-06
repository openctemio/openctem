package cirun

import (
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A run on a branch that does not count links to the branch-only findings the
// default list leaves out; a default-branch run links to the plain list.
func TestGateFindingsPath(t *testing.T) {
	repo := shared.NewID()
	def := gateFindingsPath(&cirun.Run{RepositoryAssetID: repo, IsDefaultBranch: true})
	if def != "/findings?asset_id="+repo.String() {
		t.Fatalf("default-branch link = %s", def)
	}
	feat := gateFindingsPath(&cirun.Run{RepositoryAssetID: repo})
	if !strings.HasSuffix(feat, "&branch_only=true") || !strings.Contains(feat, repo.String()) {
		t.Fatalf("feature-branch link = %s", feat)
	}
}
