package cirun

import (
	"testing"

	"github.com/openctemio/ctis/v2"

	"github.com/openctemio/openctem/server/pkg/domain/cirun"
)

func TestScopeImported(t *testing.T) {
	run := &cirun.Run{Repository: "github.com/acme/api", Branch: "feature/x", CommitSHA: "abc", PullRequest: "7"}
	rep := &ctis.Report{
		Assets: []ctis.Asset{
			{ID: "lock", Type: ctis.AssetTypeRepository, Value: "services/api/go.mod"},
			{ID: "purl", Type: ctis.AssetTypeRepository, Value: "pkg:npm/web@1.0.0"},
			{ID: "self", Type: ctis.AssetTypeRepository, Value: "https://github.com/acme/api"},
			{ID: "inside", Type: ctis.AssetTypeRepository, Value: "github.com/acme/api/web/package.json"},
			{ID: "other", Type: ctis.AssetTypeRepository, Value: "github.com/evil/other"},
			{ID: "prefix", Type: ctis.AssetTypeRepository, Value: "github.com/acme/api-fork"},
			{ID: "host", Type: ctis.AssetTypeHost, Value: "db.example.com"},
			{ID: "image", Type: ctis.AssetTypeContainer, Value: "pkg:oci/x@sha256%3Aaa"},
		},
	}
	for _, ref := range []string{"lock", "purl", "self", "inside", "other", "prefix", "host", "image"} {
		rep.Findings = append(rep.Findings, ctis.Finding{Title: ref, AssetRef: ref, Type: ctis.FindingTypeVulnerability, Severity: ctis.SeverityHigh})
	}
	dropped, err := ScopeImported(rep, run)
	if err != nil {
		t.Fatal(err)
	}
	if dropped != 4 || len(rep.Findings) != 4 {
		t.Fatalf("dropped %d kept %d", dropped, len(rep.Findings))
	}
	for _, f := range rep.Findings {
		switch f.Title {
		case "other", "prefix", "host", "image":
			t.Errorf("finding on %s kept", f.Title)
		}
		if f.AssetRef != repoAssetRef {
			t.Errorf("finding %s not on the run's repository", f.Title)
		}
	}
	if len(rep.Assets) != 1 || rep.Assets[0].Value != run.Repository {
		t.Fatalf("assets = %+v", rep.Assets)
	}
	if b := rep.Metadata.Branch; b == nil || b.Name != "pull/7" || b.CommitSHA != "abc" || b.PullRequestNumber != 7 {
		t.Fatalf("branch = %+v", b)
	}
}

func TestScopeReportForkEventNeverReportsTheBaseBranch(t *testing.T) {
	run := &cirun.Run{Repository: "github.com/acme/api", Branch: "main", DefaultBranch: "main", CommitSHA: "abc",
		Event: "pull_request_target", Fork: true, IsDefaultBranch: true}
	rep := &ctis.Report{Findings: []ctis.Finding{{Title: "x", Type: ctis.FindingTypeVulnerability, Severity: ctis.SeverityHigh}}}
	if err := ScopeReport(rep, run); err != nil {
		t.Fatal(err)
	}
	b := rep.Metadata.Branch
	if b == nil || b.Name == "main" || b.IsDefaultBranch {
		t.Fatalf("a fork event reported as the default branch: %+v", b)
	}
}

const testImage = "ghcr.io/acme/api@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

// ScopeReport accepts the container image the run scanned, attaches its
// findings to the repository and leaves only the canonical repository asset.
func TestScopeReportAcceptsScannedImage(t *testing.T) {
	run := &cirun.Run{Repository: "github.com/acme/api", Branch: "main", CommitSHA: "abc"}
	rep := &ctis.Report{
		Assets: []ctis.Asset{
			{ID: "repo", Type: ctis.AssetTypeRepository, Value: "GitHub.com/Acme/API"},
			{ID: "img", Type: ctis.AssetTypeContainerImage, Value: testImage},
		},
		Relationships: []ctis.Relationship{{Type: ctis.RelContains, FromRef: "repo", ToRef: "img"}},
		Findings: []ctis.Finding{
			{Title: "a", AssetRef: "img", Type: ctis.FindingTypeVulnerability, Severity: ctis.SeverityHigh},
			{Title: "b", AssetRef: "repo", Type: ctis.FindingTypeVulnerability, Severity: ctis.SeverityHigh},
		},
	}
	if got := scannedImage(rep); got != testImage {
		t.Fatalf("scannedImage = %q", got)
	}
	if err := ScopeReport(rep, run); err != nil {
		t.Fatal(err)
	}
	if len(rep.Assets) != 1 || rep.Assets[0].ID != repoAssetRef || rep.Assets[0].Type != ctis.AssetTypeRepository ||
		rep.Assets[0].Value != "github.com/acme/api" {
		t.Fatalf("assets = %+v", rep.Assets)
	}
	if rep.Relationships != nil {
		t.Fatalf("relationships kept: %+v", rep.Relationships)
	}
	for _, f := range rep.Findings {
		if f.AssetRef != repoAssetRef {
			t.Errorf("finding %s on %q", f.Title, f.AssetRef)
		}
	}
}

func TestScopeReportRefusesAnotherRepository(t *testing.T) {
	run := &cirun.Run{Repository: "github.com/acme/api"}
	rep := &ctis.Report{
		Assets: []ctis.Asset{
			{ID: "repo", Type: ctis.AssetTypeRepository, Value: "github.com/acme/api"},
			{ID: "other", Type: ctis.AssetTypeRepository, Value: "github.com/evil/other"},
		},
		Findings: []ctis.Finding{{Title: "a", AssetRef: "other", Type: ctis.FindingTypeVulnerability, Severity: ctis.SeverityHigh}},
	}
	if err := ScopeReport(rep, run); err != ErrReportOutOfScope {
		t.Fatalf("err = %v, want ErrReportOutOfScope", err)
	}
	// A finding that names an asset the report does not hold is refused too.
	rep = &ctis.Report{
		Assets:   []ctis.Asset{{ID: "repo", Type: ctis.AssetTypeRepository, Value: "github.com/acme/api"}},
		Findings: []ctis.Finding{{Title: "a", AssetRef: "ghost", Type: ctis.FindingTypeVulnerability, Severity: ctis.SeverityHigh}},
	}
	if err := ScopeReport(rep, run); err != ErrReportOutOfScope {
		t.Fatalf("dangling ref: err = %v", err)
	}
}
