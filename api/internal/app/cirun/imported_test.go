package cirun

import (
	"testing"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/cirun"
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
	if b := rep.Metadata.Branch; b == nil || b.Name != "feature/x" || b.CommitSHA != "abc" || b.PullRequestNumber != 7 {
		t.Fatalf("branch = %+v", b)
	}
}
