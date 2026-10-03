package ingest

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func sarifLog(run string) []byte {
	return []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"gosec","rules":[{"id":"G101"}]}},` + run +
		`"results":[{"ruleId":"G101","level":"error","message":{"text":"Hardcoded credential"},` +
		`"locations":[{"physicalLocation":{"artifactLocation":{"uri":"cmd/main.go"},"region":{"startLine":5}}}]}]}]}`)
}

func convertWithRepository(t *testing.T, data []byte, req SARIFRepository) (*ctis.Report, bool) {
	t.Helper()
	repo, ok, err := resolveSARIFRepository(data, req)
	if err != nil {
		t.Fatalf("resolveSARIFRepository: %v", err)
	}
	var opts *ctis.ConvertOptions
	if ok {
		opts = sarifConvertOptions(repo)
	}
	report, err := ctis.FromSARIF(data, opts)
	if err != nil {
		t.Fatalf("FromSARIF: %v", err)
	}
	return report, ok
}

// The QA reproduction: two repositories scanned by the same tool, pushed as
// SARIF without an asset. Each must land on its own repository asset; before,
// both fell back to the one "scan:<tool>:unknown" pseudo-asset and the second
// push's findings deduplicated into the first's.
func TestSARIF_RepositoryFromVersionControlProvenance(t *testing.T) {
	one, ok1 := convertWithRepository(t, sarifLog(`"versionControlProvenance":[{"repositoryUri":"https://github.com/acme/one","revisionId":"abc","branch":"main"}],`), SARIFRepository{})
	two, ok2 := convertWithRepository(t, sarifLog(`"versionControlProvenance":[{"repositoryUri":"https://github.com/acme/two"}],`), SARIFRepository{})
	if !ok1 || !ok2 {
		t.Fatal("versionControlProvenance did not identify the repository")
	}
	if len(one.Assets) != 1 || len(two.Assets) != 1 {
		t.Fatalf("want one asset per log, got %d and %d", len(one.Assets), len(two.Assets))
	}
	if one.Assets[0].Value == two.Assets[0].Value {
		t.Fatalf("two repositories mapped to the same asset %q", one.Assets[0].Value)
	}
	if one.Assets[0].Type != ctis.AssetTypeRepository {
		t.Errorf("asset type = %q, want repository", one.Assets[0].Type)
	}
	for _, f := range one.Findings {
		if f.AssetRef != one.Assets[0].ID {
			t.Errorf("finding not linked to the repository asset (asset_ref %q)", f.AssetRef)
		}
	}
	if one.Metadata.Branch == nil || one.Metadata.Branch.Name != "main" || one.Metadata.Branch.CommitSHA != "abc" {
		t.Errorf("branch/commit from versionControlProvenance not carried: %+v", one.Metadata.Branch)
	}
	if two.Metadata.Branch != nil {
		t.Errorf("no branch in the log, but report carries one: %+v", two.Metadata.Branch)
	}
}

func TestResolveSARIFRepository(t *testing.T) {
	cases := []struct {
		name    string
		run     string
		req     SARIFRepository
		wantURL string
		wantErr error
	}{
		{"request parameter", ``, SARIFRepository{URL: "https://gitlab.example.com/team/svc"}, "https://gitlab.example.com/team/svc", nil},
		{"request parameter wins over the log", `"versionControlProvenance":[{"repositoryUri":"https://github.com/acme/one"}],`, SARIFRepository{URL: "https://github.com/acme/other"}, "https://github.com/acme/other", nil},
		{"credentials are stripped", `"versionControlProvenance":[{"repositoryUri":"https://x-access-token:s3cret@github.com/acme/one.git?x=1#frag"}],`, SARIFRepository{}, "https://github.com/acme/one.git", nil},
		{"scp-like git url", `"versionControlProvenance":[{"repositoryUri":"git@github.com:acme/one.git"}],`, SARIFRepository{}, "git@github.com:acme/one.git", nil},
		{"git-hosted artifact uri", `"originalUriBaseIds":{"SRC":{"uri":"https://github.com/acme/three/blob/main/"}},`, SARIFRepository{}, "https://github.com/acme/three", nil},
		{"local paths only", `"originalUriBaseIds":{"SRC":{"uri":"file:///home/runner/work/x/"}},`, SARIFRepository{}, "", nil},
		{"invalid request parameter", ``, SARIFRepository{URL: "not a url"}, "", ErrSARIFInvalidRepositoryURL},
		{"file url is not a repository", ``, SARIFRepository{URL: "file:///etc/passwd"}, "", ErrSARIFInvalidRepositoryURL},
		{"invalid provenance uri", `"versionControlProvenance":[{"repositoryUri":"javascript:alert(1)"}],`, SARIFRepository{}, "", ErrSARIFInvalidRepositoryURL},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok, err := resolveSARIFRepository(sarifLog(tc.run), tc.req)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) || !errors.Is(err, shared.ErrValidation) {
					t.Fatalf("err = %v, want %v (a validation error)", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.wantURL == "" {
				if ok {
					t.Fatalf("identified %q, want no repository", got.URL)
				}
				return
			}
			if !ok || got.URL != tc.wantURL {
				t.Fatalf("got %q (ok=%v), want %q", got.URL, ok, tc.wantURL)
			}
		})
	}
}

func TestRepositoryFromArtifactURIs_DisagreeingRepositories(t *testing.T) {
	if got := repositoryFromArtifactURIs([]string{
		"https://github.com/acme/a/blob/main/x.go",
		"https://github.com/acme/b/blob/main/y.go",
	}); got != "" {
		t.Fatalf("artifacts from two repositories identified %q", got)
	}
}

// A log with results and no repository identity is refused before anything is
// written; a log with no results (a clean run) is accepted.
func TestIngestSARIF_RefusesLogWithoutRepository(t *testing.T) {
	tid := shared.NewID()
	agt := &sensor.Sensor{ID: shared.NewID(), TenantID: &tid, Status: sensor.SensorStatusActive}
	s := &Service{logger: logger.NewNop()}

	_, err := s.IngestSARIF(context.Background(), agt, sarifLog(``), SARIFRepository{}, Binding{})
	if !errors.Is(err, ErrSARIFNoRepository) || !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("err = %v, want ErrSARIFNoRepository", err)
	}

	_, err = s.IngestSARIF(context.Background(), agt, sarifLog(``), SARIFRepository{Branch: "main\r\nforged"}, Binding{})
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("control characters in branch accepted: %v", err)
	}
}

func TestResolveSARIFRepository_RunsNamingDifferentRepositories(t *testing.T) {
	data := []byte(`{"version":"2.1.0","runs":[
		{"tool":{"driver":{"name":"t"}},"versionControlProvenance":[{"repositoryUri":"https://github.com/acme/a"}],"results":[]},
		{"tool":{"driver":{"name":"t"}},"versionControlProvenance":[{"repositoryUri":"https://github.com/acme/b"}],"results":[]}]}`)
	if _, _, err := resolveSARIFRepository(data, SARIFRepository{}); !errors.Is(err, ErrSARIFMultipleRepositories) {
		t.Fatalf("err = %v, want ErrSARIFMultipleRepositories", err)
	}
	// Naming the repository explicitly resolves the ambiguity.
	if got, ok, err := resolveSARIFRepository(data, SARIFRepository{URL: "https://github.com/acme/a"}); err != nil || !ok || got.URL != "https://github.com/acme/a" {
		t.Fatalf("explicit repository not used: %+v ok=%v err=%v", got, ok, err)
	}
}

// The raw-scanner endpoint converts SARIF with its own adapter; the report it
// produces has findings and no asset. AttachSARIFRepository gives it one.
func TestAttachSARIFRepository(t *testing.T) {
	data := sarifLog(`"versionControlProvenance":[{"repositoryUri":"https://github.com/acme/one","branch":"dev"}],`)
	report := &ctis.Report{Findings: []ctis.Finding{{ID: "f1", RuleID: "G101"}, {ID: "f2", RuleID: "G102"}}}
	if err := AttachSARIFRepository(report, data, SARIFRepository{}); err != nil {
		t.Fatalf("AttachSARIFRepository: %v", err)
	}
	if len(report.Assets) != 1 || report.Assets[0].Value != "https://github.com/acme/one" || report.Assets[0].Type != ctis.AssetTypeRepository {
		t.Fatalf("assets = %+v", report.Assets)
	}
	for _, f := range report.Findings {
		if f.AssetRef != report.Assets[0].ID {
			t.Errorf("finding %s not attached (asset_ref %q)", f.ID, f.AssetRef)
		}
	}
	if report.Metadata.Branch == nil || report.Metadata.Branch.Name != "dev" {
		t.Errorf("branch not carried: %+v", report.Metadata.Branch)
	}

	anon := &ctis.Report{Findings: []ctis.Finding{{ID: "f1"}}}
	if err := AttachSARIFRepository(anon, sarifLog(``), SARIFRepository{}); !errors.Is(err, ErrSARIFNoRepository) {
		t.Fatalf("unidentified log: err = %v, want ErrSARIFNoRepository", err)
	}

	withAsset := &ctis.Report{Assets: []ctis.Asset{{ID: "x", Value: "v"}}, Findings: []ctis.Finding{{ID: "f1", AssetRef: "x"}}}
	if err := AttachSARIFRepository(withAsset, sarifLog(``), SARIFRepository{}); err != nil || len(withAsset.Assets) != 1 {
		t.Fatalf("a report with its own asset must be left alone: err=%v assets=%d", err, len(withAsset.Assets))
	}
}
