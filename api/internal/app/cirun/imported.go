package cirun

import (
	"context"
	"regexp"
	"strings"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/cirun"
)

// A CI run may upload the file a tool wrote (SARIF, an SBOM, OSV results, a
// DefectDojo export, ...) instead of a CTIS report; findingimport converts
// it. A converted report names whatever assets the file names, so before
// ingest it is cut to the run's repository: findings filed on an asset that
// is not the run's repository (a host, a domain, an image, another
// repository) are dropped and counted, never ingested. What stays is
// scoped exactly like a CTIS report (ScopeReport): one repository asset,
// the branch, commit and pull request of the verified token.

// repoLike matches a value that names a repository by host and path
// ("github.com/acme/api", "https://gitlab.example.com/grp/x").
var repoLike = regexp.MustCompile(`^(?i)([a-z][a-z0-9+.-]*://)?[a-z0-9-]+(\.[a-z0-9-]+)+(:[0-9]+)?/`)

// inRunRepository reports whether a converted report's asset is the run's
// repository or a part of its checkout: a repository asset whose value is
// the repository, a path inside it, or a value that names no repository at
// all (a lockfile path, a package URL of the scanned project).
func inRunRepository(a *ctis.Asset, run *cirun.Run) bool {
	if a.Type != ctis.AssetTypeRepository {
		return false
	}
	v := strings.TrimSpace(a.Value)
	if strings.HasPrefix(strings.ToLower(v), "pkg:") || !repoLike.MatchString(v) {
		return true
	}
	want := asset.NormalizeName(run.Repository, asset.AssetTypeRepository, "")
	got := asset.NormalizeName(v, asset.AssetTypeRepository, "")
	return got == want || strings.HasPrefix(got, want+"/")
}

// ScopeImported cuts a converted report to the run's repository and scopes
// it (ScopeReport). It returns how many findings were dropped because they
// were filed on another asset.
func ScopeImported(report *ctis.Report, run *cirun.Run) (dropped int, err error) {
	keep := map[string]bool{}
	for i := range report.Assets {
		if inRunRepository(&report.Assets[i], run) {
			keep[report.Assets[i].ID] = true
		}
	}
	findings := report.Findings[:0]
	for _, f := range report.Findings {
		if f.AssetRef != "" && !keep[f.AssetRef] {
			dropped++
			continue
		}
		f.AssetValue, f.AssetType = "", ""
		findings = append(findings, f)
	}
	report.Findings = findings
	// The run's repository is the only asset; every kept finding is on it.
	report.Assets = []ctis.Asset{{ID: repoAssetRef, Type: ctis.AssetTypeRepository, Value: run.Repository}}
	for i := range report.Findings {
		report.Findings[i].AssetRef = repoAssetRef
	}
	if err := ScopeReport(report, run); err != nil {
		return dropped, err
	}
	return dropped, nil
}

// UploadImported ingests a converted report for the run, like UploadReport,
// after cutting it to the run's repository.
func (s *Service) UploadImported(ctx context.Context, run *cirun.Run, report *ctis.Report) (*ingest.Output, int, error) {
	if report == nil {
		return nil, 0, nil
	}
	dropped, err := ScopeImported(report, run)
	if err != nil {
		return nil, dropped, err
	}
	out, err := s.UploadReport(ctx, run, report)
	return out, dropped, err
}
