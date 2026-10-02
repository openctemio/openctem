package ingest

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// SARIF findings need an asset, and a SARIF log does not have to name one.
// Before this, a log without one fell through the asset processor's fallback
// chain to a single pseudo-asset per tool ("scan:<tool>:unknown"), so every
// repository scanned by the same tool landed on that one asset and findings of
// unrelated repositories deduplicated into each other (the fingerprint is
// asset-scoped). The repository is now taken from the log itself, or from the
// request, and a log that identifies neither is refused.

// ErrSARIFNoRepository is returned when a SARIF log with results identifies no
// repository and the request names none. It wraps shared.ErrValidation: the
// payload is the problem, so callers answer 4xx.
var ErrSARIFNoRepository = fmt.Errorf("%w: SARIF log does not identify the repository it was produced from; "+
	"include runs[].versionControlProvenance[].repositoryUri or pass the repository_url query parameter",
	shared.ErrValidation)

// ErrSARIFInvalidRepositoryURL is returned for a repository_url (or a
// versionControlProvenance repositoryUri) that is not a repository URL.
var ErrSARIFInvalidRepositoryURL = fmt.Errorf("%w: repository_url must be an http(s), ssh or git URL of a repository",
	shared.ErrValidation)

// SARIFRepository names the repository a SARIF log was produced from. All
// fields are optional; URL takes precedence over what the log says.
type SARIFRepository struct {
	URL       string
	Branch    string
	CommitSHA string
}

const (
	maxSARIFRepoURLLen = 1000
	maxSARIFRefLen     = 255
)

// sarifProvenance is the part of a SARIF 2.1.0 log that says where it came
// from. ctis.FromSARIF does not read it.
type sarifProvenance struct {
	Runs []struct {
		VersionControlProvenance []struct {
			RepositoryURI string `json:"repositoryUri"`
			RevisionID    string `json:"revisionId"`
			Branch        string `json:"branch"`
		} `json:"versionControlProvenance"`
		OriginalURIBaseIDs map[string]struct {
			URI string `json:"uri"`
		} `json:"originalUriBaseIds"`
		Artifacts []struct {
			Location struct {
				URI string `json:"uri"`
			} `json:"location"`
		} `json:"artifacts"`
		Results []struct {
			Locations []struct {
				PhysicalLocation *struct {
					ArtifactLocation *struct {
						URI string `json:"uri"`
					} `json:"artifactLocation"`
				} `json:"physicalLocation"`
			} `json:"locations"`
		} `json:"results"`
	} `json:"runs"`
}

// gitHostedPathPattern matches a repository on a known public git host inside
// an absolute artifact URI, e.g. https://github.com/org/repo/blob/main/x.go.
var gitHostedPathPattern = regexp.MustCompile(`^https?://(github\.com|gitlab\.com|bitbucket\.org)/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)(?:/|$)`)

// scpLikeGitURL matches git@host:org/repo(.git).
var scpLikeGitURL = regexp.MustCompile(`^[A-Za-z0-9_.-]+@[A-Za-z0-9.-]+:[A-Za-z0-9_./~-]+$`)

// sanitizeRepositoryURL returns the repository URL without credentials, query
// or fragment, or "" when s is not a repository URL. A versionControlProvenance
// entry written by a CI job can carry a token in its userinfo
// (https://x-access-token:...@github.com/...); it must never become an asset
// name.
func sanitizeRepositoryURL(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > maxSARIFRepoURLLen || strings.ContainsAny(s, " \t\r\n") {
		return ""
	}
	if scpLikeGitURL.MatchString(s) {
		// git@host:org/repo — drop the user, keep host:path.
		return "git@" + s[strings.Index(s, "@")+1:]
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return ""
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https", "ssh", "git":
	default:
		return ""
	}
	path := strings.Trim(u.Path, "/")
	if path == "" {
		return ""
	}
	u.User = nil
	u.RawQuery = ""
	u.Fragment = ""
	u.RawFragment = ""
	return u.String()
}

// repositoryFromArtifactURIs finds a repository on a known git host in the
// log's absolute artifact URIs. Every such URI must agree: a log whose
// artifacts span two repositories does not identify one.
func repositoryFromArtifactURIs(uris []string) string {
	found := ""
	for _, uri := range uris {
		m := gitHostedPathPattern.FindStringSubmatch(strings.TrimSpace(uri))
		if m == nil {
			continue
		}
		repo := fmt.Sprintf("https://%s/%s/%s", m[1], m[2], strings.TrimSuffix(m[3], ".git"))
		if found == "" {
			found = repo
		} else if !strings.EqualFold(found, repo) {
			return ""
		}
	}
	return found
}

// ErrSARIFMultipleRepositories is returned when the runs of one SARIF log name
// different repositories: one push is filed under one repository asset, so
// such a log must be split (or the repository named explicitly).
var ErrSARIFMultipleRepositories = fmt.Errorf("%w: SARIF runs name different repositories in versionControlProvenance; "+
	"send one log per repository or pass the repository_url query parameter", shared.ErrValidation)

// resolveSARIFRepository decides which repository a SARIF log belongs to:
// the request's repository_url, else the runs' versionControlProvenance, else
// a repository on a known git host that all absolute artifact URIs agree on.
// Returns ok=false when nothing identifies a repository.
func resolveSARIFRepository(sarifData []byte, req SARIFRepository) (SARIFRepository, bool, error) {
	if req.URL != "" {
		u := sanitizeRepositoryURL(req.URL)
		if u == "" {
			return SARIFRepository{}, false, ErrSARIFInvalidRepositoryURL
		}
		return SARIFRepository{URL: u, Branch: req.Branch, CommitSHA: req.CommitSHA}, true, nil
	}

	// An unparseable log identifies nothing here; the SARIF parser rejects it
	// with its own error afterwards.
	var prov sarifProvenance
	if json.Valid(sarifData) {
		_ = json.Unmarshal(sarifData, &prov) // shape mismatches leave fields empty
	}
	if len(prov.Runs) == 0 {
		return SARIFRepository{}, false, nil
	}

	var found *SARIFRepository
	for _, run := range prov.Runs {
		for _, vcp := range run.VersionControlProvenance {
			if vcp.RepositoryURI == "" {
				continue
			}
			u := sanitizeRepositoryURL(vcp.RepositoryURI)
			if u == "" {
				return SARIFRepository{}, false, ErrSARIFInvalidRepositoryURL
			}
			if found == nil {
				found = &SARIFRepository{URL: u, Branch: vcp.Branch, CommitSHA: vcp.RevisionID}
			} else if !strings.EqualFold(found.URL, u) {
				return SARIFRepository{}, false, ErrSARIFMultipleRepositories
			}
			break // the first entry of a run describes that run's checkout
		}
	}
	if found != nil {
		if req.Branch != "" {
			found.Branch = req.Branch
		}
		if req.CommitSHA != "" {
			found.CommitSHA = req.CommitSHA
		}
		return *found, true, nil
	}

	var uris []string
	for _, run := range prov.Runs {
		for _, base := range run.OriginalURIBaseIDs {
			uris = append(uris, base.URI)
		}
		for _, a := range run.Artifacts {
			uris = append(uris, a.Location.URI)
		}
		for _, r := range run.Results {
			for _, loc := range r.Locations {
				if loc.PhysicalLocation != nil && loc.PhysicalLocation.ArtifactLocation != nil {
					uris = append(uris, loc.PhysicalLocation.ArtifactLocation.URI)
				}
			}
		}
	}
	if repo := repositoryFromArtifactURIs(uris); repo != "" {
		return SARIFRepository{URL: repo, Branch: req.Branch, CommitSHA: req.CommitSHA}, true, nil
	}
	return SARIFRepository{}, false, nil
}

// sarifRepositoryAssetID is the in-report id of the repository asset a SARIF
// log's findings are attached to.
const sarifRepositoryAssetID = "sarif-repository"

// AttachSARIFRepository files the findings of a report converted from SARIF
// (by a path other than Service.IngestSARIF, e.g. the raw-scanner endpoint's
// SARIF adapter) under the repository the log came from, with the same rules
// and errors as IngestSARIF. A report that already carries assets, or has no
// findings, is left alone.
func AttachSARIFRepository(report *ctis.Report, sarifData []byte, req SARIFRepository) error {
	if report == nil || len(report.Assets) > 0 || len(report.Findings) == 0 {
		return nil
	}
	if err := validateSARIFRepositoryInput(req); err != nil {
		return err
	}
	repo, ok, err := resolveSARIFRepository(sarifData, req)
	if err != nil {
		return err
	}
	if !ok {
		return ErrSARIFNoRepository
	}
	report.Assets = append(report.Assets, ctis.Asset{
		ID:          sarifRepositoryAssetID,
		Type:        ctis.AssetTypeRepository,
		Value:       repo.URL,
		Criticality: ctis.CriticalityHigh,
	})
	for i := range report.Findings {
		report.Findings[i].AssetRef = sarifRepositoryAssetID
		report.Findings[i].AssetValue = ""
	}
	if repo.Branch != "" && report.Metadata.Branch == nil {
		report.Metadata.Branch = &ctis.BranchInfo{Name: repo.Branch, CommitSHA: repo.CommitSHA, RepositoryURL: repo.URL}
	}
	return nil
}

// sarifConvertOptions builds the conversion options that attach every
// finding of the log to the repository asset (and branch, when known).
func sarifConvertOptions(repo SARIFRepository) *ctis.ConvertOptions {
	opts := ctis.DefaultConvertOptions()
	opts.AssetType = ctis.AssetTypeRepository
	opts.AssetValue = repo.URL
	opts.AssetID = sarifRepositoryAssetID
	if repo.Branch != "" {
		opts.BranchInfo = &ctis.BranchInfo{
			Name:          repo.Branch,
			CommitSHA:     repo.CommitSHA,
			RepositoryURL: repo.URL,
		}
	}
	return opts
}

// validateSARIFRepositoryInput bounds the request-supplied fields.
func validateSARIFRepositoryInput(req SARIFRepository) error {
	if len(req.URL) > maxSARIFRepoURLLen {
		return ErrSARIFInvalidRepositoryURL
	}
	if len(req.Branch) > maxSARIFRefLen || len(req.CommitSHA) > maxSARIFRefLen ||
		strings.ContainsAny(req.Branch+req.CommitSHA, "\r\n\x00") {
		return fmt.Errorf("%w: branch and commit_sha must be at most 255 characters without control characters", shared.ErrValidation)
	}
	return nil
}

// sarifResultFields is the slice of a SARIF result that ctis.FromSARIF drops
// but the findings table stores.
type sarifResultFields struct {
	Runs []struct {
		Results []struct {
			Kind          string `json:"kind"`
			BaselineState string `json:"baselineState"`
		} `json:"results"`
	} `json:"runs"`
}

// applySARIFResultFields copies each result's kind and baselineState onto the
// finding ctis.FromSARIF made from it. FromSARIF converts runs[0] only, one
// finding per result in order, so finding i is result i. If the counts differ
// the mapping is not trusted and nothing is copied. Values are copied as
// written ("notApplicable"); buildFinding normalizes and validates them.
func applySARIFResultFields(report *ctis.Report, sarifData []byte) {
	var doc sarifResultFields
	if err := json.Unmarshal(sarifData, &doc); err != nil || len(doc.Runs) == 0 {
		return
	}
	results := doc.Runs[0].Results
	if len(results) != len(report.Findings) {
		return
	}
	for i := range report.Findings {
		if report.Findings[i].Kind == "" {
			report.Findings[i].Kind = results[i].Kind
		}
		if report.Findings[i].BaselineState == "" {
			report.Findings[i].BaselineState = results[i].BaselineState
		}
	}
}
