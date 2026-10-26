package findingimport

// Recon results directories (a ZIP detected by its layout as reconFTW
// output, importer.ParseBundle).
//
// Threat model. The directory is untrusted and the uploader may be a
// low-privilege member:
//   - the file's own claim of what is "the target" (report.json) is never
//     used for scope: the organization's scope entries decide, so a file
//     cannot put a third party's domain in scope by naming it as its target;
//   - every host the scope does not cover is a candidate: held for review
//     (ingest.holdImportCandidates), never selected by a scan, never probed
//     (the active-scan gate also refuses what no scope entry covers);
//   - the import is partial coverage: it never closes a finding, never marks
//     a host gone, and a request declaring full coverage is refused;
//   - endpoints land only under origins the uploader may change, with the
//     tenant's path exclusions applied (ingest, processor_endpoints.go);
//   - people and credential files (osint/) are never opened; they are listed
//     as skipped by policy.

import (
	"context"
	"fmt"
	"net"
	"slices"

	"github.com/openctemio/ctis"
	"github.com/openctemio/ctis/importer"
	"github.com/openctemio/ctis/weburl"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/app/scopeauth"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ScopeCover answers which of the given names the organization's scope
// covers (*easm.ActiveGate). A name nothing covers is absent.
type ScopeCover interface {
	CoverOf(ctx context.Context, tenantID shared.ID, targets []string) (map[string]scopeauth.Via, error)
}

// SetScopeCover wires the scope check of bundle hosts. Unwired, every host
// of a bundle is a candidate.
func (s *Service) SetScopeCover(c ScopeCover) { s.cover = c }

// TagCandidate labels a finding on an imported host outside the
// organization's scope.
const TagCandidate = "candidate"

// bundleFormat reports whether a format is a multi-file bundle.
func bundleFormat(f importer.Format) bool { return f == importer.FormatReconFTW }

// assetHost is the host an imported asset names ("" for none).
func assetHost(a *ctis.Asset) string {
	if a.Type == ctis.AssetTypeHTTPService {
		if u, err := weburl.Parse(a.Value); err == nil {
			return u.Host
		}
		return ""
	}
	return a.Value
}

// judgeScope sets properties.import_scope of every host asset of the bundle
// from the organization's scope and returns how many are candidates. The
// importer's own verdict (relative to the file's claimed target) is
// replaced: only the organization's scope entries make a host in_target. A
// scope that cannot be read leaves every host a candidate (fail closed) and
// says so in the issues.
func (s *Service) judgeScope(ctx context.Context, tenantID shared.ID, res *importer.Result) int {
	if res.Report == nil {
		return 0
	}
	var hosts []string
	seen := map[string]bool{}
	for i := range res.Report.Assets {
		a := &res.Report.Assets[i]
		if _, ok := a.Properties[ingest.PropImportScope]; !ok {
			continue
		}
		if h := assetHost(a); h != "" && !seen[h] {
			seen[h] = true
			hosts = append(hosts, h)
		}
	}
	var covered map[string]scopeauth.Via
	if s.cover != nil && len(hosts) > 0 {
		var err error
		if covered, err = s.cover.CoverOf(ctx, tenantID, hosts); err != nil {
			s.logger.Warn("finding import: scope of bundle hosts", "tenant_id", tenantID.String(), "error", err)
			res.Issues = append(res.Issues, importer.Issue{Message: "the organization's scope could not be read; every host is held for review"})
			covered = nil
		}
	}
	candidates := 0
	held := map[string]bool{}
	for i := range res.Report.Assets {
		a := &res.Report.Assets[i]
		if _, ok := a.Properties[ingest.PropImportScope]; !ok {
			continue
		}
		host := assetHost(a)
		verdict := ingest.ImportScopeOutside
		switch _, in := covered[host]; {
		case host != "" && in:
			verdict = ingest.ImportScopeIn
		case net.ParseIP(host) != nil:
			verdict = ingest.ImportScopeUnknown
		}
		a.Properties[ingest.PropImportScope] = verdict
		if verdict != ingest.ImportScopeIn {
			candidates++
			held[a.ID] = true
		}
	}
	// A finding on a host outside the organization's scope stays visible
	// everywhere, labelled with the tag "candidate" so a reader knows the
	// host was not confirmed as theirs.
	for i := range res.Report.Findings {
		f := &res.Report.Findings[i]
		if held[f.AssetRef] && !slices.Contains(f.Tags, TagCandidate) {
			f.Tags = append(f.Tags, TagCandidate)
		}
	}
	if candidates > 0 {
		res.Issues = append(res.Issues, importer.Issue{Message: fmt.Sprintf("%d hosts are outside the organization's scope and wait for review", candidates)})
	}
	return candidates
}
