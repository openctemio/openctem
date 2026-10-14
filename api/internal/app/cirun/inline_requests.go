package cirun

import (
	"context"
	"strings"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/cirun"
)

// An inline ignore comment (nosemgrep, noopengrep, nosem) or a scanner ignore
// file in the repository is the author's claim, never a decision: the CI job
// runs the scanner so that such results are still reported, and the gate
// counts them. From a verified default-branch run (code already reviewed and
// merged) each claim becomes a pending suppression request for the security
// team, requested by the CI identity, with an expiry.

// maxInlineRequests bounds the requests one upload makes.
const maxInlineRequests = 20

// inlineRequestDays is how long a request asks for.
const inlineRequestDays = 90

// propIgnoreFilePaths is the report property in which the CI job lists the
// path patterns of the repository's scanner ignore file.
const propIgnoreFilePaths = "ignore_file_paths"

// requestInlineIgnores turns the in-source suppressions and ignore-file
// patterns of an uploaded report into pending requests.
func (s *Service) requestInlineIgnores(ctx context.Context, run *cirun.Run, report *ctis.Report) {
	if report == nil || !run.IsDefaultBranch || run.Fork || !run.CommitVerified {
		return
	}
	policy, _, err := s.ResolvePolicy(ctx, run.TenantID, run.RepositoryAssetID)
	if err != nil || !policy.AllowRepoPolicy {
		return
	}
	expires := s.now().UTC().AddDate(0, 0, inlineRequestDays).Format("2006-01-02")
	var inline, files []cirun.RepoException
	seen := map[string]bool{}
	for i := range report.Findings {
		f := &report.Findings[i]
		if f.Suppression == nil || f.Suppression.Kind != "in_source" || f.Location == nil {
			continue
		}
		rule, path := strings.TrimSpace(f.RuleID), strings.TrimSpace(f.Location.Path)
		if rule == "" || path == "" || len(rule) > 255 || len(path) > 500 || seen[rule+"\x00"+path] {
			continue
		}
		seen[rule+"\x00"+path] = true
		if len(inline) < maxInlineRequests {
			inline = append(inline, cirun.RepoException{RuleID: rule, Path: path, Expires: expires,
				Reason: "an inline ignore comment marks this result", Source: cirun.ExceptionSourceInline})
		}
	}
	if raw, ok := report.Metadata.Properties[propIgnoreFilePaths].([]any); ok {
		for _, v := range raw {
			p, _ := v.(string)
			p = strings.TrimSpace(p)
			if p == "" || len(p) > 500 || seen["\x00"+p] || len(files) >= maxInlineRequests {
				continue
			}
			seen["\x00"+p] = true
			files = append(files, cirun.RepoException{Path: p, Expires: expires,
				Reason: "the scanner ignore file excludes this path", Source: cirun.ExceptionSourceIgnoreFile})
		}
	}
	s.requestRepoExceptions(ctx, run, inline)
	s.requestRepoExceptions(ctx, run, files)
}
