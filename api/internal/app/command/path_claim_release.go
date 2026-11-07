package command

// The path discovery ledger claim of a job that sent no request
// (docs/architecture/web-discovery.md). The web job guard claims an origin's
// 30 days when it stores the job. A sensor that probed an origin and had no
// candidate left to request (an empty list, or every candidate refused by the
// scope) reports the gap no_candidates; when the result also shows that no
// request was sent, the origin is given back, so a job that did nothing does
// not hold it for a month or spend the daily request budget. The sensor's word
// is not enough to reset the floor again and again: an origin is given back
// once per 30 days (the ledger keeps when).

import (
	"context"
	"encoding/json"
	"slices"
	"strings"

	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	scanrundom "github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// PathClaimReleaser gives back the ledger claims of a command
// (coverage.PathDiscoveryPolicy).
type PathClaimReleaser interface {
	ReleaseEmptyPathDispatch(ctx context.Context, tenantID, commandID shared.ID, origins []string) error
}

// SetPathClaimReleaser wires the release of a path discovery job that sent
// no request. Unwired, the claim stands (the origin waits its 30 days).
func (s *Service) SetPathClaimReleaser(r PathClaimReleaser) { s.pathClaims = r }

// releaseEmptyPathDiscovery releases the claims of the targets a completed
// path discovery command reported as having no candidate to request.
func (s *Service) releaseEmptyPathDiscovery(ctx context.Context, cmd *commanddom.Command) {
	if s.pathClaims == nil || cmd == nil || len(cmd.Result) == 0 {
		return
	}
	job, ok := commanddom.WebJobOf(cmd)
	if !ok || !job.Discovery {
		return
	}
	origins := emptyDiscoveryOrigins(job.Targets, cmd.Result)
	if len(origins) == 0 {
		return
	}
	if err := s.pathClaims.ReleaseEmptyPathDispatch(ctx, cmd.TenantID, cmd.ID, origins); err != nil {
		s.logger.Warn("path discovery: claims of an empty job not released", "command_id", cmd.ID.String(), "error", logger.SanitizeError(err))
	}
}

// emptyDiscoveryOrigins returns the job targets the result names, in its
// coverage gaps, as having no candidate to request: the gap's reason is
// no_candidates, its host is exactly the target's origin (scheme, host and
// port), and nothing in the result says a request was sent to it. The result
// is the sensor's, so it is checked, not believed: the sensor puts every
// reason it met in the gap's detail, and a reason that can only follow a
// request (catch_all, throttled, budget, a blocked or hostile answer...) or a
// second gap on the same origin keeps the claim. A gap names an origin of the
// job's own targets or is ignored.
func emptyDiscoveryOrigins(targets []string, result json.RawMessage) []string {
	var r struct {
		Metadata struct {
			Gaps  json.RawMessage `json:"coverage_gaps"`
			Total int             `json:"coverage_gaps_total"`
		} `json:"metadata"`
	}
	if json.Unmarshal(result, &r) != nil {
		return nil
	}
	gaps, _ := scanrundom.ParseCoverageGaps(r.Metadata.Gaps, r.Metadata.Total)
	var out []string
	for _, t := range targets {
		empty, other := false, false
		for _, g := range gaps {
			if !sameOrigin(g.Host, t) {
				continue
			}
			if g.Reason == scanrundom.GapReasonNoCandidates && noRequestDetail(g.Detail) {
				empty = true
			} else {
				other = true
			}
		}
		if empty && !other && !slices.Contains(out, t) {
			out = append(out, t)
		}
	}
	return out
}

// noRequestDetail reports whether a gap's detail ("reason=count ...") names
// only reasons that exist with no request sent: no_candidates, and the
// candidates the scope filtered out.
func noRequestDetail(detail string) bool {
	for _, f := range strings.Fields(detail) {
		reason, _, _ := strings.Cut(f, "=")
		if reason != scanrundom.GapReasonNoCandidates && reason != scanrundom.GapReasonScopeFiltered {
			return false
		}
	}
	return true
}

// sameOrigin reports whether a gap's host is exactly the target's origin
// (scheme, host and port; case and a trailing slash aside). A bare host does
// not match: it would name every port of it.
func sameOrigin(gapHost, target string) bool {
	norm := func(s string) string { return strings.ToLower(strings.TrimRight(strings.TrimSpace(s), "/")) }
	g, t := norm(gapHost), norm(target)
	if g == "" || t == "" || !strings.Contains(g, "://") {
		return false
	}
	return g == t
}
