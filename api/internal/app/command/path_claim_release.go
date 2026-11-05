package command

// The path discovery ledger claim of a job that sent no request
// (docs/architecture/web-discovery.md). The web job guard claims an origin's
// 30 days when it stores the job. A sensor that probed an origin and had no
// candidate left to request (an empty list, or every candidate refused by the
// scope) reports the gap no_candidates; the origin is then given back, so a
// job that did nothing does not hold it for a month or spend the daily
// request budget.

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"

	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	scanrundom "github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// PathClaimReleaser gives back the ledger claims of a command
// (coverage.PathDiscoveryPolicy).
type PathClaimReleaser interface {
	ReleasePathDispatch(ctx context.Context, tenantID, commandID shared.ID, origins []string) error
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
	if err := s.pathClaims.ReleasePathDispatch(ctx, cmd.TenantID, cmd.ID, origins); err != nil {
		s.logger.Warn("path discovery: claims of an empty job not released", "command_id", cmd.ID.String(), "error", logger.SanitizeError(err))
	}
}

// emptyDiscoveryOrigins returns the job targets the result names, in its
// coverage gaps, with the reason no_candidates. The result is the sensor's:
// a gap names a host of the job's own targets or is ignored, so a sensor
// cannot release the claim of an origin it was not given.
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
	for _, g := range gaps {
		if g.Reason != scanrundom.GapReasonNoCandidates {
			continue
		}
		for _, t := range targets {
			if sameOrigin(g.Host, t) {
				out = append(out, t)
			}
		}
	}
	return out
}

// sameOrigin reports whether a gap's host names the target: the origin
// itself, or its host (the sensor reports either).
func sameOrigin(gapHost, target string) bool {
	norm := func(s string) string { return strings.ToLower(strings.TrimRight(strings.TrimSpace(s), "/")) }
	g, t := norm(gapHost), norm(target)
	if g == "" || t == "" {
		return false
	}
	if g == t {
		return true
	}
	u, err := url.Parse(t)
	return err == nil && u.Host != "" && !strings.Contains(g, "://") && g == u.Host
}
