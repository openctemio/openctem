package cirun

import (
	"context"
	"strings"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/ingestjob"
)

// KEVChecker reports whether any of the CVE ids is in the KEV catalog
// (postgres.KEVLookup).
type KEVChecker interface {
	AnyKEV(ctx context.Context, cveIDs []string) (bool, error)
}

// SetKEVChecker lets a CI upload with a KEV finding take the urgent lane.
func (s *Service) SetKEVChecker(k KEVChecker) { s.kev = k }

// maxLaneCVEs bounds the CVE ids one upload's lane looks up.
const maxLaneCVEs = 1000

// uploadLane is the lane of a CI upload, decided by the server from the
// decoded report (never from a field the job sets): urgent when a finding is
// critical or names a CVE in the KEV catalog, interactive otherwise (a
// gate waits on every CI upload). A lookup error keeps the interactive lane:
// the lane orders work, it never decides what is applied.
func (s *Service) uploadLane(ctx context.Context, report *ctis.Report) ingestjob.Lane {
	if report == nil {
		return ingestjob.LaneInteractive
	}
	var cves []string
	for i := range report.Findings {
		f := &report.Findings[i]
		if f.Severity == ctis.SeverityCritical {
			return ingestjob.LaneUrgent
		}
		if v := f.Vulnerability; v != nil && len(cves) < maxLaneCVEs {
			if id := strings.ToUpper(strings.TrimSpace(v.CVEID)); strings.HasPrefix(id, "CVE-") {
				cves = append(cves, id)
			}
			for _, raw := range v.CVEIDs {
				if id := strings.ToUpper(strings.TrimSpace(raw)); strings.HasPrefix(id, "CVE-") && len(cves) < maxLaneCVEs {
					cves = append(cves, id)
				}
			}
		}
	}
	if len(cves) == 0 || s.kev == nil {
		return ingestjob.LaneInteractive
	}
	if hit, err := s.kev.AnyKEV(ctx, cves); err == nil && hit {
		return ingestjob.LaneUrgent
	}
	return ingestjob.LaneInteractive
}
