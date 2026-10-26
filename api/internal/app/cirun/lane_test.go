package cirun

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/ingestjob"
)

type kevSet map[string]bool

func (k kevSet) AnyKEV(_ context.Context, ids []string) (bool, error) {
	if k == nil {
		return false, errors.New("lookup down")
	}
	for _, id := range ids {
		if k[id] {
			return true, nil
		}
	}
	return false, nil
}

// The lane comes from the report's content as the server reads it: a
// critical finding or a KEV CVE is urgent, anything else interactive; a
// lookup failure never promotes.
func TestUploadLane(t *testing.T) {
	vuln := func(sev ctis.Severity, cve string) ctis.Finding {
		return ctis.Finding{Type: ctis.FindingTypeVulnerability, Severity: sev, Vulnerability: &ctis.VulnerabilityDetails{CVEID: cve}}
	}
	cases := []struct {
		name string
		kev  KEVChecker
		f    []ctis.Finding
		want ingestjob.Lane
	}{
		{"nothing", kevSet{}, nil, ingestjob.LaneInteractive},
		{"critical", kevSet{}, []ctis.Finding{vuln(ctis.SeverityCritical, "")}, ingestjob.LaneUrgent},
		{"kev cve", kevSet{"CVE-2021-44228": true}, []ctis.Finding{vuln(ctis.SeverityMedium, "cve-2021-44228")}, ingestjob.LaneUrgent},
		{"other cve", kevSet{"CVE-2021-44228": true}, []ctis.Finding{vuln(ctis.SeverityHigh, "CVE-2020-0001")}, ingestjob.LaneInteractive},
		{"lookup down", kevSet(nil), []ctis.Finding{vuln(ctis.SeverityHigh, "CVE-2021-44228")}, ingestjob.LaneInteractive},
		{"no checker", nil, []ctis.Finding{vuln(ctis.SeverityHigh, "CVE-2021-44228")}, ingestjob.LaneInteractive},
	}
	for _, c := range cases {
		s := &Service{kev: c.kev}
		if got := s.uploadLane(context.Background(), &ctis.Report{Findings: c.f}); got != c.want {
			t.Errorf("%s: lane %s, want %s", c.name, got, c.want)
		}
	}
}
