package finding

import (
	"slices"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/approvalpolicy"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

func TestChangedSinceRequest(t *testing.T) {
	eval := func(reasons string) []byte {
		return []byte(`{"kind":"accepted","risk_class":"high","tier":"peer","reasons":[` + reasons + `]}`)
	}
	epss := 0.9
	cases := []struct {
		name   string
		status string
		eval   []byte
		now    approvalpolicy.Facts
		want   []string
	}{
		{"became KEV", "accepted", eval(`"severity_high"`), approvalpolicy.Facts{Severity: "high", KEV: true}, []string{"kev"}},
		{"nothing new", "accepted", eval(`"severity_high","organization_policy"`), approvalpolicy.Facts{Severity: "high"}, nil},
		{"severity and EPSS rose", "false_positive", eval(``), approvalpolicy.Facts{Severity: "critical", EPSS: &epss},
			[]string{"severity_critical", "epss_at_or_above_threshold"}},
		{"exposure counts for an acceptance", "accepted", eval(``), approvalpolicy.Facts{Severity: "low", InternetExposed: true}, []string{"internet_exposed"}},
		{"exposure does not count for a false positive", "false_positive", eval(``), approvalpolicy.Facts{Severity: "low", InternetExposed: true}, nil},
		{"request before the policy", "accepted", nil, approvalpolicy.Facts{KEV: true}, nil},
		{"not an approval status", "resolved", eval(``), approvalpolicy.Facts{KEV: true}, nil},
		{"unreadable evaluation", "accepted", []byte(`{`), approvalpolicy.Facts{KEV: true}, nil},
	}
	for _, c := range cases {
		a := &vulnerability.Approval{RequestedStatus: c.status, PolicyEval: c.eval}
		if got := changedSinceRequest(a, c.now, approvalpolicy.PlatformEPSSThreshold); !slices.Equal(got, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}
