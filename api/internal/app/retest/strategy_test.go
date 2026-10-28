package retest

import (
	"testing"

	retestdom "github.com/openctemio/openctem/api/pkg/domain/retest"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/softwarematch"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/domain/vulnmatch"
)

func finding(t *testing.T, src vulnerability.FindingSource, tool, rule string) *vulnerability.Finding {
	t.Helper()
	f, err := vulnerability.NewFinding(shared.NewID(), shared.NewID(), src, tool, vulnerability.SeverityHigh, "m")
	if err != nil {
		t.Fatal(err)
	}
	f.SetRuleID(rule)
	return f
}

func TestStrategyOf_FollowsProvenance(t *testing.T) {
	secret := finding(t, vulnerability.FindingSourceSecret, "betterleaks", "aws-key")
	imported := finding(t, vulnerability.FindingSourceVA, "tenable", "19506")
	imported.SetIngestChannel(vulnerability.IngestChannelIntegration)
	manualChannel := finding(t, vulnerability.FindingSourceVA, "scanner", "R-1")
	manualChannel.SetIngestChannel(vulnerability.IngestChannelManual)
	cases := []struct {
		name   string
		f      *vulnerability.Finding
		chk    *CustomCheck
		kind   string
		reason string
		tool   string
	}{
		{"nuclei template", finding(t, vulnerability.FindingSourceDAST, "nuclei", "apache-detect"), nil, StrategyTemplate, "", "nuclei"},
		{"version match", finding(t, vulnerability.FindingSourceVA, softwarematch.ToolName, "CVE-2023-44487"), nil, StrategyVersionRecheck, "", ""},
		{"imported scanner finding", imported, nil, StrategyTemplate, "", "tenable"},
		{"manual", finding(t, vulnerability.FindingSourceManual, "manual", ""), nil, StrategyNone, ReasonNoAutomaticRetest, ""},
		{"bug bounty", finding(t, vulnerability.FindingSourceBugBounty, "bug-bounty", ""), nil, StrategyNone, ReasonNoAutomaticRetest, ""},
		{"pentest", finding(t, vulnerability.FindingSourcePentest, "pentest", ""), nil, StrategyNone, ReasonNoAutomaticRetest, ""},
		{"manual channel", manualChannel, nil, StrategyNone, ReasonNoAutomaticRetest, ""},
		{"secret", secret, nil, StrategyNone, ReasonSecretNeedsRotation, ""},
		{"custom check wins", finding(t, vulnerability.FindingSourceBugBounty, "bug-bounty", ""), &CustomCheck{NucleiID: "retest-check-1"}, StrategyCustomCheck, "", "nuclei"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st, reason := strategyOf(tc.f, tc.chk)
			if st.Kind != tc.kind || reason != tc.reason || st.Tool != tc.tool {
				t.Fatalf("got %+v %q, want %s %q tool %q", st, reason, tc.kind, tc.reason, tc.tool)
			}
		})
	}
}

func TestFingerprintToolFor(t *testing.T) {
	cases := []struct {
		link softwarematch.FindingLink
		want string
	}{
		{softwarematch.FindingLink{Source: "technology"}, "httpx"},
		{softwarematch.FindingLink{Source: "service"}, "httpx"},
		{softwarematch.FindingLink{Source: "service", Location: "tcp/22", Port: 22}, "naabu"},
		{softwarematch.FindingLink{Source: "open_port", Location: "tcp/8080"}, "naabu"},
		{softwarematch.FindingLink{Source: "package"}, ""},
		{softwarematch.FindingLink{Source: "os"}, ""},
		{softwarematch.FindingLink{}, ""},
	}
	for _, tc := range cases {
		if got := fingerprintToolFor(&tc.link); got != tc.want {
			t.Errorf("%+v: %q, want %q", tc.link, got, tc.want)
		}
	}
}

func TestFingerprintTarget(t *testing.T) {
	cases := []struct {
		name string
		link softwarematch.FindingLink
		want string
	}{
		{"https://shop.example.com/a", softwarematch.FindingLink{}, "shop.example.com"},
		{"shop.example.com", softwarematch.FindingLink{Port: 8443}, "shop.example.com:8443"},
		{"shop.example.com", softwarematch.FindingLink{Location: "tcp/22"}, "shop.example.com:22"},
		{"2001:db8::1", softwarematch.FindingLink{Port: 443}, "[2001:db8::1]:443"},
	}
	for _, tc := range cases {
		if got := fingerprintTarget(tc.name, &tc.link); got != tc.want {
			t.Errorf("%s %+v: %q, want %q", tc.name, tc.link, got, tc.want)
		}
	}
}

func TestPickTemplateSensor(t *testing.T) {
	a, b, c := shared.NewID(), shared.NewID(), shared.NewID()
	cases := []struct {
		name     string
		cands    []SensorCandidate
		sighting *shared.ID
		release  string
		pin      *shared.ID
		ok       bool
	}{
		{"no candidate list: no choice", nil, nil, "v10.2.0", nil, true},
		{"sighting sensor first", []SensorCandidate{{ID: a, TemplatesVersion: "v11.0.0"}, {ID: b, TemplatesVersion: "v9.0.0"}}, &b, "v10.2.0", &b, true},
		{"no release to compare: any sensor", []SensorCandidate{{ID: a}}, nil, "", nil, true},
		{"newest at or above the release", []SensorCandidate{{ID: a, TemplatesVersion: "v10.2.0"}, {ID: b, TemplatesVersion: "v10.4.1"}, {ID: c, TemplatesVersion: "v9.9.9"}}, nil, "v10.2.0", &b, true},
		{"unknown release over older", []SensorCandidate{{ID: a, TemplatesVersion: "v9.0.0"}, {ID: b}}, nil, "v10.2.0", &b, true},
		{"all older", []SensorCandidate{{ID: a, TemplatesVersion: "v9.0.0"}, {ID: b, TemplatesVersion: "10.1.9"}}, nil, "v10.2.0", nil, false},
		{"sighting sensor offline", []SensorCandidate{{ID: a, TemplatesVersion: "v9.0.0"}}, &c, "v10.2.0", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pin, ok := PickTemplateSensor(tc.cands, tc.sighting, tc.release)
			if ok != tc.ok || (pin == nil) != (tc.pin == nil) || (pin != nil && *pin != *tc.pin) {
				t.Fatalf("pin %v ok %v, want %v %v", pin, ok, tc.pin, tc.ok)
			}
		})
	}
}

func TestCompareRelease(t *testing.T) {
	cases := []struct {
		a, b  string
		cmp   int
		known bool
	}{
		{"v10.2.7", "v10.2.7", 0, true},
		{"v10.2.10", "v10.2.9", 1, true},
		{"10.2", "v10.2.1", -1, true},
		{"latest", "v10.0.0", 0, false},
		{"", "v1", 0, false},
	}
	for _, tc := range cases {
		cmp, known := compareRelease(tc.a, tc.b)
		if cmp != tc.cmp || known != tc.known {
			t.Errorf("%s vs %s: %d %v", tc.a, tc.b, cmp, known)
		}
	}
}

func TestDecideVersion(t *testing.T) {
	link := softwarematch.FindingLink{ProductID: shared.NewID(), VersionID: shared.NewID(), Product: "nginx", Version: "1.25.2"}
	ranges := []softwarematch.AffectedRange{{ID: 1, Range: vulnmatch.Range{ID: "1", VulnID: "CVE-2023-44487", Scheme: vulnmatch.SchemeGeneric, End: "1.25.3"}}}
	other := func(raw string, comparable bool) softwarematch.ObservedVersion {
		return softwarematch.ObservedVersion{VersionID: shared.NewID(), Raw: raw, Scheme: vulnmatch.SchemeGeneric, Comparable: comparable}
	}
	cases := []struct {
		name     string
		observed []softwarematch.ObservedVersion
		outcome  retestdom.Outcome
		code     retestdom.ReasonCode
	}{
		{"nothing seen", nil, retestdom.OutcomeInconclusive, retestdom.ReasonVersionNotObserved},
		{"same version again", []softwarematch.ObservedVersion{{VersionID: link.VersionID, Raw: "1.25.2"}}, retestdom.OutcomeStillVulnerable, retestdom.ReasonVersionStillAffected},
		{"upgraded but still affected", []softwarematch.ObservedVersion{other("1.25.2.1", true)}, retestdom.OutcomeStillVulnerable, retestdom.ReasonVersionStillAffected},
		{"upgraded out of range", []softwarematch.ObservedVersion{other("1.25.3", true)}, retestdom.OutcomeConfirmedFixed, retestdom.ReasonVersionNotAffected},
		{"unparsed version", []softwarematch.ObservedVersion{other("1.25.x", false)}, retestdom.OutcomeInconclusive, retestdom.ReasonVersionNotObserved},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := DecideVersion(link, "CVE-2023-44487", tc.observed, ranges)
			if v.Outcome != tc.outcome || v.Code != tc.code || v.Reason == "" {
				t.Fatalf("got %+v, want %s/%s", v, tc.outcome, tc.code)
			}
		})
	}
}
