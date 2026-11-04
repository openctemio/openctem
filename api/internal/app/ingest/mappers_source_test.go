package ingest

import (
	"testing"

	"github.com/openctemio/ctis/v2"

	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// detectFindingSource used to end in `default: return FindingSourceSAST`. Every
// tool it did not recognize — Tenable, Nessus, DefectDojo, anything new — was
// therefore recorded as static code analysis. That is not a loose label, it is
// a false one, and it is why "which findings came from our VA scanner" has no
// answer in the existing data.
func TestDetectFindingSource_UnknownToolIsNotClaimedToBeSAST(t *testing.T) {
	// "burp" used to be here as an example of an unknown tool. It is a DAST
	// scanner and is now in the tool table, so it belongs in the ByToolName
	// case instead — an unknown-tool test needs names that are genuinely
	// unknown.
	for _, tool := range []string{"", "some-new-scanner", "acme-appsec", "internal-thing-2024"} {
		got := detectFindingSource(tool)
		if got == vulnerability.FindingSourceSAST {
			t.Errorf("detectFindingSource(%q) = %q; an unrecognized tool must not be "+
				"reported as static code analysis", tool, got)
		}
		if got != vulnerability.FindingSourceExternal {
			t.Errorf("detectFindingSource(%q) = %q, want %q",
				tool, got, vulnerability.FindingSourceExternal)
		}
	}
}

func TestDetectFindingSource_ByToolName(t *testing.T) {
	cases := []struct {
		tool string
		want vulnerability.FindingSource
	}{
		// The two importers that were landing as SAST.
		{"tenable", vulnerability.FindingSourceVA},
		{"nessus", vulnerability.FindingSourceVA},
		{"Qualys", vulnerability.FindingSourceVA},
		{"openvas", vulnerability.FindingSourceVA},

		{"nmap", vulnerability.FindingSourceEASM},
		{"naabu", vulnerability.FindingSourceEASM},
		{"subfinder", vulnerability.FindingSourceEASM},
		{"httpx", vulnerability.FindingSourceEASM},

		{"prowler", vulnerability.FindingSourceCSPM},
		{"scoutsuite", vulnerability.FindingSourceCSPM},

		// Unchanged behavior, asserted so the additions cannot regress it.
		{"semgrep", vulnerability.FindingSourceSAST},
		{"opengrep", vulnerability.FindingSourceSAST},
		{"codeql", vulnerability.FindingSourceSAST},
		{"snyk", vulnerability.FindingSourceSCA},
		{"nuclei", vulnerability.FindingSourceDAST},
		{"betterleaks", vulnerability.FindingSourceSecret},
		{"burp", vulnerability.FindingSourceDAST},
		{"trivy", vulnerability.FindingSourceContainer},
		{"checkov", vulnerability.FindingSourceIaC},
	}

	for _, c := range cases {
		if got := detectFindingSource(c.tool); got != c.want {
			t.Errorf("detectFindingSource(%q) = %q, want %q", c.tool, got, c.want)
		}
	}
}

// Techniques win over the tool name. This is the mechanism producers use, and
// it matters because `?tool=` is caller-controlled: naming an upload "trivy"
// must not be able to steer a Tenable report into the container bucket once
// the producer has declared what it actually is.
func TestDetectFindingSource_TechniquesOutrankToolName(t *testing.T) {
	cases := []struct {
		name string
		tool string
		tech []ctis.Technique
		want vulnerability.FindingSource
	}{
		{"nessus converter", "trivy", []ctis.Technique{ctis.TechniqueVA}, vulnerability.FindingSourceVA},
		{"easm producer", "semgrep", []ctis.Technique{ctis.TechniqueEASM}, vulnerability.FindingSourceEASM},
		{"cloud", "semgrep", []ctis.Technique{ctis.TechniqueCSPM}, vulnerability.FindingSourceCSPM},
		{"sast still works", "tenable", []ctis.Technique{ctis.TechniqueSAST}, vulnerability.FindingSourceSAST},
		// An old capability token is no technique: the name decides.
		{"old token is ignored", "tenable", []ctis.Technique{"portscan"}, vulnerability.FindingSourceVA},
	}

	for _, c := range cases {
		if got := detectFindingSource(c.tool, c.tech...); got != c.want {
			t.Errorf("%s: detectFindingSource(%q, %v) = %q, want %q",
				c.name, c.tool, c.tech, got, c.want)
		}
	}
}

// Whatever it returns must be storable, or ingest fails at insert with a
// constraint violation rather than a validation error.
func TestDetectFindingSource_AlwaysReturnsAValidSource(t *testing.T) {
	tools := []string{"", "tenable", "semgrep", "trivy", "nmap", "prowler", "who-knows"}
	capSets := [][]ctis.Technique{nil, {}, {"unrecognized"}, {ctis.TechniqueVA}, {ctis.TechniqueBAS}}

	for _, tool := range tools {
		for _, caps := range capSets {
			got := detectFindingSource(tool, caps...)
			if !got.IsValid() {
				t.Errorf("detectFindingSource(%q, %v) returned %q, which fails IsValid()",
					tool, caps, got)
			}
		}
	}
}

// The provenance channel comes from ctis.ReportMetadata.Channel, which the
// scan workflow already carried and the processor discarded. Unrecognized values
// must not be guessed: the column stays NULL, which reads as "unrecorded"
// rather than as a confident wrong answer.
func TestIngestChannelFromCTIS(t *testing.T) {
	cases := []struct {
		in    string
		want  vulnerability.IngestChannel
		valid bool
	}{
		{"scanner", vulnerability.IngestChannelScanner, true},
		{"integration", vulnerability.IngestChannelIntegration, true},
		{"collector", vulnerability.IngestChannelCollector, true},
		{"manual", vulnerability.IngestChannelManual, true},
		{"  Scanner  ", vulnerability.IngestChannelScanner, true},
		{"INTEGRATION", vulnerability.IngestChannelIntegration, true},

		{"", "", false},
		{"sensor", "", false},
		{"unknown", "", false},
		{"scanner-ish", "", false},
	}

	for _, c := range cases {
		got, ok := vulnerability.IngestChannelFromCTIS(c.in)
		if ok != c.valid {
			t.Errorf("IngestChannelFromCTIS(%q) ok = %v, want %v", c.in, ok, c.valid)
		}
		if got != c.want {
			t.Errorf("IngestChannelFromCTIS(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
