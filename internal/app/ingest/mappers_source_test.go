package ingest

import (
	"testing"

	"github.com/openctemio/api/pkg/domain/vulnerability"
)

// detectFindingSource used to end in `default: return FindingSourceSAST`. Every
// tool it did not recognize — Tenable, Nessus, DefectDojo, anything new — was
// therefore recorded as static code analysis. That is not a loose label, it is
// a false one, and it is why "which findings came from our VA scanner" has no
// answer in the existing data.
func TestDetectFindingSource_UnknownToolIsNotClaimedToBeSAST(t *testing.T) {
	for _, tool := range []string{"", "some-new-scanner", "acme-appsec", "burp"} {
		got := detectFindingSource(tool, nil)
		if got == vulnerability.FindingSourceSAST {
			t.Errorf("detectFindingSource(%q, nil) = %q; an unrecognized tool must not be "+
				"reported as static code analysis", tool, got)
		}
		if got != vulnerability.FindingSourceExternal {
			t.Errorf("detectFindingSource(%q, nil) = %q, want %q",
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
		{"codeql", vulnerability.FindingSourceSAST},
		{"snyk", vulnerability.FindingSourceSCA},
		{"nuclei", vulnerability.FindingSourceDAST},
		{"gitleaks", vulnerability.FindingSourceSecret},
		{"trivy", vulnerability.FindingSourceContainer},
		{"checkov", vulnerability.FindingSourceIaC},
	}

	for _, c := range cases {
		if got := detectFindingSource(c.tool, nil); got != c.want {
			t.Errorf("detectFindingSource(%q, nil) = %q, want %q", c.tool, got, c.want)
		}
	}
}

// Capabilities win over the tool name. This is the mechanism the importers now
// use, and it matters because `?tool=` is caller-controlled: naming an upload
// "trivy" must not be able to steer a Tenable report into the container bucket
// once the importer has declared what it actually is.
func TestDetectFindingSource_CapabilitiesOutrankToolName(t *testing.T) {
	cases := []struct {
		name string
		tool string
		caps []string
		want vulnerability.FindingSource
	}{
		{"nessus converter", "trivy", []string{"va"}, vulnerability.FindingSourceVA},
		{"defectdojo converter", "trivy", []string{"external"}, vulnerability.FindingSourceExternal},
		{"recon", "semgrep", []string{"recon"}, vulnerability.FindingSourceEASM},
		{"cloud", "semgrep", []string{"cspm"}, vulnerability.FindingSourceCSPM},
		{"sast still works", "tenable", []string{"sast"}, vulnerability.FindingSourceSAST},
	}

	for _, c := range cases {
		if got := detectFindingSource(c.tool, c.caps); got != c.want {
			t.Errorf("%s: detectFindingSource(%q, %v) = %q, want %q",
				c.name, c.tool, c.caps, got, c.want)
		}
	}
}

// Whatever it returns must be storable, or ingest fails at insert with a
// constraint violation rather than a validation error.
func TestDetectFindingSource_AlwaysReturnsAValidSource(t *testing.T) {
	tools := []string{"", "tenable", "semgrep", "trivy", "nmap", "prowler", "who-knows"}
	capSets := [][]string{nil, {}, {"unrecognized"}, {"va"}, {"external"}}

	for _, tool := range tools {
		for _, caps := range capSets {
			got := detectFindingSource(tool, caps)
			if !got.IsValid() {
				t.Errorf("detectFindingSource(%q, %v) returned %q, which fails IsValid()",
					tool, caps, got)
			}
		}
	}
}
