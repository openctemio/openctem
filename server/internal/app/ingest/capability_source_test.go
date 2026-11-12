package ingest

import (
	"testing"

	"github.com/openctemio/contract/capability"
	"github.com/openctemio/ctis/v2"

	"github.com/openctemio/openctem/server/pkg/domain/vulnerability"
)

// A report bound to a capability takes its technique from it: a third-party
// tool needs no name-table entry.
func TestReportFindingSourceByCapability(t *testing.T) {
	r := withCapability(&ctis.Report{Tool: &ctis.Tool{Name: "acme-leaks"}}, "secrets.code@1")
	if got := reportFindingSource(r); got != vulnerability.FindingSourceSecret {
		t.Fatalf("source %s", got)
	}
	setReportCapability(r, "") // unbound: the name rules apply
	r.Tool.Name = "semgrep"
	if got := reportFindingSource(r); got != vulnerability.FindingSourceSAST {
		t.Fatalf("name fallback %s", got)
	}
	if got := reportFindingSource(withCapability(&ctis.Report{}, "sast.code@1")); got != vulnerability.FindingSourceSAST {
		t.Fatalf("toolless bound report %s", got)
	}
	if reportFindingSource(nil) != detectFindingSource("") {
		t.Fatal("nil report")
	}
	// Every routed capability that emits findings has a technique.
	for _, c := range capability.All() {
		if c.MayEmit("finding:vulnerability") || c.MayEmit("finding:secret") || c.MayEmit("finding:misconfiguration") {
			if _, ok := capabilitySource[c.ID]; !ok && c.ID != "verify.finding" && c.Status != capability.StatusLater {
				t.Errorf("%s emits findings but has no technique", c.ID)
			}
		}
	}
}

// SECURITY: a bound secrets.code report is masked as a secret scan even
// when its tool name is unknown.
func TestBoundSecretsReportIsRedacted(t *testing.T) {
	raw := "ghp_0123456789abcdefghijABCDEFGHIJ0123456"
	r := &ctis.Report{Tool: &ctis.Tool{Name: "acme-leaks"},
		Findings: []ctis.Finding{{Type: ctis.FindingTypeVulnerability, Title: "token " + raw,
			Location: &ctis.FindingLocation{Path: "a.env", Snippet: raw}}}}
	setReportCapability(r, "secrets.code@1")
	redactReportSecrets(r)
	if r.Findings[0].Location.Snippet == raw {
		t.Fatal("the snippet of a bound secret scan was kept")
	}
}

// openctem-ci puts the capability in metadata.extensions["io.openctem"]: the
// IaC job of the trivy image (techniques sca, iac, secret) is IaC, not SCA.
func TestReportFindingSourceFromCapabilityProperty(t *testing.T) {
	r := withCapability(&ctis.Report{Tool: &ctis.Tool{Name: "trivy", Techniques: []ctis.Technique{ctis.TechniqueSCA, ctis.TechniqueIaC, ctis.TechniqueSecret}}}, "iac.misconfig@1")
	if got := reportFindingSource(r); got != vulnerability.FindingSourceIaC {
		t.Fatalf("capability property: got %s, want iac", got)
	}
}

// An unbound multi-capability report (a native trivy JSON with dependencies,
// misconfigurations and secrets) files each finding by its type; a bound one
// keeps the capability's technique.
func TestFindingTechniqueByTypeWhenUnbound(t *testing.T) {
	r := &ctis.Report{Tool: &ctis.Tool{Name: "trivy", Techniques: []ctis.Technique{ctis.TechniqueSCA, ctis.TechniqueIaC, ctis.TechniqueSecret}}}
	for typ, want := range map[ctis.FindingType]vulnerability.FindingSource{
		ctis.FindingTypeVulnerability:    vulnerability.FindingSourceSCA,
		ctis.FindingTypeMisconfiguration: vulnerability.FindingSourceIaC,
		ctis.FindingTypeSecret:           vulnerability.FindingSourceSecret,
	} {
		if got := findingTechnique(r, &ctis.Finding{Type: typ}); got != want {
			t.Errorf("%s: got %s, want %s", typ, got, want)
		}
	}
	setReportCapability(r, "sca.deps@1")
	if got := findingTechnique(r, &ctis.Finding{Type: ctis.FindingTypeMisconfiguration}); got != vulnerability.FindingSourceSCA {
		t.Errorf("bound report keeps its technique, got %s", got)
	}
	sast := &ctis.Report{Tool: &ctis.Tool{Name: "opengrep"}}
	if got := findingTechnique(sast, &ctis.Finding{Type: ctis.FindingTypeSecret}); got != vulnerability.FindingSourceSAST {
		t.Errorf("only an SCA fallback is split by type, got %s", got)
	}
}

// A bound capability decides the source: finding.technique never overrides
// it. Unbound, the finding's technique wins over the tool's techniques; an
// unknown technique falls back to them. The claimed technique is recorded
// apart, only when it is a known one.
func TestFindingTechnique_BoundCapabilityWins(t *testing.T) {
	bound := withCapability(&ctis.Report{Tool: &ctis.Tool{Name: "trivy", Techniques: []ctis.Technique{ctis.TechniqueSCA}}}, "sca.deps@1")
	for _, tech := range []ctis.Technique{ctis.TechniqueSecret, ctis.TechniqueIaC, ctis.TechniqueDAST, ctis.Technique("nonsense")} {
		if got := findingTechnique(bound, &ctis.Finding{Technique: tech}); got != vulnerability.FindingSourceSCA {
			t.Errorf("bound sca.deps, finding.technique %s: got %s, want sca", tech, got)
		}
	}
	unbound := &ctis.Report{Tool: &ctis.Tool{Name: "trivy", Techniques: []ctis.Technique{ctis.TechniqueSCA}}}
	if got := findingTechnique(unbound, &ctis.Finding{Technique: ctis.TechniqueSecret}); got != vulnerability.FindingSourceSecret {
		t.Errorf("unbound, finding.technique secret: got %s", got)
	}
	if got := findingTechnique(unbound, &ctis.Finding{Technique: ctis.Technique("nonsense")}); got != vulnerability.FindingSourceSCA {
		t.Errorf("unbound, unknown technique falls back to the report: got %s", got)
	}
	if got := findingClaimedTechnique(&ctis.Finding{Technique: ctis.TechniqueSecret}); got != string(ctis.TechniqueSecret) {
		t.Errorf("claimed technique = %q, want secret", got)
	}
	if got := findingClaimedTechnique(&ctis.Finding{Technique: ctis.Technique("x<script>")}); got != "" {
		t.Errorf("unknown claimed technique recorded: %q", got)
	}
}

// Tool techniques decide the source of an unbound report; with no technique
// and an unknown tool name the source is external.
func TestReportFindingSourceByToolTechniques(t *testing.T) {
	for tech, want := range map[ctis.Technique]vulnerability.FindingSource{
		ctis.TechniqueSAST:   vulnerability.FindingSourceSAST,
		ctis.TechniqueSecret: vulnerability.FindingSourceSecret,
		ctis.TechniqueIaC:    vulnerability.FindingSourceIaC,
		ctis.TechniqueDAST:   vulnerability.FindingSourceDAST,
		ctis.TechniqueVA:     vulnerability.FindingSourceVA,
	} {
		r := &ctis.Report{Tool: &ctis.Tool{Name: "acme-unknown", Techniques: []ctis.Technique{tech}}}
		if got := reportFindingSource(r); got != want {
			t.Errorf("technique %s: got %s, want %s", tech, got, want)
		}
	}
	if got := reportFindingSource(&ctis.Report{Tool: &ctis.Tool{Name: "acme-unknown"}}); got != vulnerability.FindingSourceExternal {
		t.Errorf("no technique, unknown tool: got %s, want external", got)
	}
}

// A trivy report without techniques is filed by the tool name (container),
// whatever the finding type: only an SCA report is split by finding type.
func TestFindingTechniqueTrivyByNameIsNotSplit(t *testing.T) {
	r := &ctis.Report{Tool: &ctis.Tool{Name: "trivy"}}
	if got := reportFindingSource(r); got != vulnerability.FindingSourceContainer {
		t.Fatalf("trivy by name: got %s", got)
	}
	for _, typ := range []ctis.FindingType{ctis.FindingTypeSecret, ctis.FindingTypeMisconfiguration, ctis.FindingTypeVulnerability} {
		if got := findingTechnique(r, &ctis.Finding{Type: typ}); got != vulnerability.FindingSourceContainer {
			t.Errorf("%s finding: got %s, want container", typ, got)
		}
	}
	// With the sca technique the type decides (the fallback).
	r.Tool.Techniques = []ctis.Technique{ctis.TechniqueSCA}
	if got := findingTechnique(r, &ctis.Finding{Type: ctis.FindingTypeSecret}); got != vulnerability.FindingSourceSecret {
		t.Errorf("sca report, secret finding: got %s", got)
	}
	if got := findingTechnique(r, &ctis.Finding{Type: ctis.FindingTypeMisconfiguration}); got != vulnerability.FindingSourceIaC {
		t.Errorf("sca report, misconfiguration finding: got %s", got)
	}
	if got := findingTechnique(r, &ctis.Finding{Type: ctis.FindingTypeVulnerability}); got != vulnerability.FindingSourceSCA {
		t.Errorf("sca report, vulnerability finding: got %s", got)
	}
	if got := findingTechnique(nil, nil); got != detectFindingSource("") {
		t.Errorf("nil: got %s", got)
	}
}
