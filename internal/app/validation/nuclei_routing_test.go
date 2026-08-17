package validation

import (
	"context"
	"testing"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/logger"
)

// fakeNucleiAvailability stubs the deeper-rung nuclei capability gate.
type fakeNucleiAvailability struct {
	has bool
	err error
}

func (f fakeNucleiAvailability) HasNucleiValidationAgent(_ context.Context, _ shared.ID) (bool, error) {
	return f.has, f.err
}

// newNucleiFinding builds a nuclei-native finding carrying a template id.
func newNucleiFinding(t *testing.T, assetID shared.ID, ruleID string) *vulnerability.Finding {
	t.Helper()
	f, err := vulnerability.NewFinding(
		shared.NewID(), assetID,
		vulnerability.FindingSourceDAST, "nuclei",
		vulnerability.SeverityHigh, "nuclei finding",
	)
	if err != nil {
		t.Fatalf("new finding: %v", err)
	}
	f.SetRuleID(ruleID)
	return f
}

func TestTemplateSignatureAllowed(t *testing.T) {
	cases := []struct {
		sig  string
		want bool
	}{
		{"apache-struts-rce", true},
		{"CVE-2021-44228", true},
		{"log4j-detect", true},
		{"", false},
		{"http-dos", false},           // denial-of-service class
		{"some-fuzz-template", false}, // fuzzing class
		{"intrusive-check", false},    // explicitly intrusive
		{"ssh-brute-force", false},    // brute-force class
		{"ssh-bruteforce", false},
		{"../../etc/passwd", false},        // path traversal
		{"templates/http/cve.yaml", false}, // path selector, not an id
		{"a\\b", false},                    // backslash traversal
	}
	for _, c := range cases {
		if got := templateSignatureAllowed(c.sig); got != c.want {
			t.Errorf("templateSignatureAllowed(%q) = %v, want %v", c.sig, got, c.want)
		}
	}
}

func TestNucleiSignature(t *testing.T) {
	assetID := shared.NewID()

	// nuclei-native finding → its own template id.
	nf := newNucleiFinding(t, assetID, "apache-struts-rce")
	if tmpl, _, ok := nucleiSignature(nf); !ok || tmpl != "apache-struts-rce" {
		t.Errorf("nuclei-native: got tmpl=%q ok=%v, want apache-struts-rce true", tmpl, ok)
	}

	// nuclei-native but destructive template class → rejected.
	dos := newNucleiFinding(t, assetID, "apache-dos")
	if _, _, ok := nucleiSignature(dos); ok {
		t.Error("destructive nuclei template must not be re-run")
	}

	// Non-nuclei finding with no CVE → no signature (falls back to safe-check).
	plain := newTestFinding(t, assetID)
	if _, _, ok := nucleiSignature(plain); ok {
		t.Error("finding with no signature must not route to nuclei")
	}

	// Non-nuclei finding carrying a CVE → CVE→template candidate.
	cveF, err := vulnerability.NewFinding(shared.NewID(), assetID,
		vulnerability.FindingSourceVA, "tenable", vulnerability.SeverityHigh, "tenable finding")
	if err != nil {
		t.Fatalf("new finding: %v", err)
	}
	if err := cveF.SetClassification("CVE-2021-44228", nil, "", nil, nil); err != nil {
		t.Fatalf("set classification: %v", err)
	}
	tmpl, cve, ok := nucleiSignature(cveF)
	if !ok || tmpl != "" || cve != "CVE-2021-44228" {
		t.Errorf("cross-scanner CVE: got tmpl=%q cve=%q ok=%v, want \"\" CVE-2021-44228 true", tmpl, cve, ok)
	}
}

// A nuclei-native finding + an online nuclei agent → route KindNuclei carrying
// the finding's own template id under the nuclei technique.
func TestRunService_ValidateFinding_RoutesNucleiWhenCapable(t *testing.T) {
	assetID := shared.NewID()
	f := newNucleiFinding(t, assetID, "apache-struts-rce")
	a := newTestAsset(t, "example.com")
	disp := &fakeJobDispatcher{id: shared.NewID()}

	svc := NewRunService(fakeFindingLookup{f: f}, fakeAssetLookup{a: a}, disp,
		DefaultSelector{}, []ExecutorKind{KindSafeCheck}, logger.NewNop())
	svc.SetNucleiAvailability(fakeNucleiAvailability{has: true})

	if _, err := svc.ValidateFinding(context.Background(), shared.NewID(), f.ID()); err != nil {
		t.Fatalf("ValidateFinding: %v", err)
	}
	if disp.got.ExecutorKind != KindNuclei {
		t.Errorf("executor kind = %q, want nuclei", disp.got.ExecutorKind)
	}
	if disp.got.Technique != nucleiTechnique {
		t.Errorf("technique = %q, want %q", disp.got.Technique, nucleiTechnique)
	}
	if disp.got.TemplateID != "apache-struts-rce" {
		t.Errorf("template id = %q, want apache-struts-rce", disp.got.TemplateID)
	}
}

// Signature present but NO nuclei agent → fall back to safe-check (reachability
// only), and never leak a nuclei signature onto a safe-check job.
func TestRunService_ValidateFinding_FallsBackToSafeCheckWithoutNucleiAgent(t *testing.T) {
	assetID := shared.NewID()
	f := newNucleiFinding(t, assetID, "apache-struts-rce")
	a := newTestAsset(t, "example.com")
	disp := &fakeJobDispatcher{id: shared.NewID()}

	svc := NewRunService(fakeFindingLookup{f: f}, fakeAssetLookup{a: a}, disp,
		DefaultSelector{}, []ExecutorKind{KindSafeCheck}, logger.NewNop())
	svc.SetNucleiAvailability(fakeNucleiAvailability{has: false})

	if _, err := svc.ValidateFinding(context.Background(), shared.NewID(), f.ID()); err != nil {
		t.Fatalf("ValidateFinding: %v", err)
	}
	if disp.got.ExecutorKind != KindSafeCheck {
		t.Errorf("executor kind = %q, want safe-check", disp.got.ExecutorKind)
	}
	if disp.got.Technique != safeCheckTechnique {
		t.Errorf("technique = %q, want %q", disp.got.Technique, safeCheckTechnique)
	}
	if disp.got.TemplateID != "" || disp.got.CVEID != "" {
		t.Errorf("safe-check job must not carry a nuclei signature, got tmpl=%q cve=%q",
			disp.got.TemplateID, disp.got.CVEID)
	}
}

// Nuclei agent online but the finding has no re-runnable signature → safe-check.
func TestRunService_ValidateFinding_SafeCheckWhenNoSignature(t *testing.T) {
	assetID := shared.NewID()
	f := newTestFinding(t, assetID) // tool "tool", no rule id, no CVE
	a := newTestAsset(t, "example.com")
	disp := &fakeJobDispatcher{id: shared.NewID()}

	svc := NewRunService(fakeFindingLookup{f: f}, fakeAssetLookup{a: a}, disp,
		DefaultSelector{}, []ExecutorKind{KindSafeCheck}, logger.NewNop())
	svc.SetNucleiAvailability(fakeNucleiAvailability{has: true})

	if _, err := svc.ValidateFinding(context.Background(), shared.NewID(), f.ID()); err != nil {
		t.Fatalf("ValidateFinding: %v", err)
	}
	if disp.got.ExecutorKind != KindSafeCheck {
		t.Errorf("executor kind = %q, want safe-check", disp.got.ExecutorKind)
	}
}
