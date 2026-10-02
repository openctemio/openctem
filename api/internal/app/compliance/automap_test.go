package compliance

import (
	"testing"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
)

func TestNormalizeOWASP(t *testing.T) {
	cases := map[string]string{
		"A01:2021":             "A01",
		"A1":                   "A01",
		"A03:2021 - Injection": "A03",
		"OWASP-A07":            "A07",
		"a10":                  "A10",
		"A11":                  "", // out of range
		"nonsense":             "",
		"":                     "",
	}
	for in, want := range cases {
		if got := normalizeOWASP(in); got != want {
			t.Errorf("normalizeOWASP(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormalizeCWE(t *testing.T) {
	cases := map[string]string{
		"CWE-89": "CWE-89",
		"89":     "CWE-89",
		"cwe-79": "CWE-79",
		"CWE-":   "",
		"abc":    "",
		"":       "",
	}
	for in, want := range cases {
		if got := normalizeCWE(in); got != want {
			t.Errorf("normalizeCWE(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCWEToOWASP_KnownMappings(t *testing.T) {
	cases := map[string]string{
		"CWE-89":  "A03", // SQLi → Injection
		"CWE-79":  "A03", // XSS → Injection
		"CWE-22":  "A01", // Path traversal → Broken Access Control
		"CWE-798": "A07", // Hardcoded creds → Auth failures
		"CWE-327": "A02", // Broken crypto → Cryptographic failures
		"CWE-918": "A10", // SSRF
		"CWE-502": "A08", // Deserialization → Integrity failures
	}
	for cwe, want := range cases {
		if got := cweToOWASP[cwe]; got != want {
			t.Errorf("cweToOWASP[%q] = %q, want %q", cwe, got, want)
		}
	}
}

func TestOWASPCategoriesForFinding(t *testing.T) {
	f, err := vulnerability.NewFinding(
		shared.NewID(), shared.NewID(),
		vulnerability.FindingSourceManual, "tool",
		vulnerability.SeverityHigh, "test",
	)
	if err != nil {
		t.Fatalf("new finding: %v", err)
	}
	// SQLi CWE + an explicit OWASP id → {A03} (deduped across both sources).
	if err := f.SetClassification("", nil, "", []string{"CWE-89"}, []string{"A03:2021"}); err != nil {
		t.Fatalf("classify: %v", err)
	}
	cats := owaspCategoriesForFinding(f)
	if _, ok := cats["A03"]; !ok {
		t.Errorf("expected A03 in categories, got %v", cats)
	}
	if len(cats) != 1 {
		t.Errorf("expected exactly {A03}, got %v", cats)
	}

	// Add a crypto CWE → A02 also appears.
	if err := f.SetClassification("", nil, "", []string{"CWE-89", "CWE-327"}, nil); err != nil {
		t.Fatalf("classify: %v", err)
	}
	cats = owaspCategoriesForFinding(f)
	if _, ok := cats["A02"]; !ok {
		t.Errorf("expected A02 for CWE-327, got %v", cats)
	}
}

func TestOWASPCategoriesForFinding_None(t *testing.T) {
	f, err := vulnerability.NewFinding(
		shared.NewID(), shared.NewID(),
		vulnerability.FindingSourceManual, "tool",
		vulnerability.SeverityLow, "test",
	)
	if err != nil {
		t.Fatalf("new finding: %v", err)
	}
	if cats := owaspCategoriesForFinding(f); len(cats) != 0 {
		t.Errorf("expected no categories for an unclassified finding, got %v", cats)
	}
}
