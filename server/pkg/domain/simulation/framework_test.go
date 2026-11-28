package simulation

import (
	"testing"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

func TestCanonicalFramework(t *testing.T) {
	cases := map[string]string{
		"cis":                  "CIS Controls",
		"CIS":                  "CIS Controls",
		"CIS Controls":         "CIS Controls",
		"iso27001":             "ISO 27001",
		"ISO27001":             "ISO 27001",
		"ISO 27001":            "ISO 27001",
		"nist_csf":             "NIST CSF",
		"owasp_asvs":           "OWASP ASVS",
		"MITRE ATT&CK":         "MITRE ATT&CK",
		"soc2":                 "SOC 2",
		"  Internal   policy ": "Internal policy",
		"":                     "",
	}
	for in, want := range cases {
		if got := CanonicalFramework(in); got != want {
			t.Errorf("CanonicalFramework(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNewControlTestStoresCanonicalFramework(t *testing.T) {
	ct, err := NewControlTest(shared.NewID(), "MFA", "iso27001", "A.9")
	if err != nil {
		t.Fatal(err)
	}
	if ct.Framework() != "ISO 27001" {
		t.Fatalf("framework = %q", ct.Framework())
	}
	if _, err := NewControlTest(shared.NewID(), "MFA", "   ", "A.9"); err == nil {
		t.Fatal("blank framework accepted")
	}
}
