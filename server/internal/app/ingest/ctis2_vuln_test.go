package ingest

import (
	"reflect"
	"testing"

	"github.com/openctemio/ctis/v2"
)

// The primary CVE is the numerically smallest one (not the first written, not
// the lexically smallest); a finding with no CVE has none even when it names
// other ids.
func TestPrimaryCVE(t *testing.T) {
	cases := []struct {
		name string
		v    *ctis.VulnerabilityDetails
		want string
	}{
		{"nil", nil, ""},
		{"no ids", &ctis.VulnerabilityDetails{}, ""},
		{"one", cveVuln("CVE-2024-3094"), "CVE-2024-3094"},
		{"smallest year", cveVuln("CVE-2024-1000", "CVE-2021-44228"), "CVE-2021-44228"},
		{"numeric not lexical", cveVuln("CVE-2024-10000", "CVE-2024-9999"), "CVE-2024-9999"},
		{"non-cve only", &ctis.VulnerabilityDetails{IDs: []ctis.VulnerabilityID{{Type: ctis.VulnerabilityIDGHSA, ID: "GHSA-jfh8-c2jp-5v3q"}}}, ""},
		{"cve preferred over ghsa", &ctis.VulnerabilityDetails{IDs: []ctis.VulnerabilityID{
			{Type: ctis.VulnerabilityIDGHSA, ID: "GHSA-jfh8-c2jp-5v3q"}, {Type: ctis.VulnerabilityIDCVE, ID: "CVE-2023-5000"}}}, "CVE-2023-5000"},
	}
	for _, c := range cases {
		if got := primaryCVE(c.v); got != c.want {
			t.Errorf("%s: primaryCVE = %q, want %q", c.name, got, c.want)
		}
	}
	if findingCVEs(nil) != nil {
		t.Error("findingCVEs(nil) must be nil")
	}
	if got := findingCVEs(cveVuln("CVE-2024-1000", "CVE-2021-2000")); !reflect.DeepEqual(got, []string{"CVE-2024-1000", "CVE-2021-2000"}) {
		t.Errorf("findingCVEs = %v, want document order", got)
	}
}

// Splitting a multi-CVE finding keeps the one CVE and every non-CVE id.
func TestWithOnlyCVE(t *testing.T) {
	ids := []ctis.VulnerabilityID{
		{Type: ctis.VulnerabilityIDCVE, ID: "CVE-2024-1000"},
		{Type: ctis.VulnerabilityIDGHSA, ID: "GHSA-aaaa-bbbb-cccc"},
		{Type: ctis.VulnerabilityIDCVE, ID: "CVE-2024-2000"},
		{Type: ctis.VulnerabilityIDVendor, ID: "USN-1-1", Source: "ubuntu"},
		{Type: ctis.VulnerabilityIDCVE, ID: "CVE-2024-2000"}, // duplicate
	}
	got := withOnlyCVE(ids, "CVE-2024-2000")
	want := []ctis.VulnerabilityID{
		{Type: ctis.VulnerabilityIDGHSA, ID: "GHSA-aaaa-bbbb-cccc"},
		{Type: ctis.VulnerabilityIDCVE, ID: "CVE-2024-2000"},
		{Type: ctis.VulnerabilityIDVendor, ID: "USN-1-1", Source: "ubuntu"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("withOnlyCVE = %+v, want %+v", got, want)
	}
	// A CVE the list does not hold is added.
	got = withOnlyCVE(ids[1:2], "CVE-2030-9000")
	if len(got) != 2 || got[1].ID != "CVE-2030-9000" || got[1].Type != ctis.VulnerabilityIDCVE {
		t.Fatalf("withOnlyCVE(add) = %+v", got)
	}
	if len(ids) != 5 {
		t.Fatal("input mutated")
	}
}
