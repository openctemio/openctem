package finding

import (
	"errors"
	"strings"
	"testing"
)

func TestNormalizeCVESelection(t *testing.T) {
	got, err := NormalizeCVESelection([]string{" cve-2024-3094 ", "CVE-2024-3094", "CVE-2023-44487"})
	if err != nil || strings.Join(got, ",") != "CVE-2024-3094,CVE-2023-44487" {
		t.Fatalf("got %v, %v", got, err)
	}
	many := make([]string, MaxCVESelection+1)
	for i := range many {
		many[i] = "CVE-2024-3094"
	}
	for _, bad := range [][]string{nil, {"GHSA-xxxx-yyyy-zzzz"}, {"CVE-2024-3094'--"}, many} {
		if _, err := NormalizeCVESelection(bad); !errors.Is(err, ErrCVESelection) {
			t.Errorf("%.40v: err %v", bad, err)
		}
	}
}

func TestCVESelectionLabel(t *testing.T) {
	if got := cveSelectionLabel([]string{"CVE-2024-3094", "CVE-2023-44487"}); got != "CVE-2024-3094, CVE-2023-44487" {
		t.Fatalf("label = %q", got)
	}
	ids := make([]string, 30)
	for i := range ids {
		ids[i] = "CVE-2024-1000" + string(rune('0'+i%10))
	}
	got := cveSelectionLabel(ids)
	if len(got) > 200 || !strings.Contains(got, " +") {
		t.Fatalf("long label = %q (%d)", got, len(got))
	}
}

func TestCVESelectionSpec_ReplacesCVEAndLens(t *testing.T) {
	spec, err := cveSelectionSpec(CVESelection{CVEIDs: []string{"CVE-2024-3094"}}, true)
	if err != nil {
		t.Fatal(err)
	}
	fields := map[string]bool{}
	for _, l := range spec.Leaves() {
		fields[l.Field] = true
	}
	if !fields["cve_id"] || !fields["state"] || len(spec.Sort) == 0 {
		t.Fatalf("spec leaves %v sort %v", fields, spec.Sort)
	}
}
