package tool

import "testing"

func TestCanonicalName(t *testing.T) {
	for in, want := range map[string]string{
		"gitleaks":    NameBetterleaks,
		" GitLeaks ":  NameBetterleaks,
		"betterleaks": NameBetterleaks,
		"semgrep":     "semgrep",
		"":            "",
	} {
		if got := CanonicalName(in); got != want {
			t.Errorf("CanonicalName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSameTool(t *testing.T) {
	if !SameTool("gitleaks", "betterleaks") || !SameTool("Betterleaks", " betterleaks") || !SameTool("semgrep", "SEMGREP") {
		t.Error("SameTool must match retired names, case and space")
	}
	if SameTool("gitleaks", "semgrep") || SameTool("", "betterleaks") {
		t.Error("SameTool matched different tools")
	}
}
