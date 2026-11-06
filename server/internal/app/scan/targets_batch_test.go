package scan

import "testing"

// The batch flag moved from a map here to the stage catalog. Same answer
// for every scanner the map named, and for the ones it did not.
func TestScannerAcceptsTargetList_SameAsTheOldMap(t *testing.T) {
	oldMap := []string{"nuclei", "tenable", "nessus", "subfinder", "dnsx", "naabu", "httpx", "katana"}
	for _, s := range oldMap {
		if !scannerAcceptsTargetList(s) {
			t.Errorf("%s took a target list before and must still", s)
		}
	}
	if !scannerAcceptsTargetList("  Nuclei ") {
		t.Error("scanner names are normalized")
	}
	for _, s := range []string{"zap", "semgrep", "trivy", "betterleaks", "tenable_sc", "codeql", "custom-tool", ""} {
		if scannerAcceptsTargetList(s) {
			t.Errorf("%s took one target per task before and must still", s)
		}
	}
}
