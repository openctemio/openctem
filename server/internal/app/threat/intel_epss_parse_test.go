package threat

import (
	"strings"
	"testing"
)

// realEPSSHeader mirrors the exact shape of the live FIRST/empiricalsecurity
// feed: a metadata comment line whose comma count (2) differs from the 3-column
// data header. Before FieldsPerRecord=-1 this made encoding/csv reject the
// header on line 2 ("wrong number of fields") and the whole EPSS sync failed.
const realEPSSCSV = `#model_version:v2026.06.15,score_date:2026-07-23T12:00:26Z
cve,epss,percentile
CVE-1999-0001,0.03351,0.87424
CVE-2021-44228,0.94270,0.99980
`

func TestParseEPSSCSV_CommentLineDoesNotBreakHeader(t *testing.T) {
	scores, err := parseEPSSCSV(strings.NewReader(realEPSSCSV))
	if err != nil {
		t.Fatalf("parseEPSSCSV returned error on valid feed: %v", err)
	}
	if len(scores) != 2 {
		t.Fatalf("got %d scores, want 2", len(scores))
	}

	first := scores[0]
	if first.CVEID() != "CVE-1999-0001" {
		t.Errorf("cve = %q, want CVE-1999-0001", first.CVEID())
	}
	if first.Score() != 0.03351 {
		t.Errorf("score = %v, want 0.03351", first.Score())
	}
	// Feed percentile is 0-1; the parser scales it to 0-100.
	if first.Percentile() != 87.424 {
		t.Errorf("percentile = %v, want 87.424", first.Percentile())
	}
	if first.ModelVersion() != "v2026.06.15" {
		t.Errorf("model_version = %q, want v2026.06.15 (parsed from comment line)", first.ModelVersion())
	}
	if first.ScoreDate().IsZero() {
		t.Error("score_date is zero; expected it parsed from the comment line")
	}
}

func TestParseEPSSCSV_SkipsNonCVEAndMalformedRows(t *testing.T) {
	csv := `#model_version:v1,score_date:2026-01-01
cve,epss,percentile
CVE-2024-0001,0.5,0.9
not-a-cve,0.1,0.1
CVE-2024-0002,notafloat,0.2
CVE-2024-0003,0.2,0.3
`
	scores, err := parseEPSSCSV(strings.NewReader(csv))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Only the two well-formed CVE rows survive; the non-CVE row and the
	// unparseable-score row are skipped without failing the whole parse.
	if len(scores) != 2 {
		t.Fatalf("got %d scores, want 2 (bad rows skipped)", len(scores))
	}
	if scores[0].CVEID() != "CVE-2024-0001" || scores[1].CVEID() != "CVE-2024-0003" {
		t.Errorf("unexpected surviving CVEs: %q, %q", scores[0].CVEID(), scores[1].CVEID())
	}
}
