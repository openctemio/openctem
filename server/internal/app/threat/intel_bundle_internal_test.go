package threat

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/logger"
)

// FIRST publishes the score date as a full timestamp. A date that fails to
// parse used to fall back to the time of the fetch, which made the data date
// of a direct fetch meaningless to compare with a bundle copy.
func TestParseEPSSCSV_ScoreDateTimestamp(t *testing.T) {
	csv := "#model_version:v2025.03.14,score_date:2026-10-26T12:03:22Z\ncve,epss,percentile\nCVE-2020-0001,0.5,0.9\n"
	scores, err := parseEPSSCSV(strings.NewReader(csv))
	if err != nil || len(scores) != 1 {
		t.Fatal(scores, err)
	}
	if got := scores[0].ScoreDate().UTC().Format("2006-01-02"); got != "2026-10-26" {
		t.Fatalf("score date %s", got)
	}
	plain := strings.Replace(csv, "2026-10-26T12:03:22Z", "2026-10-25", 1)
	scores, err = parseEPSSCSV(strings.NewReader(plain))
	if err != nil || scores[0].ScoreDate().UTC().Format("2006-01-02") != "2026-10-25" {
		t.Fatal(scores, err)
	}
}

func TestKEVCatalogReleasedAt(t *testing.T) {
	for in, want := range map[string]string{
		"2026-10-24T14:30:01.9444Z": "2026-10-24T14:30:01Z",
		"2026-10-24":                "2026-10-24T00:00:00Z",
		"":                          "",
		"yesterday":                 "",
	} {
		if got := (kevCatalogResponse{DateReleased: in}).releasedAt(); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}

// The direct fetch records the catalog's release time next to the
// validators, so the data date is known whichever path stored the data.
func TestFetchKEVFrom_RecordsTheReleaseTime(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"dateReleased":"2026-10-24T14:30:01.9444Z","vulnerabilities":[{"cveID":"CVE-2026-0001","vulnerabilityName":"x","dateAdded":"2026-10-19"}]}`))
	}))
	defer srv.Close()
	s := NewIntelService(nil, logger.NewNop())
	s.httpClient = srv.Client()
	_, v, err := s.fetchKEVFrom(context.Background(), srv.URL, kevValidator{})
	if err != nil || v.Released != "2026-10-24T14:30:01Z" {
		t.Fatalf("%+v %v", v, err)
	}
	got := readKEVValidators(map[string]any{kevValidatorsKey: map[string]any{kevURL: map[string]any{"released": v.Released}}})
	if got[kevURL].Released != v.Released {
		t.Fatalf("the release time is lost between runs: %+v", got)
	}
}

func TestMarkDirectAndNewerData(t *testing.T) {
	meta := map[string]any{}
	markDirect(meta, time.Time{})
	if meta[MetaDeliveredVia] != ViaDirect || meta[MetaIntelAsOf] != nil {
		t.Fatalf("an unknown date must not be invented: %v", meta)
	}
	d := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	markDirect(meta, d)
	if !storedAsOf(meta).Equal(d) {
		t.Fatalf("%v", meta)
	}
	if !newerData("kev", d.Add(time.Second), d) || newerData("kev", d, d) || newerData("kev", d.Add(-time.Hour), d) {
		t.Fatal("KEV compares releases by time")
	}
	if newerData("epss", d.Add(5*time.Hour), d) || !newerData("epss", d.Add(24*time.Hour), d) {
		t.Fatal("EPSS compares scores by day")
	}
	if !newerData("kev", d, time.Time{}) {
		t.Fatal("nothing held: any date is newer")
	}
}
