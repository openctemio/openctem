package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/stage"
)

// GET /scans/stages serves the whole catalog with JSON arrays (never
// null) and the tier labels.
func TestListStages_ServesTheCatalog(t *testing.T) {
	rec := httptest.NewRecorder()
	(&ScanHandler{}).ListStages(rec, httptest.NewRequest(http.MethodGet, "/api/v1/scans/stages", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	var raw struct {
		Stages []map[string]any `json:"stages"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	if len(raw.Stages) != len(stage.All()) {
		t.Fatalf("%d stages, want %d", len(raw.Stages), len(stage.All()))
	}
	for _, s := range raw.Stages {
		for _, k := range []string{"inputs", "outputs", "relations", "implementations"} {
			if _, ok := s[k].([]any); !ok {
				t.Errorf("%v: %s is not an array", s["key"], k)
			}
		}
	}
	var resp ScanStageListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.MaxHops != stage.MaxHops {
		t.Errorf("max_hops = %d", resp.MaxHops)
	}
	byKey := map[string]ScanStageResponse{}
	for _, s := range resp.Stages {
		byKey[s.Key] = s
	}
	if byKey["resolve.dns"].Tier != "T0" || byKey["scan.ports"].Tier != "T1" {
		t.Errorf("tiers: dns %s ports %s", byKey["resolve.dns"].Tier, byKey["scan.ports"].Tier)
	}
}
