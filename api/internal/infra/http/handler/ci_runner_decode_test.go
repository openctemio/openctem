package handler

import (
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/ingest"
)

// A CI upload is bounded before it is decoded: a body that would decode into
// more array elements than ingest.CIReportBounds allows is refused, and
// ordinary reports (bare or wrapped) still decode.
func TestDecodeCTISReport_Bounded(t *testing.T) {
	bare := `{"version":"1.0","tool":{"name":"semgrep"},"findings":[{"type":"vulnerability","title":"t","severity":"high"}]}`
	if r, ok := decodeCTISReport([]byte(bare)); !ok || len(r.Findings) != 1 {
		t.Fatalf("bare report: ok=%v", ok)
	}
	if r, ok := decodeCTISReport([]byte(`{"report":` + bare + `}`)); !ok || len(r.Findings) != 1 {
		t.Fatalf("wrapped report: ok=%v", ok)
	}
	flood := `{"version":"1.0","findings":[` + strings.TrimSuffix(strings.Repeat("{},", ingest.CIReportBounds.MaxArrayLen+1), ",") + `]}`
	if _, ok := decodeCTISReport([]byte(flood)); ok {
		t.Fatal("a findings array over the bound was decoded")
	}
	if _, ok := decodeCTISReport([]byte(`{"version":"1.0","version":"2.0"}`)); ok {
		t.Fatal("a duplicate member was accepted")
	}
}
