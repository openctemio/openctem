package cirun

import (
	"errors"
	"strings"
	"testing"

	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"

	"github.com/openctemio/ctis/v2"

	"github.com/openctemio/openctem/api/internal/app/ingest"
)

// A CI upload is bounded before it is decoded: a body that would decode into
// more array elements than ingest.CIReportBounds allows is refused, and
// an ordinary CTIS 2.0 document (the body itself) still decodes.
func TestDecodeReport_Bounded(t *testing.T) {
	bare := ciReportJSON(1)
	if r, err := DecodeReport([]byte(bare)); err != nil || len(r.Findings) != 1 {
		t.Fatalf("bare report: %v", err)
	}
	flood := `{"version":"2.0","findings":[` + strings.TrimSuffix(strings.Repeat("{},", ingest.CIReportBounds.MaxArrayLen+1), ",") + `]}`
	if _, err := DecodeReport([]byte(flood)); !errors.Is(err, ErrInvalidReport) {
		t.Fatalf("a findings array over the bound: %v", err)
	}
	if _, err := DecodeReport([]byte(`{"version":"2.0","version":"2.0"}`)); !errors.Is(err, ErrInvalidReport) {
		t.Fatalf("a duplicate member: %v", err)
	}
}

// The {"report": ...} envelope of the 1.x CI integration is refused, even
// around a valid CTIS 2.0 document: the body is the document itself.
func TestDecodeReport_RefusesEnvelope(t *testing.T) {
	if _, err := DecodeReport([]byte(`{"report":` + ciReportJSON(1) + `}`)); !errors.Is(err, ErrReportUpgrade) {
		t.Fatalf("a wrapped 2.0 report: %v, want ErrReportUpgrade", err)
	}
}

// A CTIS 1.x document is refused: CI is upgraded together with the platform.
func TestDecodeReport_RefusesV1(t *testing.T) {
	v1 := `{"version":"1.6","metadata":{"id":"` + ctis.NewReportID() + `"},"tool":{"name":"semgrep"},"findings":[{"type":"vulnerability","title":"t","severity":"high"}]}`
	if _, err := DecodeReport([]byte(v1)); !errors.Is(err, ErrReportUpgrade) {
		t.Fatalf("a 1.x report: %v, want ErrReportUpgrade", err)
	}
	if _, err := DecodeReport([]byte(`{"report":` + v1 + `}`)); !errors.Is(err, ErrReportUpgrade) {
		t.Fatalf("a wrapped 1.x report: %v, want ErrReportUpgrade", err)
	}
}

// ciReportJSON is a valid CTIS 2.0 document with n findings on one repository.
func ciReportJSON(n int) string {
	var f []string
	for i := 0; i < n; i++ {
		f = append(f, `{"type":"vulnerability","title":"t","severity":"high","asset_ref":"repo"}`)
	}
	return `{"version":"2.0","metadata":{"id":"` + ctis.NewReportID() + `","generated_at":"2026-11-01T00:00:00Z","channel":"scanner"},` +
		`"tool":{"name":"semgrep","techniques":["sast"]},` +
		`"assets":[{"id":"repo","type":"repository","value":"github.com/acme/api"}],` +
		`"findings":[` + strings.Join(f, ",") + `]}`
}

// The bounds run before any parse: an oversized or over-deep body is
// refused as invalid even when it is wrapped in the 1.x envelope, whose
// detection needs a parse of the top level.
func TestDecodeReport_BoundsBeforeParse(t *testing.T) {
	flood := `{"report":{"version":"2.0","findings":[` + strings.TrimSuffix(strings.Repeat("{},", ingest.CIReportBounds.MaxArrayLen+1), ",") + `]}}`
	if _, err := DecodeReport([]byte(flood)); !errors.Is(err, ErrInvalidReport) {
		t.Fatalf("oversized wrapped body: %v, want ErrInvalidReport", err)
	}
	deep := `{"report":` + strings.Repeat(`{"a":`, protov2.DefaultMaxJSONDepth+5) + "1" + strings.Repeat("}", protov2.DefaultMaxJSONDepth+5) + `}`
	if _, err := DecodeReport([]byte(deep)); !errors.Is(err, ErrInvalidReport) {
		t.Fatalf("over-deep wrapped body: %v, want ErrInvalidReport", err)
	}
}
