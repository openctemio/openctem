package handler

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	exposuresvc "github.com/openctemio/openctem/api/internal/app/exposure"
	"github.com/openctemio/openctem/api/pkg/domain/ctemid"
	"github.com/openctemio/openctem/api/pkg/domain/exposure"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func ctemTestEvent(et exposure.EventType, details map[string]any) *exposure.ExposureEvent {
	now := time.Now().UTC()
	return exposure.Reconstitute(shared.NewID(), shared.NewID(), nil, et, exposure.SeverityMedium, exposure.StateActive,
		"t", "", details, "fp", "src", now, now, nil, nil, "", now, now)
}

func TestExposureResponse_CTEMID(t *testing.T) {
	// Derived without the asset: a homoglyph lookalike.
	resp := toExposureResponse(ctemTestEvent(exposure.EventTypeLookalikeDomain, map[string]any{"technique": "homoglyph"}))
	if resp.CTEMID == nil || resp.CTEMID.Code != "CTEM-DOM-2" || resp.CTEMID.Basis != "lookalike_technique" ||
		resp.CTEMID.CatalogVersion != ctemid.CatalogVersion || resp.CTEMID.URL != "https://ctem.org/docs/ctem-dom-2" {
		t.Fatalf("lookalike: %+v", resp.CTEMID)
	}

	// A legacy free-text tag in details is not a code: the field is absent.
	resp = toExposureResponse(ctemTestEvent(exposure.EventTypePortOpen, map[string]any{"ctem_id": "<script>"}))
	raw, _ := json.Marshal(resp)
	if resp.CTEMID != nil || strings.Contains(string(raw), `"ctem_id":{`) {
		t.Fatalf("port without asset: %s", raw)
	}

	// The enricher's asset-aware answer replaces the asset-free one.
	applyEnrichment(&resp, exposuresvc.Enrichment{CTEMID: &ctemid.Mapping{Code: ctemid.CodeEXP6, Basis: ctemid.BasisAssetScope}})
	if resp.CTEMID == nil || resp.CTEMID.Code != "CTEM-EXP-6" || resp.CTEMID.Basis != "asset_scope" {
		t.Fatalf("enriched: %+v", resp.CTEMID)
	}
}
