package ingest

import (
	"testing"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

// A sensor report's free-form asset properties must not set the keys the
// platform reads as decisions made by people: is_crown_jewel drives P0
// priority rules, business impact feeds risk scoring, and aliases feed asset
// identity resolution.
func hostileProps() map[string]any {
	return map[string]any{
		"is_crown_jewel":        true,
		"business_impact_score": 100,
		"business_impact_notes": "set by a sensor",
		"aliases":               []any{"victim.example.com"},
		"os":                    "linux",
	}
}

func TestBuildPropertiesFromCTIS_DropsReservedKeys(t *testing.T) {
	p := &AssetProcessor{logger: logger.NewNop(), propsValidator: validator.NewPropertiesValidator()}
	props := p.buildPropertiesFromCTIS(&ctis.Asset{Value: "h.example.com", Type: "host", Properties: hostileProps()})
	for _, k := range []string{"is_crown_jewel", "business_impact_score", "business_impact_notes", "aliases"} {
		if _, ok := props[k]; ok {
			t.Errorf("sensor-supplied reserved key %q was kept", k)
		}
	}
	if props["os_name"] != "linux" { // a sensor writes "os"; the schema folds it into os_name
		t.Error("ordinary sensor properties must be kept")
	}
}

func TestMergeCTISIntoAsset_KeepsReservedValues(t *testing.T) {
	p := &AssetProcessor{logger: logger.NewNop(), propsValidator: validator.NewPropertiesValidator()}
	a, err := asset.NewAsset("h.example.com", asset.AssetTypeHost, asset.CriticalityMedium)
	if err != nil {
		t.Fatal(err)
	}
	// What an analyst decided in the UI.
	a.SetProperties(map[string]any{"is_crown_jewel": false, "business_impact_score": 10})

	p.mergeCTISIntoAsset(a, &ctis.Asset{Value: "h.example.com", Type: "host", Properties: hostileProps()}, nil, nil)

	got := a.Properties()
	if got["is_crown_jewel"] != false || got["business_impact_score"] != 10 {
		t.Errorf("a sensor changed analyst decisions: %v", got)
	}
	if _, ok := got["business_impact_notes"]; ok {
		t.Error("a sensor added a reserved key")
	}
	if got["os_name"] != "linux" {
		t.Error("ordinary sensor properties must be merged")
	}
}
