package unit

import (
	"context"
	"errors"
	"strings"
	"testing"

	assetapp "github.com/openctemio/openctem/api/internal/app/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Platform-owned property keys (crown jewel, business impact, aliases,
// discovery fields, internal markers) cannot be set through user-supplied
// properties on create, update or CSV import.

var reservedPropertyCases = []map[string]any{ //nolint:gochecknoglobals // test table
	{"is_crown_jewel": "x"},
	{"is_crown_jewel": true},
	{"isCrownJewel": true},
	{"business_impact_score": 1e9},
	{"business_impact_notes": "n"},
	{"aliases": []any{"victim.example.com"}},
	{"discovery_source": "manual"},
	{"discovery_tool": "x"},
	{"__promoted_sub_type": "x"},
}

func TestAssetService_CreateAsset_RejectsReservedProperties(t *testing.T) {
	for _, props := range reservedPropertyCases {
		svc, repo := newTestService()
		patch := make(map[string]any, len(props))
		for k, v := range props {
			patch[k] = v
		}
		_, err := svc.CreateAsset(context.Background(), assetapp.CreateAssetInput{
			TenantID: serviceTenantID.String(), Name: "reserved.example.com", Type: "domain",
			Criticality: "high", Properties: patch,
		})
		if !errors.Is(err, shared.ErrValidation) {
			t.Errorf("create with %v: err = %v, want a validation error", props, err)
			continue
		}
		for k := range props {
			if !strings.Contains(err.Error(), k) {
				t.Errorf("create with %v: error %q does not name the key", props, err)
			}
		}
		if len(repo.assets) != 0 {
			t.Errorf("create with %v wrote an asset", props)
		}
	}

	// Ordinary keys are still accepted.
	svc, _ := newTestService()
	if _, err := svc.CreateAsset(context.Background(), assetapp.CreateAssetInput{
		TenantID: serviceTenantID.String(), Name: "ok.example.com", Type: "domain",
		Criticality: "high", Properties: map[string]any{"registrar": "x"},
	}); err != nil {
		t.Errorf("create with ordinary properties: %v", err)
	}
}

func TestAssetService_UpdateAsset_RejectsChangedReservedProperties(t *testing.T) {
	svc, repo := newTestService()
	a := createAssetForTest(t, svc, serviceTenantID.String(), "jewel.example.com")
	// The crown-jewel endpoint stored these: the flag in its column, the
	// business impact in properties.
	if _, err := svc.UpdateCrownJewel(context.Background(), serviceTenantID.String(), a.ID().String(), true, 80, "core"); err != nil {
		t.Fatal(err)
	}
	stored := repo.assets[a.ID().String()]
	stored.SetProperties(map[string]any{"business_impact_score": float64(80), "business_impact_notes": "core", "registrar": "x"})

	// Every reserved key with a value other than the stored one is refused,
	// is_crown_jewel included: it is never stored in properties.
	for _, props := range reservedPropertyCases {
		patch := make(map[string]any, len(props))
		for k, v := range props {
			patch[k] = v
		}
		_, err := svc.UpdateAsset(context.Background(), a.ID().String(), serviceTenantID.String(), assetapp.UpdateAssetInput{Properties: patch})
		if !errors.Is(err, shared.ErrValidation) {
			t.Errorf("update with %v: err = %v, want a validation error", props, err)
		}
	}
	if !repo.assets[a.ID().String()].IsCrownJewel() {
		t.Error("crown-jewel flag changed")
	}

	// A full-form PUT echoes the stored values: accepted, other keys applied.
	desc := "updated"
	updated, err := svc.UpdateAsset(context.Background(), a.ID().String(), serviceTenantID.String(), assetapp.UpdateAssetInput{
		Description: &desc,
		Properties:  map[string]any{"business_impact_score": 80, "business_impact_notes": "core", "registrar": "y"},
	})
	if err != nil {
		t.Fatalf("echo of unchanged reserved values: %v", err)
	}
	p := updated.Properties()
	if !updated.IsCrownJewel() || p["registrar"] != "y" || p["business_impact_score"] != float64(80) {
		t.Errorf("after echo: crown=%v properties=%v", updated.IsCrownJewel(), p)
	}
}

func TestAssetService_UpdateCrownJewel_TenantScoped(t *testing.T) {
	svc, _ := newTestService()
	a := createAssetForTest(t, svc, serviceTenantID.String(), "cj-tenant.example.com")
	if _, err := svc.UpdateCrownJewel(context.Background(), shared.NewID().String(), a.ID().String(), true, 10, ""); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("another tenant: err = %v, want not found", err)
	}
	got, err := svc.UpdateCrownJewel(context.Background(), serviceTenantID.String(), a.ID().String(), true, 10, "n")
	if err != nil || !got.IsCrownJewel() {
		t.Errorf("own tenant: crown=%v err=%v", got != nil && got.IsCrownJewel(), err)
	}
}

func TestAssetImport_CSV_RejectsReservedProperties(t *testing.T) {
	repo := NewMockAssetRepository()
	svc := assetapp.NewAssetImportService(repo, logger.NewNop())
	csv := "name,type,properties\n" +
		`bad.example.com,domain,"{""is_crown_jewel"":""x""}"` + "\n" +
		`good.example.com,domain,"{""registrar"":""x""}"` + "\n"
	res, err := svc.ImportCSVAssets(context.Background(), serviceTenantID.String(), strings.NewReader(csv))
	if err != nil {
		t.Fatal(err)
	}
	if res.AssetsCreated != 1 || len(res.Errors) != 1 || !strings.Contains(res.Errors[0], "is_crown_jewel") {
		t.Errorf("import result = created %d errors %v; want 1 created and one is_crown_jewel error", res.AssetsCreated, res.Errors)
	}
	for _, a := range repo.assets {
		if _, ok := a.Properties()["is_crown_jewel"]; ok {
			t.Errorf("imported asset %s carries is_crown_jewel", a.Name())
		}
	}
}
