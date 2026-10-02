package ingest

import (
	"testing"

	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/ctis"
)

// The ingest mapper previously dropped the scanner's CTEM signals (only
// regulatory_owner was read). applyCTEMSignals must carry internet-exposure,
// compliance scope, data classification, and PII/PHI onto the domain asset so
// the prioritization engine sees real signals instead of heuristics.
func TestApplyCTEMSignals_CarriesScannerSignals(t *testing.T) {
	p := &AssetProcessor{logger: logger.NewNop()}
	a, err := asset.NewAsset("example.com", asset.AssetTypeDomain, asset.CriticalityMedium)
	if err != nil {
		t.Fatalf("new asset: %v", err)
	}

	p.applyCTEMSignals(a, &ctis.Asset{
		IsInternetAccessible: true,
		Compliance: &ctis.AssetCompliance{
			Frameworks:         []string{"PCI-DSS", "SOC2"},
			DataClassification: "confidential",
			PIIExposed:         true,
			PHIExposed:         true,
		},
	})

	if !a.IsInternetAccessible() {
		t.Error("is_internet_accessible not carried")
	}
	if a.Exposure() != asset.ExposurePublic {
		t.Errorf("exposure = %q, want public (explicit internet-accessible signal)", a.Exposure())
	}
	if len(a.ComplianceScope()) != 2 {
		t.Errorf("compliance scope = %v, want 2 frameworks", a.ComplianceScope())
	}
	if string(a.DataClassification()) != "confidential" {
		t.Errorf("data classification = %q, want confidential", a.DataClassification())
	}
	if !a.PIIDataExposed() || !a.PHIDataExposed() {
		t.Errorf("PII/PHI not carried: pii=%v phi=%v", a.PIIDataExposed(), a.PHIDataExposed())
	}
}

// A nil/empty compliance block and no exposure signal must be a no-op (no panic,
// no fabricated exposure).
func TestApplyCTEMSignals_NoSignalsNoOp(t *testing.T) {
	p := &AssetProcessor{logger: logger.NewNop()}
	a, _ := asset.NewAsset("internal-host", asset.AssetTypeHost, asset.CriticalityLow)

	p.applyCTEMSignals(a, &ctis.Asset{}) // no compliance, not internet-accessible

	if a.IsInternetAccessible() {
		t.Error("must not mark internet-accessible without a signal")
	}
	if a.Exposure() != asset.ExposureUnknown {
		t.Errorf("exposure = %q, want unknown (no explicit signal)", a.Exposure())
	}
	if len(a.ComplianceScope()) != 0 || a.PIIDataExposed() {
		t.Error("must not fabricate compliance/PII")
	}
}

// An invalid data_classification must be skipped (logged), not applied, and must
// not abort the other signals.
func TestApplyCTEMSignals_InvalidClassificationSkipped(t *testing.T) {
	p := &AssetProcessor{logger: logger.NewNop()}
	a, _ := asset.NewAsset("example.com", asset.AssetTypeDomain, asset.CriticalityMedium)

	p.applyCTEMSignals(a, &ctis.Asset{
		IsInternetAccessible: true,
		Compliance:           &ctis.AssetCompliance{DataClassification: "not-a-level", PIIExposed: true},
	})

	if string(a.DataClassification()) == "not-a-level" {
		t.Error("invalid data classification should not be applied")
	}
	// Other signals still applied.
	if !a.IsInternetAccessible() || !a.PIIDataExposed() {
		t.Error("a bad classification must not abort the other signals")
	}
}
