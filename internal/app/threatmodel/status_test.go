package threatmodel

import (
	"testing"

	"github.com/openctemio/api/pkg/domain/shared"
	tmdom "github.com/openctemio/api/pkg/domain/threatmodel"
)

func fact(id shared.ID, assetID shared.ID, technique, status string, cwes ...string) tmdom.FindingFact {
	return tmdom.FindingFact{ID: id, AssetID: assetID, TechniqueID: technique, Status: status, CWEIDs: cwes}
}

func TestDeriveStatus_OpenByTechnique(t *testing.T) {
	asset := shared.NewID()
	f := fact(shared.NewID(), asset, "T1190", fsConfirmed)
	st, reason, evid := deriveStatus("T1190", nil, asset.String(), []tmdom.FindingFact{f}, false)
	if st != tmdom.StatusOpen {
		t.Fatalf("expected open, got %s", st)
	}
	if evid == nil || evid.String() != f.ID.String() {
		t.Errorf("expected evidence finding id %s, got %v", f.ID, evid)
	}
	if reason == "" {
		t.Errorf("expected a status reason")
	}
}

func TestDeriveStatus_MitigatedByFix(t *testing.T) {
	asset := shared.NewID()
	f := fact(shared.NewID(), asset, "T1190", fsResolved)
	st, _, evid := deriveStatus("T1190", nil, asset.String(), []tmdom.FindingFact{f}, false)
	if st != tmdom.StatusMitigated {
		t.Fatalf("expected mitigated, got %s", st)
	}
	if evid == nil {
		t.Errorf("mitigated-by-finding should carry evidence")
	}
}

func TestDeriveStatus_MitigatedByCompensatingControl(t *testing.T) {
	asset := shared.NewID()
	// No matching finding, but the asset is covered by a compensating control.
	st, reason, evid := deriveStatus("T1190", nil, asset.String(), nil, true)
	if st != tmdom.StatusMitigated {
		t.Fatalf("expected mitigated via control, got %s", st)
	}
	if evid != nil {
		t.Errorf("control-only mitigation must not carry a finding evidence id")
	}
	if reason == "" {
		t.Errorf("expected a reason for control mitigation")
	}
}

func TestDeriveStatus_Accepted(t *testing.T) {
	asset := shared.NewID()
	f := fact(shared.NewID(), asset, "T1190", fsAccepted)
	st, _, _ := deriveStatus("T1190", nil, asset.String(), []tmdom.FindingFact{f}, false)
	if st != tmdom.StatusAccepted {
		t.Fatalf("expected accepted, got %s", st)
	}
}

func TestDeriveStatus_Theoretical(t *testing.T) {
	asset := shared.NewID()
	st, _, evid := deriveStatus("T1190", nil, asset.String(), nil, false)
	if st != tmdom.StatusTheoretical {
		t.Fatalf("expected theoretical, got %s", st)
	}
	if evid != nil {
		t.Errorf("theoretical must not carry evidence")
	}
}

func TestDeriveStatus_OpenOutranksMitigated(t *testing.T) {
	asset := shared.NewID()
	// Two findings on the same technique: one resolved, one still confirmed.
	// The live-open one must win.
	resolved := fact(shared.NewID(), asset, "T1190", fsResolved)
	open := fact(shared.NewID(), asset, "T1190", fsNew)
	st, _, _ := deriveStatus("T1190", nil, asset.String(), []tmdom.FindingFact{resolved, open}, false)
	if st != tmdom.StatusOpen {
		t.Fatalf("open should outrank mitigated, got %s", st)
	}
}

func TestDeriveStatus_CWEFallback(t *testing.T) {
	asset := shared.NewID()
	// Finding has no technique id but shares a CWE with the technique hint.
	f := fact(shared.NewID(), asset, "", fsConfirmed, "CWE-89")
	st, _, evid := deriveStatus("T1190", []string{"CWE-89"}, asset.String(), []tmdom.FindingFact{f}, false)
	if st != tmdom.StatusOpen {
		t.Fatalf("expected open via CWE fallback, got %s", st)
	}
	if evid == nil {
		t.Errorf("CWE-fallback match should carry evidence")
	}

	// Different CWE → no match → theoretical.
	st, _, _ = deriveStatus("T1190", []string{"CWE-79"}, asset.String(), []tmdom.FindingFact{f}, false)
	if st != tmdom.StatusTheoretical {
		t.Fatalf("expected theoretical when CWE does not match, got %s", st)
	}
}

func TestDeriveStatus_IgnoresOtherAssetsAndFalsePositive(t *testing.T) {
	asset := shared.NewID()
	other := shared.NewID()
	// A matching-technique finding but on a different asset must be ignored.
	onOther := fact(shared.NewID(), other, "T1190", fsNew)
	// A false-positive on this asset is not evidence.
	fp := fact(shared.NewID(), asset, "T1190", fsFalsePositive)
	st, _, _ := deriveStatus("T1190", nil, asset.String(), []tmdom.FindingFact{onOther, fp}, false)
	if st != tmdom.StatusTheoretical {
		t.Fatalf("expected theoretical (other-asset + false-positive ignored), got %s", st)
	}
}
