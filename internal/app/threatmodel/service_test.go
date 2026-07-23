package threatmodel

import (
	"testing"

	"github.com/openctemio/api/internal/app/attack"
	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/shared"
	tmdom "github.com/openctemio/api/pkg/domain/threatmodel"
	"github.com/openctemio/api/pkg/logger"
)

// TestEnumerate_EndToEnd drives the pure enumeration core (applicability +
// status) over a tiny synthetic exposure chain and finding set, proving a
// generated threat carries the right technique, mitigation, hop and — crucially
// — a live-derived status.
func TestEnumerate_EndToEnd(t *testing.T) {
	svc := &Service{logger: logger.NewNop()}

	tenantID := shared.NewID()
	entryID := shared.NewID() // public web_application (entry + target)
	hostID := shared.NewID()  // internal host reached from the web app

	chain := attack.ExposureChain{
		EntryPointID: entryID.String(),
		TargetID:     hostID.String(),
		IsCrownJewel: true,
		Score:        20,
		Hops: []attack.ChainHop{
			{AssetID: entryID.String(), AssetType: "web_application", Exposure: string(asset.ExposurePublic)},
			{AssetID: hostID.String(), AssetType: "host", Exposure: "internal"},
		},
	}

	applic := []tmdom.TechniqueApplicability{
		{TechniqueID: "T1190", AssetType: "web_application", EdgeType: "exposes", MinNetwork: "external", MinCredential: "none"},
		{TechniqueID: "T1003", AssetType: "host", EdgeType: "", MinNetwork: "internal", MinCredential: "admin", RequiresPersistence: true},
	}
	mitIdx := map[string]techInfo{
		"T1190": {tactic: "Initial Access", mitigationID: "M1050"},
		"T1003": {tactic: "Credential Access", mitigationID: "M1043"},
	}
	// Entry web app is reached via an 'exposes' edge from the entry point itself
	// (self is entry hop 0, no incoming edge); the host is reached from the web
	// app over 'exposes' too for this synthetic case.
	edgeType := map[string]string{
		edgeKey(entryID.String(), hostID.String()): "exposes",
	}
	compensating := map[string]bool{}

	// One open finding on the web app matching T1190 → that threat is "open".
	openFinding := tmdom.FindingFact{
		ID: shared.NewID(), AssetID: entryID, TechniqueID: "T1190", Status: fsConfirmed,
	}
	findings := []tmdom.FindingFact{openFinding}

	extUnauth := tmdom.AttackerProfileFact{
		ID:          shared.NewID(),
		Name:        "External Unauth",
		ProfileType: "external_unauth",
		Capabilities: tmdom.AttackerCapabilities{
			NetworkAccess: "external", CredentialLevel: "none",
		},
	}
	insider := tmdom.AttackerProfileFact{
		ID:          shared.NewID(),
		Name:        "Insider",
		ProfileType: "malicious_insider",
		Capabilities: tmdom.AttackerCapabilities{
			NetworkAccess: "internal", CredentialLevel: "admin", Persistence: true,
		},
	}

	threats := svc.enumerate(tenantID, []attack.ExposureChain{chain},
		[]tmdom.AttackerProfileFact{extUnauth, insider}, applic, mitIdx, edgeType, compensating, findings)

	if len(threats) == 0 {
		t.Fatal("expected threats to be enumerated")
	}

	// The external-unauth attacker should have produced T1190 at hop 0 (the
	// exposed web app is the entry hop → edge "" any) — wait: T1190 requires the
	// 'exposes' edge, so it applies at hop 0 only if that catalog row's edge is
	// matched. Hop 0 has no incoming edge, so T1190 (edge='exposes') does NOT
	// apply at hop 0. It DOES apply at hop 1 only if hop1 is a web_application,
	// which it is not (host). So for this synthetic graph T1190 should NOT appear;
	// instead assert the capability gating: only the insider unlocks T1003 on the
	// host, and no external-unauth technique fires on the host.
	var insiderHostT1003, extUnauthOnHost bool
	for _, tr := range threats {
		if tr.TechniqueID == "T1003" && tr.HopAssetID != nil && tr.HopAssetID.String() == hostID.String() {
			insiderHostT1003 = true
			if tr.AttackerProfileID == nil || tr.AttackerProfileID.String() != insider.ID.String() {
				t.Errorf("T1003 on host must be attributed to the insider profile")
			}
			if tr.Tactic != "Credential Access" || tr.MitigationID != "M1043" {
				t.Errorf("T1003 threat missing tactic/mitigation: tactic=%q mit=%q", tr.Tactic, tr.MitigationID)
			}
			if tr.Status != tmdom.StatusTheoretical {
				t.Errorf("T1003 on host has no finding → expected theoretical, got %s", tr.Status)
			}
			if tr.ChainFingerprint == "" {
				t.Errorf("threat must carry a chain fingerprint")
			}
			if tr.Score <= 0 {
				t.Errorf("threat score should be positive (chain.Score × weight), got %v", tr.Score)
			}
		}
		if tr.HopAssetID != nil && tr.HopAssetID.String() == hostID.String() &&
			tr.AttackerProfileID != nil && tr.AttackerProfileID.String() == extUnauth.ID.String() {
			extUnauthOnHost = true
		}
	}
	if !insiderHostT1003 {
		t.Error("expected the insider to unlock T1003 on the internal host")
	}
	if extUnauthOnHost {
		t.Error("external-unauth attacker must NOT unlock host techniques (capability gate)")
	}
}

// TestEnrichThreatCatalog maps mitigation_id → name (and technique_name +
// summary) from a single catalog slice, and tolerates a threat whose mitigation
// id has no catalog row (names stay empty → UI falls back to the raw id).
func TestEnrichThreatCatalog(t *testing.T) {
	mits := []tmdom.TechniqueMitigation{
		{TechniqueID: "T1190", TechniqueName: "Exploit Public-Facing Application",
			MitigationID: "M1050", MitigationName: "Exploit Protection",
			MitigationSummary: "Use capabilities to prevent exploitation."},
		{TechniqueID: "T1003", TechniqueName: "OS Credential Dumping",
			MitigationID: "M1043", MitigationName: "Credential Access Protection",
			MitigationSummary: "Restrict credential dumping."},
	}

	seeded := &tmdom.ThreatModelThreat{TechniqueID: "T1190", MitigationID: "M1050"}
	missing := &tmdom.ThreatModelThreat{TechniqueID: "T9999", MitigationID: "M9999"}
	// Technique in catalog but paired with an unseeded mitigation id: technique
	// name resolves, mitigation name/summary stay empty.
	techOnly := &tmdom.ThreatModelThreat{TechniqueID: "T1003", MitigationID: "M0000"}

	enrichThreatCatalog(mits, []*tmdom.ThreatModelThreat{seeded, missing, techOnly, nil})

	if seeded.MitigationName != "Exploit Protection" {
		t.Errorf("seeded mitigation name = %q, want %q", seeded.MitigationName, "Exploit Protection")
	}
	if seeded.TechniqueName != "Exploit Public-Facing Application" {
		t.Errorf("seeded technique name = %q", seeded.TechniqueName)
	}
	if seeded.MitigationSummary == "" {
		t.Error("seeded threat should carry a mitigation summary")
	}
	if missing.MitigationName != "" || missing.TechniqueName != "" {
		t.Errorf("unknown ids must leave names empty, got mit=%q tech=%q", missing.MitigationName, missing.TechniqueName)
	}
	if techOnly.TechniqueName != "OS Credential Dumping" {
		t.Errorf("technique name should resolve independently of mitigation, got %q", techOnly.TechniqueName)
	}
	if techOnly.MitigationName != "" {
		t.Errorf("unseeded mitigation pairing must leave mitigation name empty, got %q", techOnly.MitigationName)
	}
}

// TestEnumerate_OpenStatusFromFinding proves the status seam: when a finding on
// the hop asset matches the technique, the emitted threat is non-theoretical.
func TestEnumerate_OpenStatusFromFinding(t *testing.T) {
	svc := &Service{logger: logger.NewNop()}
	tenantID := shared.NewID()
	entryID := shared.NewID() // public web_application, also the target

	chain := attack.ExposureChain{
		EntryPointID: entryID.String(),
		TargetID:     entryID.String(),
		Score:        10,
		Hops: []attack.ChainHop{
			{AssetID: entryID.String(), AssetType: "domain", Exposure: string(asset.ExposurePublic)},
		},
	}
	// Recon technique applies to a domain over any edge with no creds.
	applic := []tmdom.TechniqueApplicability{
		{TechniqueID: "T1595", AssetType: "domain", EdgeType: "", MinNetwork: "external", MinCredential: "none"},
	}
	mitIdx := map[string]techInfo{"T1595": {tactic: "Reconnaissance", mitigationID: "M1056"}}
	findings := []tmdom.FindingFact{
		{ID: shared.NewID(), AssetID: entryID, TechniqueID: "T1595", Status: fsNew},
	}
	prof := tmdom.AttackerProfileFact{
		ID:           shared.NewID(),
		Capabilities: tmdom.AttackerCapabilities{NetworkAccess: "external", CredentialLevel: "none"},
	}

	threats := svc.enumerate(tenantID, []attack.ExposureChain{chain},
		[]tmdom.AttackerProfileFact{prof}, applic, mitIdx, map[string]string{}, map[string]bool{}, findings)

	if len(threats) != 1 {
		t.Fatalf("expected exactly 1 threat, got %d", len(threats))
	}
	tr := threats[0]
	if tr.TechniqueID != "T1595" || tr.Status != tmdom.StatusOpen {
		t.Fatalf("expected open T1595, got technique=%s status=%s", tr.TechniqueID, tr.Status)
	}
	if tr.EvidenceFindingID == nil {
		t.Error("open threat must carry the evidence finding id")
	}
}
