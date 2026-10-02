package threatmodel

import (
	"testing"

	tmdom "github.com/openctemio/api/pkg/domain/threatmodel"
)

func cat() []tmdom.TechniqueApplicability {
	return []tmdom.TechniqueApplicability{
		// Public web exploit — any external attacker, needs the 'exposes' edge.
		{TechniqueID: "T1190", AssetType: "web_application", EdgeType: "exposes", MinNetwork: "external", MinCredential: "none"},
		// Recon on a domain — external, no edge required.
		{TechniqueID: "T1595", AssetType: "domain", EdgeType: "", MinNetwork: "external", MinCredential: "none"},
		// Credential dumping on a host — internal + admin + persistence.
		{TechniqueID: "T1003", AssetType: "host", EdgeType: "", MinNetwork: "internal", MinCredential: "admin", RequiresPersistence: true},
		// Valid accounts — user creds, authenticates_to edge.
		{TechniqueID: "T1078", AssetType: "host", EdgeType: "authenticates_to", MinNetwork: "external", MinCredential: "user"},
	}
}

func techIDs(ts []ApplicableTechnique) map[string]bool {
	m := make(map[string]bool, len(ts))
	for _, t := range ts {
		m[t.TechniqueID] = true
	}
	return m
}

func TestApplicableTechniques_ExternalUnauthGate(t *testing.T) {
	caps := tmdom.AttackerCapabilities{NetworkAccess: "external", CredentialLevel: "none"}

	// web_application reached via 'exposes' → T1190 included.
	got := techIDs(applicableTechniques("web_application", "exposes", caps, cat()))
	if !got["T1190"] {
		t.Errorf("expected T1190 for external-unauth on exposed web_application, got %v", got)
	}

	// Same asset but wrong incoming edge → T1190 excluded (edge constraint).
	got = techIDs(applicableTechniques("web_application", "depends_on", caps, cat()))
	if got["T1190"] {
		t.Errorf("T1190 must not match when incoming edge is not 'exposes'")
	}

	// host via authenticates_to but attacker has no creds → T1078 excluded.
	got = techIDs(applicableTechniques("host", "authenticates_to", caps, cat()))
	if got["T1078"] {
		t.Errorf("T1078 requires user creds; external-unauth must not unlock it")
	}
	// And T1003 (internal+admin+persistence) excluded for external-unauth.
	if got["T1003"] {
		t.Errorf("T1003 requires internal+admin+persistence; must be excluded")
	}
}

func TestApplicableTechniques_InsiderUnlocksDeeperTechniques(t *testing.T) {
	insider := tmdom.AttackerCapabilities{NetworkAccess: "internal", CredentialLevel: "admin", Persistence: true}

	got := techIDs(applicableTechniques("host", "", insider, cat()))
	if !got["T1003"] {
		t.Errorf("insider (internal+admin+persistence) should unlock T1003, got %v", got)
	}

	// user-cred edge technique needs the matching edge; with "" edge it's excluded.
	if got["T1078"] {
		t.Errorf("T1078 requires 'authenticates_to' edge; must not match entry hop")
	}
	got = techIDs(applicableTechniques("host", "authenticates_to", insider, cat()))
	if !got["T1078"] {
		t.Errorf("insider over authenticates_to should unlock T1078")
	}
}

func TestApplicableTechniques_PersistenceGate(t *testing.T) {
	// internal + admin but NO persistence → T1003 excluded.
	noPersist := tmdom.AttackerCapabilities{NetworkAccess: "internal", CredentialLevel: "admin", Persistence: false}
	if techIDs(applicableTechniques("host", "", noPersist, cat()))["T1003"] {
		t.Errorf("T1003 requires persistence; attacker without persistence must be excluded")
	}
}

func TestApplicableTechniques_AssetTypeExact(t *testing.T) {
	caps := tmdom.AttackerCapabilities{NetworkAccess: "external", CredentialLevel: "none"}
	// domain recon technique should not appear on a web_application.
	if techIDs(applicableTechniques("web_application", "", caps, cat()))["T1595"] {
		t.Errorf("T1595 is domain-scoped; must not match web_application")
	}
	if !techIDs(applicableTechniques("domain", "", caps, cat()))["T1595"] {
		t.Errorf("T1595 should match a domain over any edge")
	}
}

func TestTechniqueWeight_Ordering(t *testing.T) {
	easy := tmdom.TechniqueApplicability{MinNetwork: "external", MinCredential: "none"}
	hard := tmdom.TechniqueApplicability{MinNetwork: "internal", MinCredential: "admin", RequiresPersistence: true}
	if techniqueWeight(easy) <= techniqueWeight(hard) {
		t.Errorf("easy technique should weigh more than a privilege+persistence-gated one: easy=%v hard=%v",
			techniqueWeight(easy), techniqueWeight(hard))
	}
	if techniqueWeight(hard) < 0.1 {
		t.Errorf("weight must be floored at 0.1, got %v", techniqueWeight(hard))
	}
}
