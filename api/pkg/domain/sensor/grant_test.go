package sensor

// Per-sensor grant admission, trust and narrowing (RFC-052 §5, threat model
// §6 rows 2, 11, 13, 14, 15, 16).

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func payload(t *testing.T, v map[string]any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustProfile(t *testing.T, name string, zones ...shared.ID) Grant {
	t.Helper()
	g, err := NewGrantFromProfile(shared.NewID(), shared.NewID(), name, zones)
	if err != nil {
		t.Fatalf("profile %s: %v", name, err)
	}
	if err := g.Normalize(); err != nil {
		t.Fatalf("normalize %s: %v", name, err)
	}
	return *g
}

func trusted(g Grant) Grant { g.TrustLevel = TrustTrusted; return g }

func TestProfiles_NarrowestDefaults(t *testing.T) {
	for _, p := range SelectableProfiles() {
		g := mustProfile(t, p)
		if g.TrustLevel != TrustNew {
			t.Errorf("%s: trust %s, want new", p, g.TrustLevel)
		}
		if g.TierCeiling == TierIntrusive {
			t.Errorf("%s: T2 by default", p)
		}
		if len(g.RemoteActions) != 0 {
			t.Errorf("%s: gated remote actions %v by default", p, g.RemoteActions)
		}
		e := g.Effective()
		if e.TierCeiling != TierPassive || e.AllowCredentials || e.AllowPushIngest {
			t.Errorf("%s: New is not passive-only without credentials and push: %+v", p, e)
		}
	}
	if ValidProfile(ProfileLegacyBroad) {
		t.Error("legacy-broad is selectable")
	}
	if !ValidProfile("collector:tenable-sc") || ValidProfile("collector:Bad Name") || ValidProfile("scanner:x") {
		t.Error("collector parameter validation")
	}
	if g := mustProfile(t, "collector:tenable-sc"); !slices.Equal(g.Tools, []string{"tenable-sc"}) || g.TargetNetwork != TargetNetworkNone {
		t.Errorf("collector grant: %+v", g)
	}
}

// Threat 2: a New sensor (just paired, perhaps after a phished approval)
// gets no active work and no credentials.
func TestAdmit_NewSensorPassiveOnly(t *testing.T) {
	g := mustProfile(t, ProfileInternalScanner)
	if r := g.Admit("scan", payload(t, map[string]any{"scanner": "nuclei", "targets": []string{"example.com"}}), nil); r == nil || r.Dimension != DimTier {
		t.Fatalf("New sensor admitted a T1 nuclei scan: %v", r)
	}
	if r := g.Admit("scan", payload(t, map[string]any{"scanner": "subfinder", "targets": []string{"example.com"}}), nil); r != nil {
		t.Fatalf("New sensor refused a T0 subfinder scan: %v", r)
	}
	if r := trusted(g).Admit("scan", payload(t, map[string]any{"scanner": "nuclei", "targets": []string{"example.com"}}), nil); r != nil {
		t.Fatalf("trusted sensor refused a T1 scan: %v", r)
	}
	// Control commands always pass.
	if r := g.Admit("health_check", nil, nil); r != nil {
		t.Fatalf("health_check refused: %v", r)
	}
}

// Threat 11: claims outside the grant's job types, zones, tools,
// capabilities and tier.
func TestAdmit_Dimensions(t *testing.T) {
	zA, zB := shared.NewID(), shared.NewID()
	g := trusted(mustProfile(t, ProfileInternalScanner, zA))
	scan := payload(t, map[string]any{"scanner": "nuclei", "targets": []string{"10.0.0.5"}})
	if r := g.Admit("scan", scan, &zB); r == nil || r.Dimension != DimZones {
		t.Errorf("other zone: %v", r)
	}
	if r := g.Admit("scan", scan, &zA); r != nil {
		t.Errorf("own zone: %v", r)
	}
	if r := g.Admit("collect", payload(t, map[string]any{"collector": "x"}), nil); r == nil || r.Dimension != DimJobTypes {
		t.Errorf("job type: %v", r)
	}
	g.Tools = []string{"subfinder"}
	if r := g.Admit("scan", scan, nil); r == nil || r.Dimension != DimTools {
		t.Errorf("tool: %v", r)
	}
	g.Tools = nil
	g.Capabilities = []string{"recon"}
	if r := g.Admit("scan", payload(t, map[string]any{"scanner": "nuclei", "required_capabilities": []string{"vulnerability"}}), nil); r == nil || r.Dimension != DimCapabilities {
		t.Errorf("capability: %v", r)
	}
	g.Capabilities = nil
	// Custom templates or out-of-band callbacks make a job T2; an unknown
	// tool is T2 (fail closed).
	if r := g.Admit("scan", payload(t, map[string]any{"scanner": "nuclei", "config": map[string]any{"allow_interactsh": true}}), nil); r == nil || r.Dimension != DimTier {
		t.Errorf("interactsh T2: %v", r)
	}
	if r := g.Admit("scan", payload(t, map[string]any{"scanner": "made-up-tool"}), nil); r == nil || r.Dimension != DimTier {
		t.Errorf("unknown tool: %v", r)
	}
	if lb := LegacyBroadGrant(shared.NewID(), shared.NewID()); lb.Admit("scan", payload(t, map[string]any{"scanner": "made-up-tool"}), nil) != nil {
		t.Error("legacy-broad refused a T2 job")
	}
}

// Threat 14: credential jobs only to trusted sensors whose grant allows them.
func TestAdmit_Credentials(t *testing.T) {
	cred := payload(t, map[string]any{"scanner": "nuclei", "targets": []string{"example.com"},
		"scanner_config": map[string]any{"api_key": "sk-live-abcdefghijklmnop"}})
	auth := mustProfile(t, ProfileAuthenticatedScanner)
	if r := auth.Admit("scan", cred, nil); r == nil {
		t.Fatal("New authenticated-scanner admitted a credential job")
	}
	if r := trusted(auth).Admit("scan", cred, nil); r != nil {
		t.Fatalf("trusted authenticated-scanner refused a credential job: %v", r)
	}
	if r := trusted(mustProfile(t, ProfileInternalScanner)).Admit("scan", cred, nil); r == nil || r.Dimension != DimCredentials {
		t.Fatalf("internal-network-scanner admitted a credential job: %v", r)
	}
	if !CarriesCredentials(json.RawMessage(`{"scanner_config":`)) {
		t.Error("an unreadable payload must count as carrying credentials")
	}
}

// Threat 15: private targets for easm-external; targets outside the scope.
func TestAdmit_Targets(t *testing.T) {
	easm := trusted(mustProfile(t, ProfileEASMExternal))
	for _, target := range []string{"10.1.2.3", "192.168.0.0/24", "db.internal", "http://127.0.0.1:8080/x"} {
		if r := easm.Admit("scan", payload(t, map[string]any{"scanner": "nuclei", "targets": []string{target}}), nil); r == nil || r.Dimension != DimTargetNetwork {
			t.Errorf("easm-external admitted private target %s: %v", target, r)
		}
	}
	if r := easm.Admit("scan", payload(t, map[string]any{"scanner": "nuclei", "target": "www.example.com"}), nil); r != nil {
		t.Errorf("easm-external refused a public target: %v", r)
	}

	g := trusted(mustProfile(t, ProfileInternalScanner))
	g.TargetCIDRs, g.TargetDomains = []string{"10.0.0.0/16"}, []string{"corp.example.com"}
	if err := g.Normalize(); err != nil {
		t.Fatal(err)
	}
	in := []string{"10.0.4.5", "10.0.1.0/24", "app.corp.example.com", "https://corp.example.com/login"}
	out := []string{"10.1.0.1", "10.0.0.0/8", "example.com", "evilcorp.example.com.attacker.net"}
	for _, target := range in {
		if r := g.Admit("scan", payload(t, map[string]any{"scanner": "nuclei", "targets": []string{target}}), nil); r != nil {
			t.Errorf("in-scope %s refused: %v", target, r)
		}
	}
	for _, target := range out {
		if r := g.Admit("scan", payload(t, map[string]any{"scanner": "nuclei", "targets": []string{target}}), nil); r == nil || r.Dimension != DimTargetScope {
			t.Errorf("out-of-scope %s admitted: %v", target, r)
		}
	}
	// No network targets for a code-only grant; a repository path passes.
	ci := trusted(mustProfile(t, ProfileCIRunner))
	if r := ci.Admit("scan", payload(t, map[string]any{"scanner": "semgrep", "targets": []string{"example.com"}}), nil); r == nil || r.Dimension != DimTargetNetwork {
		t.Errorf("ci-runner admitted a network target: %v", r)
	}
	if r := ci.Admit("scan", payload(t, map[string]any{"scanner": "semgrep", "targets": []string{"org/repo"}}), nil); r != nil {
		t.Errorf("ci-runner refused a repository: %v", r)
	}
	if r := g.Admit("scan", json.RawMessage(`{"scanner":"nuclei","target":5}`), nil); r == nil {
		t.Error("unreadable targets admitted")
	}
}

func TestRemoteActions(t *testing.T) {
	g := mustProfile(t, ProfileInternalScanner)
	for _, a := range []string{"pause", "drain", "cancel", "resume", "send_manifest"} {
		if !g.MayReceiveAction(a) {
			t.Errorf("%s must always be allowed", a)
		}
	}
	for _, a := range []string{"update", "rotate_key", "diagnostics"} {
		if g.MayReceiveAction(a) {
			t.Errorf("%s allowed without the grant listing it", a)
		}
		if !LegacyBroadGrant(shared.NewID(), shared.NewID()).MayReceiveAction(a) {
			t.Errorf("legacy-broad refuses %s", a)
		}
	}
}

// Threat 16: every widening is detected, dimension by dimension; narrowing
// is not reported as widening.
func TestWidened(t *testing.T) {
	cur := mustProfile(t, ProfileEASMExternal)
	cases := map[string]func(*Grant){
		DimTrust:         func(g *Grant) { g.TrustLevel = TrustTrusted },
		DimJobTypes:      func(g *Grant) { g.JobTypes = append(g.JobTypes, "collect") },
		DimTools:         func(g *Grant) { g.Tools = nil },
		DimTier:          func(g *Grant) { g.TierCeiling = TierIntrusive },
		DimTargetNetwork: func(g *Grant) { g.TargetNetwork = TargetNetworkAny },
		DimCredentials:   func(g *Grant) { g.AllowCredentials = true },
		DimPushIngest:    func(g *Grant) { g.AllowPushIngest = true },
		DimRemoteActions: func(g *Grant) { g.RemoteActions = []string{"update"} },
	}
	for dim, mutate := range cases {
		next := cur
		next.JobTypes = slices.Clone(cur.JobTypes)
		if dim == DimTools {
			cur.Tools = []string{"nuclei"}
		}
		mutate(&next)
		if w := Widened(cur, next); !slices.Contains(w, dim) {
			t.Errorf("%s widening not detected: %v", dim, w)
		}
		cur.Tools = nil
	}
	scoped := cur
	scoped.TargetCIDRs = []string{"10.0.0.0/16"}
	wider := scoped
	wider.TargetCIDRs = []string{"10.0.0.0/8"}
	if !slices.Contains(Widened(scoped, wider), DimTargetScope) {
		t.Error("larger CIDR not detected as widening")
	}
	narrower := scoped
	narrower.TargetCIDRs = []string{"10.0.1.0/24"}
	if w := Widened(scoped, narrower); len(w) != 0 {
		t.Errorf("narrower CIDR reported as widening: %v", w)
	}
	if w := Widened(scoped, cur); !slices.Contains(w, DimTargetScope) {
		t.Errorf("dropping the scope not detected: %v", w)
	}
	z := shared.NewID()
	zoned := mustProfile(t, ProfileInternalScanner, z)
	unzoned := zoned
	unzoned.ZoneIDs = nil
	if !slices.Contains(Widened(zoned, unzoned), DimZones) {
		t.Error("removing the zone limit not detected")
	}
	lb := LegacyBroadGrant(cur.TenantID, cur.SensorID)
	if w := Widened(*lb, cur); len(w) != 0 {
		t.Errorf("legacy-broad -> easm-external reported as widening: %v", w)
	}
	if c := Changed(cur, cur); len(c) != 0 {
		t.Errorf("no change reported as %v", c)
	}
}

func TestNormalize_Rejects(t *testing.T) {
	for name, mutate := range map[string]func(*Grant){
		"trust":   func(g *Grant) { g.TrustLevel = "restricted" },
		"tier":    func(g *Grant) { g.TierCeiling = 3 },
		"network": func(g *Grant) { g.TargetNetwork = "lan" },
		"job":     func(g *Grant) { g.JobTypes = []string{"rm -rf"} },
		"cidr":    func(g *Grant) { g.TargetCIDRs = []string{"10.0.0.0/33"} },
		"domain":  func(g *Grant) { g.TargetDomains = []string{"no_dot"} },
		"action":  func(g *Grant) { g.RemoteActions = []string{"shell"} },
	} {
		g := mustProfile(t, ProfileInternalScanner)
		mutate(&g)
		if err := g.Normalize(); err == nil {
			t.Errorf("%s: invalid grant accepted", name)
		}
	}
	g := mustProfile(t, ProfileInternalScanner)
	g.TargetCIDRs = []string{"10.0.0.7/16", "10.0.0.1"}
	g.Tools = []string{" Gitleaks ", "nuclei", "nuclei"}
	if err := g.Normalize(); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(g.TargetCIDRs, []string{"10.0.0.0/16", "10.0.0.1/32"}) || !slices.Equal(g.Tools, []string{"betterleaks", "nuclei"}) {
		t.Errorf("normalised: %v %v", g.TargetCIDRs, g.Tools)
	}
}

// With the sensor-level tool limit gone, the grant is what narrows a
// sensor's tools: a sensor that reports nuclei and trivy, granted only
// nuclei, is refused a trivy job and admitted a nuclei job.
func TestAdmit_GrantNarrowsReportedTools(t *testing.T) {
	a := &Sensor{Reported: ReportOf("nuclei", "trivy")}
	if !a.HasTool("trivy") || !a.HasTool("nuclei") {
		t.Fatalf("effective tools %v", a.EffectiveTools())
	}
	g := trusted(mustProfile(t, ProfileInternalScanner))
	g.Tools = []string{"nuclei"}
	if r := g.Admit("scan", payload(t, map[string]any{"scanner": "trivy", "targets": []string{"10.0.0.5"}}), nil); r == nil || r.Dimension != DimTools {
		t.Fatalf("trivy outside the grant admitted: %v", r)
	}
	if r := g.Admit("scan", payload(t, map[string]any{"scanner": "nuclei", "targets": []string{"10.0.0.5"}}), nil); r != nil {
		t.Fatalf("nuclei inside the grant refused: %v", r)
	}
}
