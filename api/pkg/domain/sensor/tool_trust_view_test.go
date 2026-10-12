package sensor

import (
	"testing"
	"time"
)

// manifestWith is a manifest whose tools report the given contracts.
func manifestWith(contracts map[string]*ToolContract) *Manifest {
	m := &Manifest{}
	for name, c := range contracts {
		m.Tools = append(m.Tools, ManifestTool{Name: name, Contract: c})
	}
	return m
}

// The view shows each tool's trust and the tier the platform assigns, from
// the contracts the sensors report; an operator-installed copy makes the
// tool unverified and T2, and a grant below T2 excludes that sensor.
func TestComputeToolAvailability_TrustAndTier(t *testing.T) {
	builtinNaabu := builtinContract("T1", "scan.ports@1")
	adapterNaabu := builtinContract("T1", "scan.ports@1")
	adapterNaabu.Origin = ToolOriginAdapter

	a := availSensor("edge-a", ago(5*time.Second), map[string]string{"naabu": "2.3.0"})
	b := availSensor("edge-b", ago(5*time.Second), map[string]string{"naabu": "2.3.0"})
	old := availSensor("edge-old", ago(5*time.Second), map[string]string{"subfinder": "2.6.0"})
	catalog := []CatalogTool{{Name: "naabu", Enabled: true}, {Name: "subfinder", Enabled: true}}

	// Both built in: builtin, T1.
	got := ComputeToolAvailability(catalog, []SensorInventory{
		{Sensor: a, Manifest: manifestWith(map[string]*ToolContract{"naabu": builtinNaabu})},
		{Sensor: b, Manifest: manifestWith(map[string]*ToolContract{"naabu": builtinNaabu})},
		{Sensor: old},
	}, nil, testNow)
	if n := findTool(t, got, "naabu"); n.Trust != ToolTrustBuiltin || n.Tier != TierActive {
		t.Fatalf("naabu %q T%d", n.Trust, n.Tier)
	}
	// SECURITY: a sensor without a contract keeps the catalog rule, and
	// trust stays unknown rather than builtin.
	if s := findTool(t, got, "subfinder"); s.Trust != "" || s.Tier != TierPassive {
		t.Fatalf("subfinder %q T%d", s.Trust, s.Tier)
	}

	// SECURITY: one operator-installed copy makes the tool unverified, T2.
	got = ComputeToolAvailability(catalog, []SensorInventory{
		{Sensor: a, Manifest: manifestWith(map[string]*ToolContract{"naabu": builtinNaabu})},
		{Sensor: b, Manifest: manifestWith(map[string]*ToolContract{"naabu": adapterNaabu})},
	}, nil, testNow)
	if n := findTool(t, got, "naabu"); n.Trust != ToolTrustUnverified || n.Tier != TierIntrusive {
		t.Fatalf("mixed naabu %q T%d", n.Trust, n.Tier)
	}

	// SECURITY: under a T1 ceiling the unverified copy is excluded (as
	// dispatch refuses it), and the view counts only the built-in sensor.
	g := &Grant{TrustLevel: TrustTrusted, TierCeiling: TierActive, TargetNetwork: TargetNetworkAny}
	got = ComputeToolAvailability(catalog, []SensorInventory{
		{Sensor: a, Grant: g, Manifest: manifestWith(map[string]*ToolContract{"naabu": builtinNaabu})},
		{Sensor: b, Grant: g, Manifest: manifestWith(map[string]*ToolContract{"naabu": adapterNaabu})},
	}, nil, testNow)
	n := findTool(t, got, "naabu")
	if n.SensorsExcluded != 1 || n.SensorsTotal != 1 || n.Trust != ToolTrustBuiltin || n.Tier != TierActive {
		t.Fatalf("grant view: excluded %d total %d %q T%d", n.SensorsExcluded, n.SensorsTotal, n.Trust, n.Tier)
	}
}
