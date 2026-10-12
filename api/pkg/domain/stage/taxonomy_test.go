package stage

import (
	"fmt"
	"slices"
	"testing"

	"github.com/openctemio/ctis/capability"
)

// Every capability contract is the taxonomy entry of ctis/capability: ports,
// params, tier floor, phase and ATT\&CK ids come from there, never from a
// second copy here.
func TestContractsComeFromTheTaxonomy(t *testing.T) {
	for _, s := range Taxonomy() {
		c, ok := capability.Lookup(s.ID())
		if !ok {
			t.Fatalf("%s is not in ctis/capability", s.ID())
		}
		if s.Tier != Tier(c.TierFloor) {
			t.Errorf("%s: tier %s, floor T%d", s.Key, s.Tier, c.TierFloor)
		}
		if fmt.Sprint(s.InPorts) != fmt.Sprint(c.InPorts) || fmt.Sprint(s.OutPorts) != fmt.Sprint(c.OutPorts) {
			t.Errorf("%s: ports %v/%v, taxonomy %v/%v", s.Key, s.InPorts, s.OutPorts, c.InPorts, c.OutPorts)
		}
		if len(s.Params) != len(c.Params) {
			t.Errorf("%s: %d params, taxonomy %d", s.Key, len(s.Params), len(c.Params))
		}
		if s.Phase != string(c.Phase) || s.CTEMStage != c.CTEMStage() || !slices.Equal(s.Attack, c.ATTACK) {
			t.Errorf("%s: phase/stage/attack differ from the taxonomy", s.Key)
		}
		if len(s.RequiredOutput) != len(c.Outputs) {
			t.Errorf("%s: required output rules differ", s.Key)
		}
	}
	// The platform port table covers every taxonomy port type.
	for _, p := range capability.PortTypes() {
		if _, ok := LookupPortType(PortType(p.Type)); !ok {
			t.Errorf("port type %s has no platform carries", p.Type)
		}
	}
}

func TestNewCapabilitiesArePlanned(t *testing.T) {
	for _, k := range []Key{"discover.cloud", "sbom.generate", "import.file"} {
		if _, ok := Lookup(k); ok {
			t.Errorf("%s is routed", k)
		}
		found := false
		for _, s := range Taxonomy() {
			found = found || s.Key == k
		}
		if !found {
			t.Errorf("%s is not listed", k)
		}
	}
}

func TestLookupCapabilityPanicsOnUnknown(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("no panic")
		}
	}()
	lookupCapability("scan.everything")
}
