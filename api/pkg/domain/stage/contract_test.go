package stage

import (
	"slices"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
)

func portKnown(t PortType) bool {
	_, ok := LookupPortType(t)
	return ok
}

// carriedBy reports whether some port in ports carries ref.
func carriedBy(ref asset.TypeRef, ports []PortType) bool {
	for _, p := range ports {
		if p.Carries(ref) {
			return true
		}
	}
	return false
}

func TestPortTypes_ClosedSetOfTen(t *testing.T) {
	got := PortTypes()
	if len(got) != 10 {
		t.Fatalf("port types: %d, want the closed set of 10", len(got))
	}
	seen := map[PortType]bool{}
	for _, p := range got {
		if seen[p.Type] || p.Label == "" {
			t.Fatalf("port type %q duplicated or unlabelled", p.Type)
		}
		seen[p.Type] = true
		if p.Type != PortFinding && len(p.Carries) == 0 {
			t.Fatalf("port type %q carries no stored type", p.Type)
		}
	}
	if PortType("technology").Carries(tHTTPService) {
		t.Fatal("an unknown port type must carry nothing")
	}
}

// The ports are the typed face of the stored Inputs/Outputs the router
// uses: every type a stage takes is carried by one of its input ports, and
// every input port carries something the stage takes (no port that can be
// wired but never fed). Same for outputs; the certificate is an output with
// no port yet.
func TestContracts_PortsMatchStoredTypes(t *testing.T) {
	for _, s := range All() {
		if s.Version != ContractVersion || s.ID() != string(s.Key)+"@1" {
			t.Fatalf("%s: version %d id %s", s.Key, s.Version, s.ID())
		}
		if len(s.InPorts) == 0 || len(s.OutPorts) == 0 {
			t.Fatalf("%s: a routed capability needs in and out ports", s.Key)
		}
		for _, p := range append(slices.Clone(s.InPorts), s.OutPorts...) {
			if !portKnown(p) {
				t.Fatalf("%s: unknown port type %q", s.Key, p)
			}
		}
		for _, in := range s.Inputs {
			if !carriedBy(in, s.InPorts) {
				t.Errorf("%s: input %s has no input port", s.Key, Label(in))
			}
		}
		for _, p := range s.InPorts {
			info, _ := LookupPortType(p)
			if !slices.ContainsFunc(info.Carries, s.Accepts) {
				t.Errorf("%s: input port %s carries nothing the stage takes", s.Key, p)
			}
		}
		for _, out := range s.Outputs {
			if out == tCertificate {
				continue
			}
			if !carriedBy(out, s.OutPorts) {
				t.Errorf("%s: output %s has no output port", s.Key, Label(out))
			}
		}
		for _, p := range s.OutPorts {
			if p == PortFinding {
				if !s.Findings {
					t.Errorf("%s: finding port on a stage that reports no findings", s.Key)
				}
				continue
			}
			info, _ := LookupPortType(p)
			if !slices.ContainsFunc(info.Carries, s.Produces) {
				t.Errorf("%s: output port %s carries nothing the stage produces", s.Key, p)
			}
		}
		if s.Findings && !s.EmitsPort(PortFinding) {
			t.Errorf("%s: reports findings but has no finding port", s.Key)
		}
	}
}

func TestContracts_ParamsAndMappings(t *testing.T) {
	for _, s := range Taxonomy() {
		names := map[string]bool{}
		for _, p := range s.Params {
			if p.Name == "" || names[p.Name] {
				t.Fatalf("%s: param %q empty or duplicated", s.Key, p.Name)
			}
			names[p.Name] = true
			switch p.Type {
			case ParamString, ParamStringList, ParamInteger, ParamBoolean, ParamPortList:
			default:
				t.Fatalf("%s.%s: unknown param type %q", s.Key, p.Name, p.Type)
			}
			if p.Min != nil && p.Max != nil && *p.Min > *p.Max {
				t.Fatalf("%s.%s: min above max", s.Key, p.Name)
			}
		}
		if len(s.RequiredOutputFields) == 0 {
			t.Fatalf("%s: no required output fields", s.Key)
		}
		for _, impl := range s.Implementations {
			if impl.Params == nil {
				t.Fatalf("%s/%s: no param mapping", s.Key, impl.Tool)
			}
			for std, key := range impl.Params {
				if !names[std] || key == "" {
					t.Fatalf("%s/%s: maps %q, not a standard param of the capability", s.Key, impl.Tool, std)
				}
			}
		}
	}
	// Every tool mapping names a param of a capability the tool implements,
	// so no mapping silently drops out of the contract.
	for tool, m := range toolParams {
		for std := range m {
			found := false
			for _, s := range ForTool(tool) {
				if _, ok := s.Implementations[slices.IndexFunc(s.Implementations, func(i Implementation) bool { return i.Tool == tool })].Params[std]; ok {
					found = true
				}
			}
			if !found {
				t.Fatalf("tool %s maps %q, which none of its capabilities declares", tool, std)
			}
		}
	}
	// The mapped keys are the settings the sensor declares for the tool.
	scan, _ := Lookup(ScanPorts)
	if got := scan.Implementations[0].Params; got["top_n"] != "top_ports" || got["ports"] != "ports" || got["rate"] != "rate" {
		t.Fatalf("naabu mapping: %v", got)
	}
}

func TestAdapters_TypeCheck(t *testing.T) {
	if len(Adapters()) == 0 {
		t.Fatal("no adapters")
	}
	for _, a := range Adapters() {
		s, ok := Lookup(a.Capability)
		if !ok {
			t.Fatalf("adapter %s→%s: unknown capability %s", a.From, a.To, a.Capability)
		}
		if !s.TakesPort(a.From) || !s.EmitsPort(a.To) {
			t.Fatalf("adapter %s→%s: %s does not take %s and emit %s", a.From, a.To, s.Key, a.From, a.To)
		}
		if s.Tier >= TierIntrusive {
			t.Fatalf("adapter %s is intrusive", s.Key)
		}
	}
	if a, ok := AdapterFor(PortHostname, PortURL); !ok || a.Capability != ProbeHTTP {
		t.Fatalf("hostname→url adapter: %+v %v", a, ok)
	}
	if _, ok := AdapterFor(PortRepository, PortURL); ok {
		t.Fatal("repository→url must have no adapter")
	}
}

// Taxonomy v1 has 22 capabilities. The planned ones are listed but never
// routed: no lookup, tool or capability word reaches them.
func TestTaxonomy_PlannedAreNeverRouted(t *testing.T) {
	all := Taxonomy()
	if len(all) != 22 {
		t.Fatalf("taxonomy v1: %d capabilities, want 22", len(all))
	}
	ids := map[string]bool{}
	for _, s := range all {
		if ids[s.ID()] {
			t.Fatalf("duplicate capability id %s", s.ID())
		}
		ids[s.ID()] = true
		if s.CrossCutting != (s.Key == "verify.finding") {
			t.Fatalf("%s: cross-cutting flag", s.Key)
		}
	}
	for _, p := range planned {
		if p.Available() || len(p.Implementations) > 0 {
			t.Fatalf("planned %s has implementations", p.Key)
		}
		if _, ok := Lookup(p.Key); ok {
			t.Fatalf("planned %s is visible to Lookup", p.Key)
		}
		if _, err := ForCapabilities([]string{string(p.Key)}); err == nil {
			t.Fatalf("planned %s resolves from a capability word", p.Key)
		}
		for _, port := range append(slices.Clone(p.InPorts), p.OutPorts...) {
			if !portKnown(port) {
				t.Fatalf("planned %s: unknown port %q", p.Key, port)
			}
		}
	}
	// Adding the planned contracts changed no tool's routing.
	if len(ForTool("nuclei")) != 1 || len(ForTool("httpx")) != 1 {
		t.Fatal("a planned capability changed how nuclei or httpx steps route")
	}
}

func TestAcceptsTargetList(t *testing.T) {
	for _, tool := range []string{"nuclei", "subfinder", "dnsx", "naabu", "httpx", "katana", " NUCLEI "} {
		if !AcceptsTargetList(tool) {
			t.Errorf("%q takes a target list", tool)
		}
	}
	for _, tool := range []string{"zap", "semgrep", "trivy", "tenable_sc", "betterleaks", "unknown", ""} {
		if AcceptsTargetList(tool) {
			t.Errorf("%q takes one target per task", tool)
		}
	}
	for _, s := range All() {
		for _, impl := range s.Implementations {
			if impl.Batch != AcceptsTargetList(impl.Tool) {
				t.Errorf("%s/%s: implementation batch flag disagrees", s.Key, impl.Tool)
			}
		}
	}
}
