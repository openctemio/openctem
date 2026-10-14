package stage_test

import (
	"slices"
	"testing"

	. "github.com/openctemio/openctem/api/pkg/domain/stage"
	"github.com/openctemio/openctem/api/pkg/domain/stage/stagetest"
)

// A capability is routed to a tool only a reported contract describes, with
// the contract's param mapping (standard params only) and batch flag.
func TestWithTools_ContractOnlyToolImplementsItsCapability(t *testing.T) {
	st, err := cat.ForCapabilities([]string{"dast.web"})
	if err != nil {
		t.Fatal(err)
	}
	if !st.Available() || st.DefaultTool() != "toyweb" || !st.Implements("ToyWeb") {
		t.Fatalf("dast.web implementations = %+v", st.Implementations)
	}
	if k, ok := st.ToolParamKey("toyweb", "max_duration_minutes"); !ok || k != "max_minutes" {
		t.Fatalf("max_duration_minutes -> %q %v", k, ok)
	}
	if _, ok := st.ToolParamKey("toyweb", "not_a_param"); ok {
		t.Fatal("a mapping of a param the capability does not define was kept")
	}
	if cat.AcceptsTargetList("toyweb") || st.ChunkSizeFor("toyweb") != 0 {
		t.Fatal("toyweb's contract takes one target per task")
	}
	if got := ToolConfig(st, "toyweb", map[string]any{"max_duration_minutes": 30}, false); got["max_minutes"] != 30 {
		t.Fatalf("toyweb config = %v", got)
	}
	if cat.ProbeTier("toyweb") != TierIntrusive || !cat.WebTool("toyweb") {
		t.Fatal("toyweb runs dast.web: T2, a web tool")
	}
	// Without its contract the same organization has no dast.web tool.
	if st, _ := stagetest.Catalog().ForCapabilities([]string{"dast.web"}); st.Available() {
		t.Fatalf("dast.web runnable without a reported contract: %v", st.Tools())
	}
}

// A capability the catalog does not route is never routed, whatever a
// contract claims; the zero catalog routes nothing.
func TestWithTools_UnknownCapabilityIsNotRouted(t *testing.T) {
	c := WithTools([]ToolFacts{{Name: "odd", Implements: []Key{"made.up", "sbom.generate"}, Batch: true}})
	if got := c.ForTool("odd"); len(got) != 0 {
		t.Fatalf("odd implements %v", got)
	}
	if _, ok := c.ForStep("odd", nil); ok {
		t.Fatal("a tool without a routed capability was placed")
	}
	if len(Catalog{}.ToolNames()) != 0 || (Catalog{}).ProbeTier("nuclei") != TierActive {
		t.Fatal("the zero catalog knows tools")
	}
}

// The default preference orders the implementations; a tool it does not
// name comes after, by name; the first present is the default.
func TestWithTools_DefaultPreference(t *testing.T) {
	c := WithTools([]ToolFacts{
		{Name: "zz-sast", Implements: []Key{SASTCode}},
		{Name: "codeql", Implements: []Key{SASTCode}},
		{Name: "aa-sast", Implements: []Key{SASTCode}},
		{Name: "opengrep", Implements: []Key{SASTCode}},
		{Name: "OpenGrep", Implements: []Key{SecretsCode}}, // a second report of the same tool is ignored
	})
	st, _ := c.Lookup(SASTCode)
	if got := st.Tools(); !slices.Equal(got, []string{"opengrep", "codeql", "aa-sast", "zz-sast"}) {
		t.Fatalf("order = %v", got)
	}
	if st.DefaultTool() != "opengrep" {
		t.Fatalf("default = %s", st.DefaultTool())
	}
	if len(c.ForTool("opengrep")) != 1 {
		t.Fatal("a duplicate report widened a tool")
	}
}

// naabu (scan.ports first, discover.hosts second): pinned without a
// capability it scans ports; it discovers hosts only when the step names
// it. Its facts equal the tables they replace.
func TestWithTools_PrimaryCapability(t *testing.T) {
	ports, _ := cat.Lookup(ScanPorts)
	hosts, _ := cat.Lookup(DiscoverHosts)
	pi := ports.Implementations[slices.IndexFunc(ports.Implementations, func(i Implementation) bool { return i.Tool == "naabu" })]
	hi := hosts.Implementations[slices.IndexFunc(hosts.Implementations, func(i Implementation) bool { return i.Tool == "naabu" })]
	if pi.ByCapability || !hi.ByCapability || !pi.Batch || !hi.Batch || !pi.Default || !hi.Default {
		t.Fatalf("naabu implementations: %+v %+v", pi, hi)
	}
	if pi.Params["top_n"] != "top_ports" || pi.Params["ports"] != "ports" || pi.Params["rate"] != "rate" {
		t.Fatalf("naabu scan.ports params: %v", pi.Params)
	}
	if s, ok := cat.ForStep("naabu", nil); !ok || s.Key != ScanPorts {
		t.Fatalf("pinned naabu -> %s %v", s.Key, ok)
	}
	if s, ok := cat.ForStep("naabu", []string{"discover.hosts"}); !ok || s.Key != DiscoverHosts {
		t.Fatalf("naabu discover.hosts -> %s %v", s.Key, ok)
	}
}

// One organization's facts never show in another's catalog.
func TestWithTools_CatalogsAreSeparate(t *testing.T) {
	a := WithTools([]ToolFacts{{Name: "tool-a", Implements: []Key{ProbeHTTP}}})
	b := WithTools([]ToolFacts{{Name: "tool-b", Implements: []Key{ProbeHTTP}}})
	if st, _ := a.Lookup(ProbeHTTP); !slices.Equal(st.Tools(), []string{"tool-a"}) {
		t.Fatalf("a: %v", st.Tools())
	}
	if st, _ := b.Lookup(ProbeHTTP); !slices.Equal(st.Tools(), []string{"tool-b"}) {
		t.Fatalf("b: %v", st.Tools())
	}
	if st, _ := Lookup(ProbeHTTP); st.Available() {
		t.Fatal("the package catalog has implementations")
	}
}
