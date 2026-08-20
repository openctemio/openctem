package postgres

import (
	"strconv"
	"testing"

	"github.com/openctemio/api/pkg/domain/asset"
)

// --- Feature 1: multi-hop control-plane walk (walkControlPlane) --------------

// cpGraph is a tiny builder: edges[controlPlane] = served ids, plus per-asset
// criticality (name defaults to the id).
type cpGraph struct {
	edges map[string][]string
	crit  map[string]asset.Criticality
	names map[string]string
}

func newCPGraph() *cpGraph {
	return &cpGraph{
		edges: map[string][]string{},
		crit:  map[string]asset.Criticality{},
		names: map[string]string{},
	}
}

// serves records "controlPlane is the control plane of served" (edge served ->
// controlPlane, is_control_plane) and sets the served asset's own criticality.
func (g *cpGraph) serves(controlPlane, served string, c asset.Criticality) *cpGraph {
	g.edges[controlPlane] = append(g.edges[controlPlane], served)
	g.crit[served] = c
	g.names[served] = served
	return g
}

func TestWalkControlPlane_SingleHopBackCompat(t *testing.T) {
	// idp is the control plane of a critical service — the original 1-hop case.
	g := newCPGraph().serves("idp", "svc", asset.CriticalityCritical)
	got, name := walkControlPlane("idp", g.edges, g.crit, g.names, maxControlPlaneDepth)
	if got != asset.CriticalityCritical {
		t.Fatalf("single-hop crit = %q, want critical", got)
	}
	if name != "svc" {
		t.Fatalf("single-hop name = %q, want svc", name)
	}
}

func TestWalkControlPlane_TwoHop(t *testing.T) {
	// idp -> secrets -> crown(critical). idp is control plane of secrets (low),
	// secrets is control plane of the crown jewel. idp must inherit critical.
	g := newCPGraph().
		serves("idp", "secrets", asset.CriticalityLow).
		serves("secrets", "crown", asset.CriticalityCritical)
	got, name := walkControlPlane("idp", g.edges, g.crit, g.names, maxControlPlaneDepth)
	if got != asset.CriticalityCritical {
		t.Fatalf("2-hop crit = %q, want critical", got)
	}
	if name != "crown" {
		t.Fatalf("2-hop name = %q, want crown", name)
	}
}

func TestWalkControlPlane_ThreeHop(t *testing.T) {
	// idp -> secrets -> db -> crown(critical): three hops, still within cap 3.
	g := newCPGraph().
		serves("idp", "secrets", asset.CriticalityLow).
		serves("secrets", "db", asset.CriticalityMedium).
		serves("db", "crown", asset.CriticalityCritical)
	got, _ := walkControlPlane("idp", g.edges, g.crit, g.names, maxControlPlaneDepth)
	if got != asset.CriticalityCritical {
		t.Fatalf("3-hop crit = %q, want critical", got)
	}
}

func TestWalkControlPlane_BeyondDepthCapDoesNotPropagate(t *testing.T) {
	// Four hops to the crown jewel; hops 1-3 are only low/medium. With cap 3 the
	// critical asset at hop 4 must NOT propagate.
	g := newCPGraph().
		serves("idp", "a", asset.CriticalityLow).
		serves("a", "b", asset.CriticalityLow).
		serves("b", "c", asset.CriticalityMedium).
		serves("c", "crown", asset.CriticalityCritical)
	got, _ := walkControlPlane("idp", g.edges, g.crit, g.names, maxControlPlaneDepth)
	if got == asset.CriticalityCritical {
		t.Fatalf("crit at hop 4 must not propagate with cap %d, got %q", maxControlPlaneDepth, got)
	}
	if got != asset.CriticalityMedium { // hop-3 medium is the deepest reachable
		t.Fatalf("within-cap crit = %q, want medium (hop 3)", got)
	}
}

func TestWalkControlPlane_CycleTerminates(t *testing.T) {
	// a -> b -> a cycle, plus a critical branch off b. Must terminate AND still
	// pick up the critical asset reachable within the cap.
	g := newCPGraph().
		serves("a", "b", asset.CriticalityLow).
		serves("b", "a", asset.CriticalityLow).
		serves("b", "crown", asset.CriticalityCritical)
	done := make(chan struct{})
	var got asset.Criticality
	go func() {
		got, _ = walkControlPlane("a", g.edges, g.crit, g.names, maxControlPlaneDepth)
		close(done)
	}()
	<-done // if the walk did not terminate, the test would hang / time out
	if got != asset.CriticalityCritical {
		t.Fatalf("cycle graph crit = %q, want critical", got)
	}
}

func TestWalkControlPlane_NoServedAssets(t *testing.T) {
	// An asset that is nobody's control plane gets the zero criticality.
	g := newCPGraph()
	got, name := walkControlPlane("lonely", g.edges, g.crit, g.names, maxControlPlaneDepth)
	if got != "" || name != "" {
		t.Fatalf("no-edge walk = (%q,%q), want empty", got, name)
	}
}

// --- Feature 2: BU hierarchy criticality inheritance (resolveBUCriticality) --

func TestResolveBUCriticality_OwnHigherNotLowered(t *testing.T) {
	// Child is critical, parent only medium — child keeps its own (only-raise).
	nodes := map[string]buNode{
		"child":  {parentID: "parent", crit: asset.CriticalityCritical, name: "Payments"},
		"parent": {parentID: "", crit: asset.CriticalityMedium, name: "Corp"},
	}
	got, name := resolveBUCriticality("child", nodes, maxBUHierarchyDepth)
	if got != asset.CriticalityCritical || name != "Payments" {
		t.Fatalf("own-higher = (%q,%q), want (critical,Payments)", got, name)
	}
}

func TestResolveBUCriticality_InheritsParent(t *testing.T) {
	// Child is low, parent is critical — child inherits critical + parent name.
	nodes := map[string]buNode{
		"child":  {parentID: "parent", crit: asset.CriticalityLow, name: "Team"},
		"parent": {parentID: "", crit: asset.CriticalityCritical, name: "Payments"},
	}
	got, name := resolveBUCriticality("child", nodes, maxBUHierarchyDepth)
	if got != asset.CriticalityCritical || name != "Payments" {
		t.Fatalf("inherit = (%q,%q), want (critical,Payments)", got, name)
	}
}

func TestResolveBUCriticality_MultiLevelChain(t *testing.T) {
	// grandchild(low) -> child(medium) -> root(critical): inherits root's critical.
	nodes := map[string]buNode{
		"grandchild": {parentID: "child", crit: asset.CriticalityLow, name: "Squad"},
		"child":      {parentID: "root", crit: asset.CriticalityMedium, name: "Div"},
		"root":       {parentID: "", crit: asset.CriticalityCritical, name: "Payments"},
	}
	got, name := resolveBUCriticality("grandchild", nodes, maxBUHierarchyDepth)
	if got != asset.CriticalityCritical || name != "Payments" {
		t.Fatalf("multi-level = (%q,%q), want (critical,Payments)", got, name)
	}
}

func TestResolveBUCriticality_FlatBackCompat(t *testing.T) {
	// No parent — result is exactly the BU's own criticality/name.
	nodes := map[string]buNode{
		"bu": {parentID: "", crit: asset.CriticalityHigh, name: "IT"},
	}
	got, name := resolveBUCriticality("bu", nodes, maxBUHierarchyDepth)
	if got != asset.CriticalityHigh || name != "IT" {
		t.Fatalf("flat = (%q,%q), want (high,IT)", got, name)
	}
}

func TestResolveBUCriticality_CycleTerminates(t *testing.T) {
	// a -> b -> a parent cycle. Must terminate and take the MAX seen (high).
	nodes := map[string]buNode{
		"a": {parentID: "b", crit: asset.CriticalityLow, name: "A"},
		"b": {parentID: "a", crit: asset.CriticalityHigh, name: "B"},
	}
	done := make(chan struct{})
	var got asset.Criticality
	go func() {
		got, _ = resolveBUCriticality("a", nodes, maxBUHierarchyDepth)
		close(done)
	}()
	<-done
	if got != asset.CriticalityHigh {
		t.Fatalf("cycle chain = %q, want high", got)
	}
}

func TestResolveBUCriticality_DepthCap(t *testing.T) {
	// Chain longer than the cap: the critical BU sits beyond maxDepth ancestors,
	// so it must not propagate. Build n0 -> n1 -> ... where the last is critical.
	nodes := map[string]buNode{}
	const chain = maxBUHierarchyDepth + 3
	for i := 0; i < chain; i++ {
		id := "n" + strconv.Itoa(i)
		parent := ""
		if i < chain-1 {
			parent = "n" + strconv.Itoa(i+1)
		}
		c := asset.CriticalityLow
		if i == chain-1 {
			c = asset.CriticalityCritical // beyond the cap from n0
		}
		nodes[id] = buNode{parentID: parent, crit: c, name: id}
	}
	got, _ := resolveBUCriticality("n0", nodes, maxBUHierarchyDepth)
	if got == asset.CriticalityCritical {
		t.Fatalf("critical BU beyond depth cap %d must not propagate, got %q", maxBUHierarchyDepth, got)
	}
}

func TestResolveBUCriticality_Unknown(t *testing.T) {
	got, name := resolveBUCriticality("missing", map[string]buNode{}, maxBUHierarchyDepth)
	if got != "" || name != "" {
		t.Fatalf("unknown BU = (%q,%q), want empty", got, name)
	}
}
