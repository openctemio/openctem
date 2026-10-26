package stage

import "testing"

// A planned capability is refused as a node unless the step is optional (it
// waits for a tool): then it is a warning and its connections are typed.
func TestValidateGraph_OptionalPlannedNode(t *testing.T) {
	g := Graph{
		Nodes: []GraphNode{
			{ID: "http", Kind: NodeCapability, Capability: ProbeHTTP},
			{ID: "shots", Kind: NodeCapability, Capability: "capture.screenshot", Optional: true},
		},
		Edges: []GraphEdge{{From: "http", To: "shots"}},
	}
	rep := ValidateGraph(g)
	if !rep.Valid() || len(rep.Warnings) != 1 || rep.Warnings[0].Code != IssueWaitsForTool {
		t.Fatalf("optional planned node: errors %+v warnings %+v", rep.Errors, rep.Warnings)
	}

	g.Nodes[1].Optional = false
	if rep := ValidateGraph(g); rep.Valid() || rep.Errors[0].Code != IssuePlanned {
		t.Fatalf("a planned node that is not optional must be refused: %+v", rep.Errors)
	}

	// Optional does not excuse a wrong connection: a screenshot takes web
	// addresses, not root domains.
	bad := Graph{
		Nodes: []GraphNode{
			{ID: "rdap", Kind: NodeCapability, Capability: LookupRDAP},
			{ID: "shots", Kind: NodeCapability, Capability: "capture.screenshot", Optional: true},
		},
		Edges: []GraphEdge{{From: "rdap", To: "shots"}},
	}
	if rep := ValidateGraph(bad); rep.Valid() {
		t.Fatal("an optional node must still have typed connections")
	}

	// A cross-cutting capability is never a node, optional or not.
	cc := Graph{Nodes: []GraphNode{{ID: "v", Kind: NodeCapability, Capability: "verify.finding", Optional: true}}}
	if rep := ValidateGraph(cc); rep.Valid() || rep.Errors[0].Code != IssueCrossCutting {
		t.Fatalf("verify.finding as an optional node: %+v", rep.Errors)
	}
	// An unknown capability stays unknown.
	unk := Graph{Nodes: []GraphNode{{ID: "x", Kind: NodeCapability, Capability: "exploit.everything", Optional: true}}}
	if rep := ValidateGraph(unk); rep.Valid() || rep.Errors[0].Code != IssueUnknownCapability {
		t.Fatalf("unknown optional capability: %+v", rep.Errors)
	}
	if !IsPlanned("capture.screenshot") || IsPlanned("verify.finding") || IsPlanned(ScanPorts) {
		t.Fatal("IsPlanned")
	}
}

// Depth params are standard params only: no tool extras, no executor keys,
// no unknown names, and each value within the contract.
func TestValidateStandardParams(t *testing.T) {
	ports, _ := Lookup(ScanPorts)
	if err := ValidateStandardParams(ports, map[string]any{"top_n": 1000}); err != nil {
		t.Fatal(err)
	}
	for _, p := range []map[string]any{
		{"x": map[string]any{"naabu": map[string]any{"rate": 1}}},
		{"exclude": []string{"10.0.0.1"}},
		{"command": "sh"},
		{"top_n": 70000},
		{"top_n": "many"},
	} {
		if err := ValidateStandardParams(ports, p); err == nil {
			t.Errorf("%v accepted", p)
		}
	}
}
