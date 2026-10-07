package stage

import (
	"strings"
	"testing"
)

func capNode(id string, k Key) GraphNode {
	return GraphNode{ID: id, Kind: NodeCapability, Capability: k}
}

func codes(issues []GraphIssue) []string {
	out := make([]string, len(issues))
	for i, is := range issues {
		out[i] = is.Code
	}
	return out
}

func hasCode(issues []GraphIssue, code string) bool {
	for _, is := range issues {
		if is.Code == code {
			return true
		}
	}
	return false
}

// The full recon → vuln chain (the owner's example) is valid.
func TestValidateGraph_ReconToVulnChain(t *testing.T) {
	g := Graph{
		Nodes: []GraphNode{
			capNode("subdomains", DiscoverSubdomains),
			capNode("resolve", ResolveDNS),
			capNode("ports", ScanPorts),
			capNode("http", ProbeHTTP),
			capNode("crawl", CrawlWeb),
			{ID: "vulns", Kind: NodeCapability, Capability: VulnTemplates, Tool: "nuclei"},
		},
		Edges: []GraphEdge{
			{From: "subdomains", To: "resolve"},
			{From: "resolve", To: "ports"},
			{From: "ports", To: "http"},
			{From: "http", To: "crawl"},
			{From: "http", To: "vulns"},
			{From: "crawl", To: "vulns"},
			{From: "ports", To: "vulns", FromPort: PortService, ToPort: PortService},
		},
	}
	rep := ValidateGraph(g)
	if !rep.Valid() || len(rep.Warnings) != 0 {
		t.Fatalf("valid chain refused: errors %+v warnings %+v", rep.Errors, rep.Warnings)
	}
}

// subfinder → katana: hostnames into a URL crawler. Refused at the edge, with
// the adapter that fixes it.
func TestValidateGraph_IncompatibleEdgeNamesTheAdapter(t *testing.T) {
	rep := ValidateGraph(Graph{
		Nodes: []GraphNode{
			{ID: "subs", Kind: NodeCapability, Capability: DiscoverSubdomains, Tool: "subfinder"},
			{ID: "crawl", Kind: NodeCapability, Capability: CrawlWeb, Tool: "katana"},
		},
		Edges: []GraphEdge{{From: "subs", To: "crawl"}},
	})
	if rep.Valid() || len(rep.Errors) != 1 {
		t.Fatalf("errors: %+v", rep.Errors)
	}
	e := rep.Errors[0]
	if e.Code != IssueIncompatible || e.From != "subs" || e.To != "crawl" || e.Adapter != ProbeHTTP {
		t.Fatalf("issue: %+v", e)
	}
	if !strings.Contains(e.Message, "HTTP probe") || !strings.Contains(e.Message, "hostname") {
		t.Fatalf("message does not explain: %q", e.Message)
	}
}

func TestValidateGraph_Refusals(t *testing.T) {
	cases := map[string]struct {
		g    Graph
		code string
	}{
		"unknown capability": {Graph{Nodes: []GraphNode{capNode("a", "scan.everything")}}, IssueUnknownCapability},
		"planned capability": {Graph{Nodes: []GraphNode{capNode("a", "check.tls")}}, IssuePlanned},
		"cross-cutting":      {Graph{Nodes: []GraphNode{capNode("a", "verify.finding")}}, IssueCrossCutting},
		"pinned tool does not implement": {Graph{Nodes: []GraphNode{
			{ID: "a", Kind: NodeCapability, Capability: ScanPorts, Tool: "nuclei"}}}, IssueToolMismatch},
		"empty id":  {Graph{Nodes: []GraphNode{capNode(" ", ScanPorts)}}, IssueEmptyID},
		"duplicate": {Graph{Nodes: []GraphNode{capNode("a", ScanPorts), capNode("a", ProbeHTTP)}}, IssueDuplicateNode},
		"dangling edge": {Graph{Nodes: []GraphNode{capNode("a", ScanPorts)},
			Edges: []GraphEdge{{From: "a", To: "ghost"}}}, IssueUnknownNode},
		"self loop": {Graph{Nodes: []GraphNode{capNode("a", ProbeHTTP)},
			Edges: []GraphEdge{{From: "a", To: "a"}}}, IssueSelfLoop},
		"cycle": {Graph{Nodes: []GraphNode{capNode("a", ProbeHTTP), capNode("b", CrawlWeb)},
			Edges: []GraphEdge{{From: "a", To: "b"}, {From: "b", To: "a"}}}, IssueCycle},
		"code to network": {Graph{Nodes: []GraphNode{capNode("s", SASTCode), capNode("p", ScanPorts)},
			Edges: []GraphEdge{{From: "s", To: "p"}}}, IssueIncompatible},
		"findings feed nothing": {Graph{Nodes: []GraphNode{capNode("v", VulnTemplates), capNode("c", CrawlWeb)},
			Edges: []GraphEdge{{From: "v", To: "c"}}}, IssueIncompatible},
		"port not on node": {Graph{Nodes: []GraphNode{capNode("a", ResolveDNS), capNode("b", ScanPorts)},
			Edges: []GraphEdge{{From: "a", To: "b", FromPort: PortURL, ToPort: PortURL}}}, IssueBadPort},
		"one-sided port": {Graph{Nodes: []GraphNode{capNode("a", ResolveDNS), capNode("b", ScanPorts)},
			Edges: []GraphEdge{{From: "a", To: "b", FromPort: PortIP}}}, IssueBadPort},
		"mismatched ports": {Graph{Nodes: []GraphNode{capNode("a", ResolveDNS), capNode("b", ScanPorts)},
			Edges: []GraphEdge{{From: "a", To: "b", FromPort: PortIP, ToPort: PortHostname}}}, IssueIncompatible},
		"derived targets into T2": {Graph{Nodes: []GraphNode{capNode("h", ProbeHTTP), capNode("z", DASTWeb)},
			Edges: []GraphEdge{{From: "h", To: "z"}}}, IssueIntrusiveFed},
	}
	for name, c := range cases {
		rep := ValidateGraph(c.g)
		if rep.Valid() || !hasCode(rep.Errors, c.code) {
			t.Errorf("%s: errors %v, want %s", name, codes(rep.Errors), c.code)
		}
	}
}

func TestValidateGraph_CycleIsNamed(t *testing.T) {
	rep := ValidateGraph(Graph{
		Nodes: []GraphNode{capNode("a", ProbeHTTP), capNode("b", CrawlWeb), capNode("c", CrawlWeb)},
		Edges: []GraphEdge{{From: "a", To: "b"}, {From: "b", To: "c"}, {From: "c", To: "b"}},
	})
	var msg string
	for _, e := range rep.Errors {
		if e.Code == IssueCycle {
			msg = e.Message
		}
	}
	if !strings.Contains(msg, "b → c → b") {
		t.Fatalf("cycle message %q", msg)
	}
}

// A T2 node on the scan's own targets is fine (it is never fed).
func TestValidateGraph_IntrusiveRootAllowed(t *testing.T) {
	if rep := ValidateGraph(Graph{Nodes: []GraphNode{capNode("z", DASTWeb)}}); !rep.Valid() {
		t.Fatalf("T2 root refused: %+v", rep.Errors)
	}
}

// A tool the catalog does not know has no ports: an edge to or from it is
// a warning (it orders, it passes nothing), never a silent "seeds only".
func TestValidateGraph_OpaqueNodesWarn(t *testing.T) {
	rep := ValidateGraph(Graph{
		Nodes: []GraphNode{capNode("http", ProbeHTTP), {ID: "custom", Kind: NodeOpaque, Tool: "dotenv-check"}},
		Edges: []GraphEdge{{From: "http", To: "custom"}},
	})
	if !rep.Valid() || len(rep.Warnings) != 1 || rep.Warnings[0].Code != IssueOpaqueEdge {
		t.Fatalf("errors %+v warnings %+v", rep.Errors, rep.Warnings)
	}
}

func TestValidateGraph_SizeLimits(t *testing.T) {
	var g Graph
	for i := range MaxGraphNodes + 1 {
		g.Nodes = append(g.Nodes, capNode(strings.Repeat("n", i+1), ScanPorts))
	}
	if rep := ValidateGraph(g); !hasCode(rep.Errors, IssueTooLarge) {
		t.Fatalf("31 nodes: %v", codes(rep.Errors))
	}
	g = Graph{Nodes: []GraphNode{capNode("a", ResolveDNS), capNode("b", ScanPorts)}}
	for range MaxGraphEdges + 1 {
		g.Edges = append(g.Edges, GraphEdge{From: "a", To: "b"})
	}
	if rep := ValidateGraph(g); !hasCode(rep.Errors, IssueTooLarge) {
		t.Fatalf("121 edges: %v", codes(rep.Errors))
	}
}

// Every issue is anchored to a node or an edge (or the whole graph for the
// size limits), so the editor can point at it.
func TestValidateGraph_IssuesAreAnchored(t *testing.T) {
	rep := ValidateGraph(Graph{
		Nodes: []GraphNode{capNode("s", SASTCode), capNode("p", ScanPorts), capNode("x", "nope")},
		Edges: []GraphEdge{{From: "s", To: "p"}},
	})
	for _, e := range rep.Errors {
		if e.Node == "" && (e.From == "" || e.To == "") {
			t.Fatalf("unanchored issue %+v", e)
		}
	}
}
