package stage

import (
	"fmt"
	"slices"
	"strings"
)

// Graph validation: one rule set for a scan workflow graph, used on every
// save (and by the editor through the validate endpoint). The editor only
// offers what the served contracts allow; this is the authority.

// NodeKind is what a workflow node asks for.
type NodeKind string

const (
	// NodeCapability asks for a capability; a tool is resolved at plan time
	// (optionally pinned).
	NodeCapability NodeKind = "capability"
	// NodeOpaque is a step the catalog cannot place: a tenant tool with
	// no contract. It has no ports: it runs on the scan's seeds, and an
	// edge into it orders it after its predecessor without passing data.
	NodeOpaque NodeKind = "opaque"
)

// GraphNode is one node of a workflow graph.
type GraphNode struct {
	// ID is the node's id in the graph (a workflow step's step_key).
	ID   string
	Kind NodeKind
	// Capability is the node's capability (NodeCapability only).
	Capability Key
	// Tool is the pinned tool, if any.
	Tool string
}

// GraphEdge feeds To from From. FromPort and ToPort are optional: an edge
// without ports is valid when the two nodes share at least one port type.
type GraphEdge struct {
	From, To         string
	FromPort, ToPort PortType
}

// Graph is a workflow graph.
type Graph struct {
	Nodes []GraphNode
	Edges []GraphEdge
}

// Graph size limits (a spaghetti guard).
const (
	MaxGraphNodes = 30
	MaxGraphEdges = 120
)

// Issue codes.
const (
	IssueEmptyID           = "EMPTY_NODE_ID"
	IssueDuplicateNode     = "DUPLICATE_NODE"
	IssueUnknownCapability = "UNKNOWN_CAPABILITY"
	IssuePlanned           = "CAPABILITY_NOT_AVAILABLE"
	IssueCrossCutting      = "CAPABILITY_NOT_A_NODE"
	IssueToolMismatch      = "TOOL_DOES_NOT_IMPLEMENT"
	IssueUnknownNode       = "UNKNOWN_EDGE_NODE"
	IssueSelfLoop          = "SELF_LOOP"
	IssueCycle             = "CYCLE"
	IssueIncompatible      = "INCOMPATIBLE_PORTS"
	IssueBadPort           = "UNKNOWN_PORT"
	IssueIntrusiveFed      = "INTRUSIVE_NODE_FED"
	IssueTooLarge          = "GRAPH_TOO_LARGE"
	IssueOpaqueEdge        = "EDGE_PASSES_NO_DATA"
)

// GraphIssue is one problem, anchored to a node or an edge.
type GraphIssue struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Node    string `json:"node,omitempty"`
	// From and To anchor an edge issue.
	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`
	// Adapter is the capability that would connect an incompatible edge.
	Adapter Key `json:"adapter,omitempty"`
}

// GraphReport is the outcome of ValidateGraph. Errors refuse a save;
// warnings are shown and do not.
type GraphReport struct {
	Errors   []GraphIssue `json:"errors"`
	Warnings []GraphIssue `json:"warnings"`
}

// Valid reports whether the graph has no errors.
func (r GraphReport) Valid() bool { return len(r.Errors) == 0 }

func (r *GraphReport) errorf(code string, anchor GraphIssue, format string, args ...any) {
	anchor.Code = code
	anchor.Message = fmt.Sprintf(format, args...)
	r.Errors = append(r.Errors, anchor)
}

func (r *GraphReport) warnf(code string, anchor GraphIssue, format string, args ...any) {
	anchor.Code = code
	anchor.Message = fmt.Sprintf(format, args...)
	r.Warnings = append(r.Warnings, anchor)
}

// ValidateGraph checks a workflow graph against the capability contracts:
// node ids, known and routable capabilities, a pinned tool implementing its
// capability, edges between existing nodes, no cycle, typed compatibility
// of every edge (with the adapter that would fix an incompatible one), no
// derived targets into an intrusive (T2) node, and the size limits.
func ValidateGraph(g Graph) GraphReport {
	rep := GraphReport{Errors: []GraphIssue{}, Warnings: []GraphIssue{}}
	if len(g.Nodes) > MaxGraphNodes {
		rep.errorf(IssueTooLarge, GraphIssue{}, "a workflow has at most %d nodes (this one has %d)", MaxGraphNodes, len(g.Nodes))
	}
	if len(g.Edges) > MaxGraphEdges {
		rep.errorf(IssueTooLarge, GraphIssue{}, "a workflow has at most %d connections (this one has %d)", MaxGraphEdges, len(g.Edges))
	}

	nodes := map[string]GraphNode{}
	stages := map[string]Stage{}
	for _, n := range g.Nodes {
		id := strings.TrimSpace(n.ID)
		if id == "" {
			rep.errorf(IssueEmptyID, GraphIssue{}, "a node has no id")
			continue
		}
		if _, dup := nodes[id]; dup {
			rep.errorf(IssueDuplicateNode, GraphIssue{Node: id}, "two nodes are named %q", id)
			continue
		}
		nodes[id] = n
		if n.Kind == NodeOpaque {
			continue
		}
		st, ok := checkNodeCapability(&rep, id, n)
		if ok {
			stages[id] = st
		}
	}

	adj := map[string][]string{}
	for _, e := range g.Edges {
		anchor := GraphIssue{From: e.From, To: e.To}
		from, okF := nodes[e.From]
		to, okT := nodes[e.To]
		switch {
		case !okF || !okT:
			missing := e.From
			if okF {
				missing = e.To
			}
			rep.errorf(IssueUnknownNode, anchor, "a connection names %q, which is not a node of this workflow", missing)
			continue
		case e.From == e.To:
			rep.errorf(IssueSelfLoop, anchor, "%q is connected to itself", e.From)
			continue
		}
		adj[e.From] = append(adj[e.From], e.To)
		if from.Kind == NodeOpaque || to.Kind == NodeOpaque {
			rep.warnf(IssueOpaqueEdge, anchor,
				"%s → %s only orders the two: a tool without a contract neither passes nor takes data, so %q runs on the scan's targets",
				e.From, e.To, e.To)
			continue
		}
		fs, okFS := stages[e.From]
		ts, okTS := stages[e.To]
		if !okFS || !okTS {
			continue // the node itself is already reported
		}
		checkEdge(&rep, anchor, e, fs, ts)
	}

	if cyc := findCycle(g.Nodes, adj); len(cyc) > 0 {
		rep.errorf(IssueCycle, GraphIssue{Node: cyc[0]}, "the workflow has a cycle: %s", strings.Join(cyc, " → "))
	}
	return rep
}

func checkNodeCapability(rep *GraphReport, id string, n GraphNode) (Stage, bool) {
	anchor := GraphIssue{Node: id}
	st, ok := Lookup(n.Capability)
	if !ok {
		if p, planned := lookupPlanned(n.Capability); planned {
			if p.CrossCutting {
				rep.errorf(IssueCrossCutting, anchor, "%s (%s) is used by retests, not as a workflow step", p.Name, p.Key)
			} else {
				rep.errorf(IssuePlanned, anchor, "%s (%s) is not available yet", p.Name, p.Key)
			}
			return Stage{}, false
		}
		rep.errorf(IssueUnknownCapability, anchor, "%q is not a known capability", n.Capability)
		return Stage{}, false
	}
	if n.Tool != "" && !st.Implements(n.Tool) {
		rep.errorf(IssueToolMismatch, anchor, "%s does not implement %s (%s); it implements: %s",
			n.Tool, st.Name, st.Key, strings.Join(st.Tools(), ", "))
		return Stage{}, false
	}
	return st, true
}

func checkEdge(rep *GraphReport, anchor GraphIssue, e GraphEdge, from, to Stage) {
	if e.FromPort != "" || e.ToPort != "" {
		switch {
		case e.FromPort == "" || e.ToPort == "":
			rep.errorf(IssueBadPort, anchor, "a connection names a port on one side only")
		case !from.EmitsPort(e.FromPort):
			rep.errorf(IssueBadPort, anchor, "%s has no %s output", from.Name, e.FromPort)
		case !to.TakesPort(e.ToPort):
			rep.errorf(IssueBadPort, anchor, "%s has no %s input", to.Name, e.ToPort)
		case e.FromPort != e.ToPort:
			incompatible(rep, anchor, from, to, []PortType{e.FromPort})
		}
	} else if !slices.ContainsFunc(from.OutPorts, to.TakesPort) {
		incompatible(rep, anchor, from, to, from.OutPorts)
	}
	if to.Tier >= TierIntrusive {
		rep.errorf(IssueIntrusiveFed, anchor,
			"%s is intrusive (T2): it runs only on the scan's own targets and is never fed derived targets; remove this connection",
			to.Name)
	}
}

// incompatible reports an edge whose types do not meet, naming the adapter
// that would connect them when the catalog has one.
func incompatible(rep *GraphReport, anchor GraphIssue, from, to Stage, outs []PortType) {
	for _, out := range outs {
		for _, in := range to.InPorts {
			if a, ok := AdapterFor(out, in); ok {
				as, _ := Lookup(a.Capability)
				anchor.Adapter = a.Capability
				rep.errorf(IssueIncompatible, anchor,
					"%s takes %s, but %s gives %s. Insert %s (%s) between them to turn %s into %s",
					to.Name, portNames(to.InPorts), from.Name, portNames(from.OutPorts), as.Name, as.Key, out, in)
				return
			}
		}
	}
	rep.errorf(IssueIncompatible, anchor, "%s takes %s, but %s gives %s",
		to.Name, portNames(to.InPorts), from.Name, portNames(from.OutPorts))
}

func portNames(ps []PortType) string {
	s := make([]string, len(ps))
	for i, p := range ps {
		s[i] = string(p)
	}
	return strings.Join(s, ", ")
}

func lookupPlanned(k Key) (Stage, bool) {
	for _, p := range planned {
		if p.Key == k {
			return p.clone(), true
		}
	}
	return Stage{}, false
}

// findCycle returns one cycle as a path of node ids (first == last), or nil.
func findCycle(nodes []GraphNode, adj map[string][]string) []string {
	const (
		white = iota
		grey
		black
	)
	color := map[string]int{}
	var stack []string
	var cycle []string
	var visit func(n string) bool
	visit = func(n string) bool {
		color[n] = grey
		stack = append(stack, n)
		for _, m := range adj[n] {
			switch color[m] {
			case grey:
				i := slices.Index(stack, m)
				cycle = append(slices.Clone(stack[i:]), m)
				return true
			case white:
				if visit(m) {
					return true
				}
			}
		}
		stack = stack[:len(stack)-1]
		color[n] = black
		return false
	}
	for _, n := range nodes {
		id := strings.TrimSpace(n.ID)
		if color[id] == white && visit(id) {
			return cycle
		}
	}
	return nil
}
