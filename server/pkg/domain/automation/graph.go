package automation

import (
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Graph error codes. Each is a 400 (shared.ErrValidation).
const (
	ErrCodeGraphCycle       = "WORKFLOW_GRAPH_CYCLE"
	ErrCodeGraphUnreachable = "WORKFLOW_GRAPH_UNREACHABLE"
	ErrCodeGraphEdge        = "WORKFLOW_GRAPH_EDGE"
)

// Condition output handles. An edge out of a condition node leaves through
// one of them; the executor follows "yes" when the expression holds.
const (
	HandleYes = "yes"
	HandleNo  = "no"
)

// checkEdgeShape refuses an edge into a trigger (a trigger only starts a run)
// and an edge out of a condition without a yes/no handle.
func checkEdgeShape(e *Edge, nodeType func(string) (NodeType, bool)) error {
	if t, ok := nodeType(e.TargetNodeKey); ok && t == NodeTypeTrigger {
		return shared.NewDomainError(ErrCodeGraphEdge,
			fmt.Sprintf("edge %s -> %s ends at a trigger; a trigger only starts a run", e.SourceNodeKey, e.TargetNodeKey),
			shared.ErrValidation)
	}
	if t, ok := nodeType(e.SourceNodeKey); ok && t == NodeTypeCondition &&
		e.SourceHandle != HandleYes && e.SourceHandle != HandleNo {
		return shared.NewDomainError(ErrCodeGraphEdge,
			fmt.Sprintf("edge %s -> %s leaves a condition without a yes/no handle", e.SourceNodeKey, e.TargetNodeKey),
			shared.ErrValidation)
	}
	return nil
}

// findCycle returns a node key on a cycle of the graph, or "".
func findCycle(keys []string, out map[string][]string) string {
	const (
		unseen = iota
		open
		done
	)
	state := make(map[string]int, len(keys))
	var visit func(k string) string
	visit = func(k string) string {
		state[k] = open
		for _, next := range out[k] {
			switch state[next] {
			case open:
				return next
			case unseen:
				if c := visit(next); c != "" {
					return c
				}
			}
		}
		state[k] = done
		return ""
	}
	for _, k := range keys {
		if state[k] == unseen {
			if c := visit(k); c != "" {
				return c
			}
		}
	}
	return ""
}

// validateTopology refuses edges into triggers, condition edges without a
// handle and cycles; with requireReachable it also refuses a node no
// trigger leads to (it would never run). It assumes keys are unique and
// edges reference existing nodes.
func (w *Workflow) validateTopology(requireReachable bool) error {
	types := make(map[string]NodeType, len(w.Nodes))
	keys := make([]string, 0, len(w.Nodes))
	for _, n := range w.Nodes {
		types[n.NodeKey] = n.NodeType
		keys = append(keys, n.NodeKey)
	}
	lookup := func(k string) (NodeType, bool) { t, ok := types[k]; return t, ok }
	out := make(map[string][]string, len(w.Nodes))
	for _, e := range w.Edges {
		if err := checkEdgeShape(e, lookup); err != nil {
			return err
		}
		out[e.SourceNodeKey] = append(out[e.SourceNodeKey], e.TargetNodeKey)
	}
	if k := findCycle(keys, out); k != "" {
		return shared.NewDomainError(ErrCodeGraphCycle,
			"workflow graph has a cycle through node "+k+"; a run must end", shared.ErrValidation)
	}
	if !requireReachable {
		return nil
	}
	reached := make(map[string]bool, len(keys))
	var stack []string
	for _, k := range keys {
		if types[k] == NodeTypeTrigger {
			reached[k] = true
			stack = append(stack, k)
		}
	}
	for len(stack) > 0 {
		k := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for _, next := range out[k] {
			if !reached[next] {
				reached[next] = true
				stack = append(stack, next)
			}
		}
	}
	for _, k := range keys {
		if !reached[k] {
			return shared.NewDomainError(ErrCodeGraphUnreachable,
				"node "+k+" is not connected to a trigger and would never run", shared.ErrValidation)
		}
	}
	return nil
}

// ValidateTopology checks the loaded graph has no edge into a trigger, no
// condition edge without a handle, no cycle, and no node a trigger does not
// reach. Unlike ValidateGraph it accepts an empty graph.
func (w *Workflow) ValidateTopology() error {
	return w.validateTopology(true)
}

// ValidateNewEdge checks that adding e to the loaded graph keeps it valid:
// both ends exist, it does not end at a trigger, a condition edge has a
// yes/no handle, and it closes no cycle. Reachability is not required here
// (a graph is built one edge at a time); a full-graph save checks it.
func (w *Workflow) ValidateNewEdge(e *Edge) error {
	if w.GetNodeByKey(e.SourceNodeKey) == nil || w.GetNodeByKey(e.TargetNodeKey) == nil {
		return shared.NewDomainError(ErrCodeGraphEdge, "edge references an unknown node", shared.ErrValidation)
	}
	trial := &Workflow{Nodes: w.Nodes, Edges: append(append([]*Edge{}, w.Edges...), e)}
	return trial.validateTopology(false)
}
