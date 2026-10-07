package scanrun

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
)

// A scan workflow's steps as a workflow graph, validated on every save against
// the capability contracts (stage.ValidateGraph). Before, a save checked only
// each step's key and tool: an edge between incompatible steps (subfinder →
// katana), a cycle or a dependency on a missing step was stored, and the run
// silently fed the step the scan's seeds instead.

// GraphInvalidError refuses a save whose graph has errors. It carries the
// whole report, so the caller can point at each node and edge.
type GraphInvalidError struct {
	Report stage.GraphReport
}

func (e *GraphInvalidError) Error() string {
	msgs := make([]string, 0, len(e.Report.Errors))
	for _, is := range e.Report.Errors {
		msgs = append(msgs, is.Message)
	}
	return "the workflow is not valid: " + strings.Join(msgs, "; ")
}

// Unwrap makes the error a validation error.
func (e *GraphInvalidError) Unwrap() error { return shared.ErrValidation }

// StepsGraph is the workflow graph of a scan workflow's steps: one node per step
// (its id is the step key), one edge per dependency.
//
// A step is a capability node when the catalog places it (stage.ForStep:
// a pinned catalog tool, or capability words naming one stage), with its
// tool as the pin. A step naming a planned or cross-cutting capability is a
// capability node too, so the validator refuses it by name. Anything else
// (a tenant tool with no contract, legacy words naming no stage) is opaque:
// it runs on the scan's seeds and takes no data from its predecessors.
func StepsGraph(steps []*scanworkflow.Step) stage.Graph {
	g := stage.Graph{Nodes: make([]stage.GraphNode, 0, len(steps))}
	for _, s := range steps {
		g.Nodes = append(g.Nodes, stepNode(s))
		for _, dep := range s.DependsOn {
			g.Edges = append(g.Edges, stage.GraphEdge{From: dep, To: s.StepKey})
		}
	}
	return g
}

func stepNode(s *scanworkflow.Step) stage.GraphNode {
	if st, ok := stage.ForStep(s.Tool, s.Capabilities); ok {
		return stage.GraphNode{ID: s.StepKey, Kind: stage.NodeCapability, Capability: st.Key, Tool: s.Tool}
	}
	for _, c := range s.Capabilities {
		k := stage.Key(strings.ToLower(strings.TrimSpace(c)))
		if slices.ContainsFunc(stage.Taxonomy(), func(t stage.Stage) bool { return t.Key == k }) {
			return stage.GraphNode{ID: s.StepKey, Kind: stage.NodeCapability, Capability: k, Tool: s.Tool}
		}
	}
	return stage.GraphNode{ID: s.StepKey, Kind: stage.NodeOpaque, Tool: s.Tool}
}

// validateStepsGraph refuses steps whose graph has errors.
func validateStepsGraph(steps []*scanworkflow.Step) error {
	rep := stage.ValidateGraph(StepsGraph(steps))
	if !rep.Valid() {
		return &GraphInvalidError{Report: rep}
	}
	return nil
}

// ValidateGraphInput is a set of steps to check without saving them.
type ValidateGraphInput struct {
	TenantID string
	Steps    []AddStepInput
}

// ValidateGraph checks a would-be scan workflow (the editor's draft): each step
// as a save checks it, then the graph. Nothing is stored and no tenant data
// is read beyond the tenant's tool registry.
func (s *Service) ValidateGraph(ctx context.Context, input ValidateGraphInput) (stage.GraphReport, error) {
	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return stage.GraphReport{}, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	steps := make([]*scanworkflow.Step, 0, len(input.Steps))
	for i, in := range input.Steps {
		if in.Order == 0 {
			in.Order = i + 1
		}
		st, err := s.buildStep(ctx, tenantID, shared.ID{}, in)
		if err != nil {
			return stage.GraphReport{}, err
		}
		steps = append(steps, st)
	}
	return stage.ValidateGraph(StepsGraph(steps)), nil
}
