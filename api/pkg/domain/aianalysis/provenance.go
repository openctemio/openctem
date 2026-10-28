package aianalysis

import (
	"context"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Provenance is what every change an analyst makes carries: which analyst,
// which run, which model and prompt, and who was accountable at that moment.
// The executor puts it in the context before it calls a command; the finding
// activity writer and the audit logger stamp it on their rows, so a command
// needs no AI-specific code.
type Provenance struct {
	AnalystID            shared.ID
	AnalystName          string
	RunID                shared.ID
	Executor             Executor
	Provider             string
	Model                string
	PromptTemplateID     string
	PromptTemplateDigest string
	Accountable          []OwnerRef
	TriggeredBy          *shared.ID
}

type provenanceKey struct{}

// WithProvenance returns ctx carrying p.
func WithProvenance(ctx context.Context, p Provenance) context.Context {
	return context.WithValue(ctx, provenanceKey{}, p)
}

// ProvenanceFrom returns the provenance in ctx, if any.
func ProvenanceFrom(ctx context.Context) (Provenance, bool) {
	p, ok := ctx.Value(provenanceKey{}).(Provenance)
	return p, ok && !p.AnalystID.IsZero()
}

// Map is the provenance as stored in source_metadata.ai and audit metadata.ai.
func (p Provenance) Map() map[string]any {
	acc := make([]map[string]any, 0, len(p.Accountable))
	for _, o := range p.Accountable {
		acc = append(acc, map[string]any{"kind": string(o.Kind), "id": o.ID.String(), "name": o.Name})
	}
	m := map[string]any{
		"analyst_id":   p.AnalystID.String(),
		"analyst_name": p.AnalystName,
		"run_id":       p.RunID.String(),
		"executor":     string(p.Executor),
		"accountable":  acc,
	}
	if p.Provider != "" {
		m["provider"] = p.Provider
	}
	if p.Model != "" {
		m["model"] = p.Model
	}
	if p.PromptTemplateID != "" {
		m["prompt_template"] = p.PromptTemplateID
	}
	if p.PromptTemplateDigest != "" {
		m["prompt_digest"] = p.PromptTemplateDigest
	}
	if p.TriggeredBy != nil {
		m["triggered_by"] = p.TriggeredBy.String()
	}
	return m
}

// StampActor reports whether a row written by actorID in ctx is the
// analyst's, and if so the provenance to stamp.
func StampActor(ctx context.Context, actorID *shared.ID) (Provenance, bool) {
	p, ok := ProvenanceFrom(ctx)
	if !ok || actorID == nil || *actorID != p.AnalystID {
		return Provenance{}, false
	}
	return p, true
}
