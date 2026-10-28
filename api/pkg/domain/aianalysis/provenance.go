package aianalysis

import (
	"context"
	"fmt"

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

// ErrAssistReadOnly: read-only AI assistance tried to change state. AI
// assistance (explain, summarize, translate, questions) runs under the
// viewer's own permissions, persists no decision and writes nothing; every
// change to state goes through an AI analyst.
var ErrAssistReadOnly = fmt.Errorf("%w: AI assistance is read-only; changes go through an AI analyst", shared.ErrForbidden)

type assistKey struct{}

// WithAssist marks ctx as read-only AI assistance for the viewer.
func WithAssist(ctx context.Context) context.Context {
	return context.WithValue(ctx, assistKey{}, true)
}

// IsAssist reports whether ctx is read-only AI assistance.
func IsAssist(ctx context.Context) bool {
	v, _ := ctx.Value(assistKey{}).(bool)
	return v
}

// RefuseAssist returns ErrAssistReadOnly in an assistance context; the
// finding write paths call it first.
func RefuseAssist(ctx context.Context) error {
	if IsAssist(ctx) {
		return ErrAssistReadOnly
	}
	return nil
}
