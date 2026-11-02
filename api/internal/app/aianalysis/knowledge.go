package aianalysis

import (
	"context"
	"strconv"
	"strings"

	"github.com/openctemio/openctem/api/internal/app/aibundle"
	aidom "github.com/openctemio/openctem/api/pkg/domain/aianalysis"
	kdom "github.com/openctemio/openctem/api/pkg/domain/aiknowledge"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Knowledge retrieval for single-shot runs (docs/architecture/ai-knowledge.md):
// before the model call the platform retrieves, as the AI agent, the
// organization's approved knowledge that matches the finding. The query is
// built from the finding, never from model output; the tenant and the AI
// agent are the run's. Excerpts are masked with the run's key, fenced and
// labeled kb:<n>; the run records what it saw and what the output cited.
// Knowledge may explain a suggestion but never justify a change on its own.

// KnowledgeSource retrieves knowledge as an AI agent and records a run's
// retrieval.
type KnowledgeSource interface {
	Retrieve(ctx context.Context, tenantID shared.ID, aiAgent *aidom.AIAgent, query string, limit int) ([]kdom.Hit, error)
	Record(ctx context.Context, tenantID, runID shared.ID, mode kdom.RetrievalMode, ex []kdom.RunExcerpt) error
}

// SetKnowledge wires knowledge retrieval (nil: runs retrieve nothing).
func (e *BuiltinExecutor) SetKnowledge(k KnowledgeSource) { e.knowledge = k }

// runExcerpts is how many excerpts a single-shot run receives.
const runExcerpts = 5

// ReviewKnowledgeOnly: a suggestion whose only resolved evidence is
// organization knowledge; it may not change the finding.
const ReviewKnowledgeOnly = "knowledge_only_evidence"

// retrieval is what a run retrieved, by ordinal.
type retrieval struct {
	mode kdom.RetrievalMode
	hits map[int]kdom.Hit
}

// knowledgeQuery is the search text for a finding: its title, identifiers,
// tool and rule, and the asset's name, type and environment.
func knowledgeQuery(f *vulnerability.Finding, a *aibundle.Asset) string {
	parts := []string{f.Title(), f.CVEID(), strings.Join(f.CWEIDs(), " "), f.ToolName(), f.RuleID(), f.RuleName()}
	if a != nil {
		parts = append(parts, a.Name, a.Type, a.Environment)
	}
	return strings.Join(parts, " ")
}

// retrieve returns the excerpts for the bundle. A retrieval error never
// fails the run: it runs without knowledge (mode none).
func (e *BuiltinExecutor) retrieve(ctx context.Context, p *Principal, run *aidom.Run, f *vulnerability.Finding, in *aibundle.Input) *retrieval {
	r := &retrieval{mode: kdom.ModeNone, hits: map[int]kdom.Hit{}}
	if e.knowledge == nil {
		return r
	}
	hits, err := e.knowledge.Retrieve(ctx, run.TenantID, p.AIAgent, knowledgeQuery(f, in.Asset), runExcerpts)
	if err != nil {
		e.logger.Warn("AI knowledge retrieval failed", "run_id", run.ID.String(), "error", logger.SanitizeError(err))
		return r
	}
	r.mode = kdom.ModeLexical
	for i, h := range hits {
		ord := i + 1
		r.hits[ord] = h
		title := h.DocumentTitle
		if h.ChunkTitle != "" {
			title += " > " + h.ChunkTitle
		}
		in.Knowledge = append(in.Knowledge, aibundle.Excerpt{Ordinal: ord, Title: title, Body: h.Body,
			Restricted: h.Class == kdom.ClassRestricted, Updated: h.UpdatedAt.UTC().Format("2006-01-02")})
	}
	return r
}

// record stores the excerpts the bundle really carried, with the ones the
// output cited.
func (e *BuiltinExecutor) record(ctx context.Context, run *aidom.Run, r *retrieval, bundle *aibundle.Bundle, cited map[string]bool) {
	if e.knowledge == nil || r == nil {
		return
	}
	ex := make([]kdom.RunExcerpt, 0, len(bundle.Knowledge))
	for _, k := range bundle.Knowledge {
		h, ok := r.hits[k.Ordinal]
		if !ok {
			continue
		}
		ex = append(ex, kdom.RunExcerpt{Ordinal: k.Ordinal, ChunkID: h.ChunkID, DocumentID: h.DocumentID, SourceID: h.SourceID,
			VersionDigest: h.VersionDigest, Score: h.Score, Cited: cited["kb:"+strconv.Itoa(k.Ordinal)]})
	}
	if err := e.knowledge.Record(ctx, run.TenantID, run.ID, r.mode, ex); err != nil {
		e.logger.Warn("failed to record AI knowledge retrieval", "run_id", run.ID.String(), "error", logger.SanitizeError(err))
	}
}

// knowledgeOnly reports evidence that resolves only to knowledge excerpts.
func knowledgeOnly(ev []aidom.Evidence) bool {
	if len(ev) == 0 {
		return false
	}
	for _, x := range ev {
		if !strings.HasPrefix(x.Ref, "kb:") {
			return false
		}
	}
	return true
}

// sourcesLine names the knowledge a suggestion cited, for the AI agent's
// comment. Organization-wide documents are named; a team document is not
// (a reader of the finding may not be in that team).
func sourcesLine(ev []aidom.Evidence, r *retrieval) string {
	if r == nil {
		return ""
	}
	names := make([]string, 0, len(ev))
	seen := map[string]bool{}
	for _, x := range ev {
		if !strings.HasPrefix(x.Ref, "kb:") || seen[x.Ref] {
			continue
		}
		seen[x.Ref] = true
		ord, err := strconv.Atoi(strings.TrimPrefix(x.Ref, "kb:"))
		if err != nil {
			continue
		}
		h, ok := r.hits[ord]
		if !ok {
			continue
		}
		name := "team knowledge document"
		if h.Visibility == kdom.VisibilityOrganization {
			name = h.DocumentTitle
		}
		names = append(names, x.Ref+" "+name)
	}
	if len(names) == 0 {
		return ""
	}
	return "\n\nSources: " + strings.Join(names, "; ")
}
