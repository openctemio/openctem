package pipeline

// Incremental web scanning (docs/rfcs/RFC-056-web-attack-surface.md §4.8):
// a template step chained after a crawl may take, instead of each origin,
// only the endpoints the crawl found new (or new and changed) in this run.
// The step setting `endpoint_selector` is "all" (the default: the origins),
// "new" or "changed". The selected endpoint URLs pass the same per-hop gate
// as any derived target (scope exclusions with their paths, ownership, act
// scope, zone); endpoints under a path exclusion are never selected.

import (
	"context"
	"fmt"
	"strings"
	"time"

	pipelinedom "github.com/openctemio/openctem/api/pkg/domain/pipeline"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
)

// EndpointSelector returns, per origin asset, the URLs of its in-scope
// active endpoints first seen (mode "new") or first seen or changed (mode
// "changed") at or after since (*postgres.WebEndpointRepository).
type EndpointSelector interface {
	SelectEndpointURLs(ctx context.Context, tenantID shared.ID, originAssetIDs []shared.ID, mode string, since time.Time, limit int) (map[shared.ID][]string, error)
}

// WithEndpointSelector wires the incremental web selector. Without it the
// setting is refused (a step must not silently scan everything it was told
// to narrow).
func WithEndpointSelector(sel EndpointSelector) Option {
	return func(s *Service) { s.endpoints = sel }
}

// webConsumers are the stages that can take endpoint URLs instead of
// origins.
var webConsumers = map[stage.Key]bool{stage.VulnTemplates: true}

// expandEndpoints replaces each origin candidate with the URLs of its
// selected endpoints. An origin with none is skipped as unchanged.
func (s *Service) expandEndpoints(ctx context.Context, run *pipelinedom.Run, st stage.Stage, step *pipelinedom.Step,
	cands candidates, skipped map[string]int,
) (candidates, error) {
	mode := pipelinedom.EndpointSelectorOf(step.Config)
	if mode == pipelinedom.EndpointSelectorAll || !webConsumers[st.Key] || len(cands.gate) == 0 {
		return cands, nil
	}
	if s.endpoints == nil {
		return cands, fmt.Errorf("incremental web scanning is not configured; step %s not planned", step.StepKey)
	}
	since := run.CreatedAt
	if run.StartedAt != nil {
		since = *run.StartedAt
	}
	ids := make([]shared.ID, 0, len(cands.gate))
	for _, c := range cands.gate {
		ids = append(ids, c.assetID)
	}
	budget := min(st.MaxFanout, stage.RunFanoutCap)
	urls, err := s.endpoints.SelectEndpointURLs(ctx, run.TenantID, ids, mode, since, budget)
	if err != nil {
		return cands, fmt.Errorf("select endpoints: %w", err)
	}
	out := candidates{dropped: cands.dropped}
	seen := map[string]bool{}
	for _, c := range cands.gate {
		list := urls[c.assetID]
		if len(list) == 0 {
			c.reason = pipelinedom.ReasonUnchanged
			skipped[c.reason]++
			out.dropped = append(out.dropped, c)
			continue
		}
		for _, u := range list {
			key, ok := hopTargetKey(u)
			if !ok || seen[key] || !strings.HasPrefix(strings.ToLower(key), "http") {
				continue
			}
			if len(out.gate) >= budget {
				skipped[pipelinedom.ReasonOverCap]++
				continue
			}
			seen[key] = true
			e := c
			e.key = key
			out.gate = append(out.gate, e)
		}
	}
	return out, nil
}
