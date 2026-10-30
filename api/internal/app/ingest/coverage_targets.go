package ingest

import (
	"context"
	"encoding/json"

	"github.com/openctemio/ctis/outcome"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Per-target coverage (research/263 addendum A). A run of many targets is
// rarely clean on every one of them: one host that stops answering or sits
// behind an edge block made the whole run "partial", and nothing it covered
// could ever close. When the command result accounts for every target
// (target_outcomes), coverage is decided per target instead: a target counts
// only when its outcome is done and no gap, unreached or refused entry names
// its host. Everything else proves nothing and closes nothing.

// coverageCandidateAssetRepo is implemented by the postgres finding
// repository: the assets with open findings of the tool whose last sighting
// came from a command that targeted one of targets.
type coverageCandidateAssetRepo interface {
	CoverageCandidateAssets(ctx context.Context, tenantID shared.ID, tool string, targets []string) ([]shared.ID, error)
}

// resultTargetOutcomes returns the per-target outcomes a command result
// carries, and whether it carries any.
func resultTargetOutcomes(raw json.RawMessage) ([]outcome.Target, bool) {
	if len(raw) == 0 {
		return nil, false
	}
	var r struct {
		Outcomes []outcome.Target `json:"target_outcomes"`
	}
	if json.Unmarshal(raw, &r) != nil || len(r.Outcomes) == 0 {
		return nil, false
	}
	return r.Outcomes, true
}

// resultUncoveredHosts returns the hosts a command result names as not
// covered (coverage gaps, unreached and refused targets), and false when its
// metadata cannot be read or a list was cut short (then no host can be
// trusted as covered).
func resultUncoveredHosts(raw json.RawMessage) (map[string]bool, bool) {
	hosts := map[string]bool{}
	if len(raw) == 0 {
		return hosts, true
	}
	type named struct {
		Host   string `json:"host"`
		Target string `json:"target"`
	}
	var r struct {
		Metadata struct {
			RefusedTargets      []named `json:"refused_targets"`
			RefusedTargetsTotal int     `json:"refused_targets_total"`
			CoverageGaps        []named `json:"coverage_gaps"`
			CoverageGapsTotal   int     `json:"coverage_gaps_total"`
			UnreachedTargets    []named `json:"unreached_targets"`
			UnreachedTotal      int     `json:"unreached_targets_total"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, false
	}
	m := r.Metadata
	// A list shorter than its total names only some of the hosts: the
	// others are unknown, so nothing is trusted.
	if len(m.CoverageGaps) < m.CoverageGapsTotal || len(m.UnreachedTargets) < m.UnreachedTotal ||
		len(m.RefusedTargets) < m.RefusedTargetsTotal {
		return nil, false
	}
	for _, list := range [][]named{m.CoverageGaps, m.UnreachedTargets, m.RefusedTargets} {
		for _, n := range list {
			v := n.Host
			if v == "" {
				v = n.Target
			}
			if h, _ := parseLocator(v); h != "" {
				hosts[h] = true
			}
		}
	}
	return hosts, true
}

// coveredTargets returns the command targets the run really covered. With
// per-target outcomes, a target is covered only when its outcome is done; a
// target without an outcome is not. Without outcomes (an older sensor), every
// target counts: such a run reaches here only when it declared full coverage
// and listed no gap. In both cases a target whose host the result names as
// uncovered is left out.
func coveredTargets(targets []string, raw json.RawMessage) []string {
	uncovered, ok := resultUncoveredHosts(raw)
	if !ok {
		return nil
	}
	outcomes, perTarget := resultTargetOutcomes(raw)
	done := map[string]bool{}
	notDone := map[string]bool{}
	for _, o := range outcomes {
		k := targetKey(o.Target)
		if o.State == outcome.Done && o.Class == "" {
			done[k] = true
		} else {
			notDone[k] = true
		}
	}
	out := make([]string, 0, len(targets))
	for _, t := range targets {
		k := targetKey(t)
		if perTarget && (!done[k] || notDone[k]) {
			continue
		}
		if h, _ := parseLocator(t); h == "" || uncovered[h] {
			continue
		}
		out = append(out, t)
	}
	return out
}

// targetKey is the comparison form of a target string.
func targetKey(t string) string {
	h, p := parseLocator(t)
	return h + p
}

// coveredRunAssets returns the assets a run proves covered: the assets its
// reports touched plus the assets with open findings of the tool last seen by
// a command aimed at one of the covered targets, all filtered to the covered
// targets. The second set is what lets a scan that found nothing on a host
// close what it no longer sees there; it is bounded by the repository query.
func (s *Service) coveredRunAssets(ctx context.Context, tenantID, commandID shared.ID, tool string, result json.RawMessage, touched []shared.ID) []shared.ID {
	b := s.bindingFromCommandID(ctx, tenantID, &commandID)
	if b.Kind != BindingCommand || len(b.Targets) == 0 {
		return nil
	}
	b.Targets = coveredTargets(b.Targets, result)
	if len(b.Targets) == 0 {
		return nil
	}
	candidates := append([]shared.ID(nil), touched...)
	if repo, ok := s.findingRepo.(coverageCandidateAssetRepo); ok {
		more, err := repo.CoverageCandidateAssets(ctx, tenantID, tool, b.Targets)
		if err != nil {
			// Fewer candidates only means fewer closes.
			s.logger.Warn("coverage auto-resolve: candidate assets lookup failed", "command_id", commandID.String(), "error", logger.SanitizeError(err))
		}
		seen := make(map[shared.ID]bool, len(candidates)+len(more))
		for _, id := range candidates {
			seen[id] = true
		}
		for _, id := range more {
			if !seen[id] {
				seen[id] = true
				candidates = append(candidates, id)
			}
		}
	}
	return s.coveredByScope(ctx, tenantID, newAlterScope(b), candidates)
}
