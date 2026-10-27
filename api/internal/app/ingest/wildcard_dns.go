package ingest

// Wildcard-only names (docs/rfcs/RFC-088-scope-aware-target-allocation.md,
// decision A4; docs/architecture/scan-targets.md). The platform sends every
// dnsx job with the wildcard-DNS filter on, and dnsx then reports only the
// names that resolve other than through a wildcard record of their zone.
// When such a job is over (the command completed and every report filed
// under it completed with nothing rejected), the names it was given and did
// not report are marked wildcard-only, and the names it reported are
// cleared. The active-scan gate treats a marked name as passive only until a
// person confirms it, and the scope join never confirms it automatically.
//
// A run with the filter off (a step that sets wildcard_filter: false) proves
// nothing either way and changes no mark. Every lookup and write is
// tenant-scoped; a failure is logged and changes nothing.

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/assetfreshness"
	"github.com/openctemio/openctem/api/pkg/domain/assetresolution"
	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/ingestreport"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
	"github.com/openctemio/openctem/api/pkg/logger"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

// wildcardFilterTool is the resolver whose wildcard-DNS filter the platform
// controls (scan.withWildcardFilter).
const wildcardFilterTool = "dnsx"

// SetWildcardDNS wires the wildcard-only marks. Nil: nothing is marked.
func (s *Service) SetWildcardDNS(st assetfreshness.WildcardDNSStore) { s.wildcardDNS = st }

// SetNameResolution wires what tells a name that does not resolve from one
// that resolves only through a wildcard record, and where the not-resolving
// names are recorded. Without a prober no name is marked wildcard-only.
func (s *Service) SetNameResolution(p NameProber, st assetresolution.Store) {
	s.nameProber, s.resolutionStore = p, st
}

// wildcardFilterOn reports whether a command ran dnsx with the wildcard-DNS
// filter on ("wildcard_filter": true in its config or scanner_config).
func wildcardFilterOn(cmd *command.Command) bool {
	if cmd == nil || !strings.EqualFold(strings.TrimSpace(command.PayloadTool(cmd.Payload)), wildcardFilterTool) {
		return false
	}
	var p struct {
		Config        map[string]any `json:"config"`
		ScannerConfig map[string]any `json:"scanner_config"`
	}
	if json.Unmarshal(cmd.Payload, &p) != nil {
		return false
	}
	for _, cfg := range []map[string]any{p.Config, p.ScannerConfig} {
		if v, ok := cfg["wildcard_filter"]; ok {
			b, isBool := v.(bool)
			return isBool && b
		}
	}
	return false
}

// resolutionOver reports whether a command's run is over and complete: the
// command completed with exit code 0, at least one report was filed, and
// every report completed with no rejected or quarantined asset (a dropped
// report item is not proof that the resolver dropped the name).
func resolutionOver(c *ingestreport.CommandCoverage) bool {
	if c == nil || c.CommandStatus != string(command.CommandStatusCompleted) || len(c.Reports) == 0 {
		return false
	}
	var result struct {
		ExitCode *int `json:"exit_code"`
	}
	if len(c.Result) > 0 && json.Unmarshal(c.Result, &result) == nil && result.ExitCode != nil && *result.ExitCode != 0 {
		return false
	}
	for _, r := range c.Reports {
		if r.State != protov2.StateCompleted {
			return false
		}
		for _, o := range r.SegmentOutcomes {
			if o.RejectedAssets > 0 || o.QuarantinedAssets > 0 || len(o.Errors) > 0 || o.ErrorsTruncated {
				return false
			}
		}
	}
	return true
}

// resolverInputNames are the host names among a command's targets
// (lower-case, no trailing dot, de-duplicated).
func resolverInputNames(cmd *command.Command) []string {
	targets := CommandTargets(cmd)
	seen := make(map[string]bool, len(targets))
	out := make([]string, 0, len(targets))
	for _, t := range targets {
		n := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(t), "."))
		if n == "" || seen[n] || stage.ClassifyTarget(n) != stage.KindName {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	return out
}

// splitWildcardOnly divides the input assets into the ones the run reported
// (clear) and the ones it did not (mark). A registrable domain is never
// marked, and any mark it has is cleared: a wildcard record never answers
// for the name it sits under, so an apex the resolver left out has no
// address, or shares its address with its own wildcard (which the
// resolver's filter cannot tell apart); neither makes it wildcard-only.
func splitWildcardOnly(inputs map[string]*asset.Asset, c *ingestreport.CommandCoverage) (mark, clear []shared.ID) {
	reported := map[shared.ID]bool{}
	for _, r := range c.Reports {
		for _, id := range r.TouchedAssetIDs {
			reported[id] = true
		}
	}
	seen := map[shared.ID]bool{}
	for _, a := range inputs {
		if a == nil || seen[a.ID()] {
			continue
		}
		seen[a.ID()] = true
		if reported[a.ID()] || asset.IsRegistrableDomain(a.Name()) {
			clear = append(clear, a.ID())
		} else {
			mark = append(mark, a.ID())
		}
	}
	return mark, clear
}

// evaluateWildcardDNS records the outcome of a finished filtered resolution.
// It runs from both ends of the command (completion, last report), like the
// coverage evaluation; a second call writes the same marks again.
func (s *Service) evaluateWildcardDNS(ctx context.Context, tenantID, commandID shared.ID, cov *ingestreport.CommandCoverage) {
	if s.wildcardDNS == nil || s.commands == nil || s.assetRepo == nil || !resolutionOver(cov) {
		return
	}
	cmd, err := s.commands.GetByTenantAndID(ctx, tenantID, commandID)
	if err != nil || cmd == nil || !wildcardFilterOn(cmd) {
		return
	}
	names := resolverInputNames(cmd)
	if len(names) == 0 {
		return
	}
	inputs, err := s.assetRepo.GetByNames(ctx, tenantID, names)
	if err != nil {
		s.logger.Warn("wildcard-DNS marks: could not load the resolved names", "command_id", commandID.String(), "error", logger.SanitizeError(err))
		return
	}
	mark, clear := splitWildcardOnly(inputs, cov)
	at := time.Now()
	if cmd.CompletedAt != nil {
		at = *cmd.CompletedAt
	}
	// A name the resolver left out is not wildcard-only by that alone: it
	// may not resolve at all. Ask DNS; mark only what resolves through a
	// probed wildcard record.
	mark, clear = s.classifyUnreported(ctx, tenantID, commandID, inputs, mark, clear, at)
	if err := s.wildcardDNS.ClearWildcardOnly(ctx, tenantID, clear); err != nil {
		s.logger.Warn("wildcard-DNS marks: clear failed", "command_id", commandID.String(), "error", logger.SanitizeError(err))
	}
	if err := s.wildcardDNS.MarkWildcardOnly(ctx, tenantID, mark, commandID, at); err != nil {
		s.logger.Warn("wildcard-DNS marks: mark failed", "command_id", commandID.String(), "error", logger.SanitizeError(err))
		return
	}
	if len(mark) > 0 {
		s.logger.Info("names resolve only through a wildcard record; passive only", "tenant_id", tenantID.String(), "command_id", commandID.String(), "count", len(mark))
	}
}

// classifyUnreported sorts the names the resolver did not report: a name
// DNS has no answer for is recorded as failing to resolve (not_resolving
// after consecutive failures) and is not marked; a name that resolves
// through a wildcard record of a parent zone stays marked; a name that
// resolves by itself has any mark cleared. Without a prober, or when the
// probe is unsure, nothing is marked (a mark needs proof). It returns the
// final mark and clear lists.
func (s *Service) classifyUnreported(ctx context.Context, tenantID, commandID shared.ID, inputs map[string]*asset.Asset, mark, clear []shared.ID, at time.Time) (marks, clears []shared.ID) {
	if len(mark) == 0 {
		return nil, clear
	}
	if s.nameProber == nil {
		return nil, clear
	}
	byID := make(map[shared.ID]string, len(inputs))
	for n, a := range inputs {
		if a != nil {
			byID[a.ID()] = n
		}
	}
	names := make([]string, 0, len(mark))
	for _, id := range mark {
		if n, ok := byID[id]; ok {
			names = append(names, n)
		}
	}
	classes := probeNames(ctx, s.nameProber, names)
	var failed, resolved []shared.ID
	for _, id := range mark {
		switch classes[byID[id]] {
		case NameWildcardOnly:
			marks = append(marks, id)
		case NameNoAnswer:
			failed = append(failed, id)
			clear = append(clear, id)
		case NameResolves:
			resolved = append(resolved, id)
			clear = append(clear, id)
		}
	}
	if s.resolutionStore != nil {
		if err := s.resolutionStore.RecordFailed(ctx, tenantID, failed, at, assetresolution.SourceResolveStage); err != nil {
			s.logger.Warn("resolution states: failed names not recorded", "command_id", commandID.String(), "error", logger.SanitizeError(err))
		}
		if err := s.resolutionStore.RecordResolved(ctx, tenantID, resolved, at); err != nil {
			s.logger.Warn("resolution states: resolved names not recorded", "command_id", commandID.String(), "error", logger.SanitizeError(err))
		}
	}
	if len(failed) > 0 {
		s.logger.Info("names the resolver left out do not resolve", "tenant_id", tenantID.String(), "command_id", commandID.String(), "count", len(failed))
	}
	return marks, clear
}
