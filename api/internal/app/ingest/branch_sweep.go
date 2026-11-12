package ingest

// Per-branch occurrence sweep: a full scan of a branch marks the occurrences
// it no longer reports there auto_fixed. "No longer reported" means
// something only when the scan ran to the end, so the sweep never runs from
// a run that exited non-zero, was killed, or that the sensor says it
// stopped: older sensors deliver such a run as "completed", coverage
// "full", every target done (research/467 F6). A run bound to a command is
// swept once both halves are known (the command completed and every report
// of it completed), from EvaluateCommandCoverage.

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/openctemio/ctis/v2"

	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/ingestreport"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

// Branch sweep decisions (log values).
const (
	branchSweepNotScan        = "not_scan_command"
	branchSweepNotCompleted   = "command_not_completed"
	branchSweepStopped        = "run_stopped"
	branchSweepTruncated      = "truncated_result"
	branchSweepReportsPending = "reports_pending"
	branchSweepReportFailed   = "report_failed"
	branchSweepEligible       = "eligible"
)

// reportCoverageFull reports whether a report's metadata claims a full scan
// that finished every target it lists: coverage_type "full" and, when the
// report lists its targets, each one done. A full report that lists a
// failed, skipped or unfinished target did not look everywhere.
func reportCoverageFull(md ctis.ReportMetadata) bool {
	return md.CoverageType == ctis.CoverageFull && reportTargetsDone(md)
}

// reportTargetsDone reports whether every target a report lists is done (a
// report that lists none passes: the command result decides).
func reportTargetsDone(md ctis.ReportMetadata) bool {
	for _, t := range md.Targets {
		if t.State != ctis.TargetDone {
			return false
		}
	}
	return true
}

// commandRunClean reports whether a command's run ended by itself: the
// command is a completed scan whose result is neither stopped nor
// truncated. Fails closed: no command reader, a lookup error or another
// tenant's command is not clean.
func (s *Service) commandRunClean(ctx context.Context, tenantID shared.ID, commandID *shared.ID) bool {
	if s.commands == nil || commandID == nil {
		return false
	}
	cmd, err := s.commands.GetByTenantAndID(ctx, tenantID, *commandID)
	if err != nil || cmd == nil || cmd.TenantID != tenantID {
		return false
	}
	return runCleanFor(string(cmd.Type), string(cmd.Status), cmd.Result) == branchSweepEligible
}

// v1RunMaySweepBranch is the run half of the v1 per-branch sweep (Ingest):
// the report lists no unfinished target and, when it is bound to a command,
// that command already completed by itself. A v1 report usually arrives
// before its command completes: it then sweeps nothing, which fails closed.
func (s *Service) v1RunMaySweepBranch(ctx context.Context, tenantID shared.ID, binding Binding, md ctis.ReportMetadata) bool {
	if !reportTargetsDone(md) {
		return false
	}
	return binding.Kind != BindingCommand || s.commandRunClean(ctx, tenantID, binding.CommandID)
}

// commitSweepsBranch reports whether CommitV2Report sweeps the branch a
// report scanned: only an unbound report (it carries no exit code, only its
// own metadata decides) that claims a full scan of a named branch with every
// listed target done. A bound report is swept with its run
// (sweepRunBranchOccurrences).
func commitSweepsBranch(prov Provenance, md ctis.ReportMetadata) bool {
	return prov.CommandID == nil && reportCoverageFull(md) && md.Branch != nil && md.Branch.Name != ""
}

// runCleanFor is the command half of the branch sweep decision.
func runCleanFor(cmdType, status string, result json.RawMessage) string {
	if !isCoverageCommandType(cmdType) {
		return branchSweepNotScan
	}
	if status != string(command.CommandStatusCompleted) {
		return branchSweepNotCompleted
	}
	if stopped, _ := command.RunStopped(result); stopped {
		return branchSweepStopped
	}
	if command.ResultTruncated(result) {
		return branchSweepTruncated
	}
	return branchSweepEligible
}

// branchSweepReport is one report of a run the sweep may act on.
type branchSweepReport struct {
	reportID string
	tool     *ctis.Tool
	branch   string
	touched  []shared.ID
}

// decideRunBranchSweep says whether a command's run may sweep branch
// occurrences, and for which reports. The command must be a completed scan
// that ended by itself; every report must be completed (a failed or expired
// report, or one still in flight, may hold occurrences that were never
// recorded). A report sweeps only when it claims a full scan of a named
// branch that finished every listed target, with a verified integrity and
// nothing rejected, quarantined or in error. Two reports of the run on the
// same branch and tool sweep nothing: one scan id cannot stand for both.
func decideRunBranchSweep(c *ingestreport.CommandCoverage) (string, []branchSweepReport) {
	if c == nil {
		return branchSweepNotScan, nil
	}
	if why := runCleanFor(c.CommandType, c.CommandStatus, c.Result); why != branchSweepEligible {
		return why, nil
	}
	for _, r := range c.Reports {
		switch r.State {
		case protov2.StateCompleted:
		case protov2.StateFailed, protov2.StateExpired:
			return branchSweepReportFailed, nil
		default:
			return branchSweepReportsPending, nil
		}
	}
	// Every report of the run that names a tool and a branch counts toward
	// the "one report per branch and tool" rule, eligible or not: the sweep
	// keys on the report id, so a full report would mark the occurrences a
	// sibling report of the same run recorded as gone.
	seen := map[string]int{}
	type parsed struct {
		r      ingestreport.CoverageReport
		header V2Header
	}
	named := make([]parsed, 0, len(c.Reports))
	for _, r := range c.Reports {
		var header V2Header
		if len(r.Header) == 0 || json.Unmarshal(r.Header, &header) != nil {
			continue
		}
		if header.Tool == nil || header.Metadata.Branch == nil || header.Metadata.Branch.Name == "" {
			continue
		}
		seen[branchSweepKey(header.Tool.Name, header.Metadata.Branch.Name)]++
		named = append(named, parsed{r: r, header: header})
	}
	kept := make([]branchSweepReport, 0, len(named))
	for _, p := range named {
		md := p.header.Metadata
		if seen[branchSweepKey(p.header.Tool.Name, md.Branch.Name)] != 1 || !reportCoverageFull(md) {
			continue
		}
		if p.r.Integrity != protov2.IntegritySingle && p.r.Integrity != protov2.IntegrityManifest {
			continue
		}
		if segmentsDroppedItems(p.r.SegmentOutcomes) {
			continue
		}
		kept = append(kept, branchSweepReport{reportID: p.r.ReportID, tool: p.header.Tool, branch: md.Branch.Name, touched: p.r.TouchedAssetIDs})
	}
	return branchSweepEligible, kept
}

// branchSweepKey is the tool and branch a report sweeps.
func branchSweepKey(tool, branch string) string {
	return strings.ToLower(strings.TrimSpace(tool)) + "\x00" + branch
}

// segmentsDroppedItems reports whether any segment of a report rejected or
// quarantined an item or recorded an error (a failed branch occurrence
// write is one).
func segmentsDroppedItems(outcomes map[string]ingestreport.SegmentOutcome) bool {
	for _, o := range outcomes {
		if o.RejectedFindings > 0 || o.QuarantinedFindings > 0 || o.RejectedAssets > 0 ||
			o.QuarantinedAssets > 0 || len(o.Errors) > 0 || o.ErrorsTruncated {
			return true
		}
	}
	return false
}

// sweepRunBranchOccurrences runs the per-branch occurrence sweep of a
// command's run once the run is known to be clean (decideRunBranchSweep),
// on the assets the command covers, for tools its sensors declare. Safe to
// run repeatedly: an occurrence the scan saw carries its scan id and is
// never swept by it.
func (s *Service) sweepRunBranchOccurrences(ctx context.Context, tenantID, commandID shared.ID, cov *ingestreport.CommandCoverage) {
	if s.branchRepo == nil || s.findingRepo == nil {
		return
	}
	why, reports := decideRunBranchSweep(cov)
	if why != branchSweepEligible {
		s.logger.Debug("branch occurrence sweep: not eligible", "command_id", commandID.String(), "reason", why)
		return
	}
	for _, r := range reports {
		if !s.sensorsDeclareTool(ctx, cov, r.tool.Name) {
			continue
		}
		for _, assetID := range s.coveredByCommand(ctx, tenantID, &commandID, r.touched) {
			br, err := s.branchRepo.GetByName(ctx, assetID, r.branch)
			if err != nil || br == nil {
				continue
			}
			n, err := s.findingRepo.AutoResolveStaleBranchOccurrences(ctx, tenantID, br.ID(), r.tool.Name, r.reportID)
			if err != nil {
				s.logger.Warn("branch occurrence sweep failed", "command_id", commandID.String(), "asset_id", assetID.String(), "error", err)
			} else if n > 0 {
				s.logger.Info("branch occurrence sweep: auto-fixed occurrences", "command_id", commandID.String(), "asset_id", assetID.String(), "count", n)
			}
		}
	}
}
