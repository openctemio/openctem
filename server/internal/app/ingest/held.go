package ingest

// Held findings of a throttled run (docs/architecture/held-findings.md).
//
// A command whose result names a host as throttled, blocked, behind an edge
// protection, at the rate floor or answering every path alike (coverage
// gaps) holds the findings its reports sighted first on that host: what the
// host answered may have been the limit, not the application, so the match
// is kept with the reason target_throttled but held out of risk scores, SLA
// escalation, notifications and tickets until it is checked.
//
// It runs from both ends, like coverage: when the report is ingested and
// the command's result is already in (the findings are held before their
// created events, so nothing is announced), and when the command's coverage
// is evaluated (the reports that arrived before the result). The repository
// changes only unchecked rows and returns what it changed, so each finding
// is held, and counted in the one notice about held critical findings, once.

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/openctemio/openctem/server/internal/app/outbox"
	"github.com/openctemio/openctem/server/pkg/domain/asset"
	"github.com/openctemio/openctem/server/pkg/domain/integration"
	"github.com/openctemio/openctem/server/pkg/domain/scanrun"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// gapHolder is implemented by the postgres finding repository.
type gapHolder interface {
	HoldGapFindings(ctx context.Context, tenantID, commandID shared.ID, reportID string, hosts []string, reasons []string) ([]vulnerability.HeldFinding, error)
}

// heldNoticeEnqueuer is the outbox (integrations: Slack, email, webhooks).
type heldNoticeEnqueuer interface {
	Enqueue(ctx context.Context, params outbox.EnqueueParams) error
}

// SetHeldNoticeOutbox wires the outbox that carries the notice about held
// critical findings.
func (s *Service) SetHeldNoticeOutbox(o heldNoticeEnqueuer) { s.heldOutbox = o }

// keyCommandID is the command field of the hold's log lines and notice.
const keyCommandID = "command_id"

// runHoldReasons are the hold reasons of a throttled run.
var runHoldReasons = []string{vulnerability.HoldTargetThrottled}

// resultHoldHosts returns the hosts (asset.HostOf form) a command result
// names in a coverage gap that holds findings (vulnerability.HoldGapReasons).
func resultHoldHosts(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var r struct {
		Metadata struct {
			CoverageGaps      json.RawMessage `json:"coverage_gaps"`
			CoverageGapsTotal int             `json:"coverage_gaps_total"`
		} `json:"metadata"`
	}
	if json.Unmarshal(raw, &r) != nil || len(r.Metadata.CoverageGaps) == 0 {
		return nil
	}
	gaps, _ := scanrun.ParseCoverageGaps(r.Metadata.CoverageGaps, r.Metadata.CoverageGapsTotal)
	var hosts []string
	for _, g := range gaps {
		if !slices.Contains(vulnerability.HoldGapReasons, g.Reason) {
			continue
		}
		if h := asset.HostOf(g.Host); h != "" && !slices.Contains(hosts, h) {
			hosts = append(hosts, h)
		}
	}
	return hosts
}

// holdRunFindings holds the findings of the command's reports (one report
// when reportID is set) on the hosts its result names as throttled, and
// sends the notice about held critical findings. It returns the findings it
// held.
func (s *Service) holdRunFindings(ctx context.Context, tenantID, commandID shared.ID, result json.RawMessage, reportID string) []vulnerability.HeldFinding {
	hosts := resultHoldHosts(result)
	repo, ok := s.findingRepo.(gapHolder)
	if len(hosts) == 0 || !ok {
		return nil
	}
	held, err := repo.HoldGapFindings(ctx, tenantID, commandID, reportID, hosts, runHoldReasons)
	if err != nil {
		s.logger.Warn("held findings: could not hold the findings of a throttled run",
			keyCommandID, commandID.String(), "error", logger.SanitizeError(err))
		return nil
	}
	if len(held) == 0 {
		return nil
	}
	s.logger.Info("held findings of a throttled run", keyCommandID, commandID.String(),
		"held_findings", len(held), "hosts", len(hosts))
	s.noticeHeldCritical(ctx, tenantID, commandID, held)
	return held
}

// noticeHeldCritical sends one notice for the critical findings among held:
// they send no new-finding message until they are checked.
func (s *Service) noticeHeldCritical(ctx context.Context, tenantID, commandID shared.ID, held []vulnerability.HeldFinding) {
	n := 0
	for _, h := range held {
		if h.Severity == vulnerability.SeverityCritical.String() {
			n++
		}
	}
	if n == 0 || s.heldOutbox == nil {
		return
	}
	title := "Critical finding held: the target throttled the scan"
	if n > 1 {
		title = fmt.Sprintf("%d critical findings held: the target throttled the scan", n)
	}
	if err := s.heldOutbox.Enqueue(ctx, outbox.EnqueueParams{
		TenantID: tenantID, EventType: string(integration.EventTypeFindingHeldCritical), AggregateType: "scan",
		Title:    title,
		Body:     "The match came while the target was throttling or blocking the scan, so it may be the target's limit page. It is kept, held out of scores, SLA and tickets until it is checked.",
		Severity: vulnerability.SeverityCritical.String(), URL: "/findings?verification_state=held",
		Metadata: map[string]any{"held_critical": n, "held_findings": len(held), keyCommandID: commandID.String(), "reason": vulnerability.HoldTargetThrottled},
	}); err != nil {
		s.logger.Warn("held findings: notice not enqueued", "tenant_id", tenantID.String(), "error", logger.SanitizeError(err))
	}
}

// runHoldKey carries, through the ingest of one command's report, the hold
// of that run's findings (applyRunHold).
type runHoldKey struct{}

// runHold holds the just-created findings of the report in progress.
type runHold func(ctx context.Context, tenantID shared.ID) []vulnerability.HeldFinding

// withRunHold attaches the hold of a command's report: the command's result
// is read only when findings were created, and holds nothing until the
// result is in.
func (s *Service) withRunHold(ctx context.Context, commandID shared.ID) context.Context {
	if s.commands == nil {
		return ctx
	}
	reportID := reportIDOf(ctx)
	return context.WithValue(ctx, runHoldKey{}, runHold(func(ctx context.Context, tenantID shared.ID) []vulnerability.HeldFinding {
		cmd, err := s.commands.GetByTenantAndID(ctx, tenantID, commandID)
		if err != nil || cmd == nil {
			return nil
		}
		return s.holdRunFindings(ctx, tenantID, commandID, cmd.Result, reportID)
	}))
}

// applyRunHold holds the created findings of a throttled run (when the
// command's result is already in) and marks them held, so the created
// events below skip them.
func applyRunHold(ctx context.Context, tenantID shared.ID, created []*vulnerability.Finding) {
	hold, ok := ctx.Value(runHoldKey{}).(runHold)
	if !ok || len(created) == 0 {
		return
	}
	held := hold(ctx, tenantID)
	if len(held) == 0 {
		return
	}
	ids := make(map[shared.ID]bool, len(held))
	for _, h := range held {
		ids[h.ID] = true
	}
	for _, f := range created {
		if ids[f.ID()] {
			f.Hold(runHoldReasons...)
		}
	}
}

// withoutHeld drops held findings: they send no created event (no
// new-finding notification, no automation rule, no ticket) until checked.
func withoutHeld(findings []*vulnerability.Finding) []*vulnerability.Finding {
	out := make([]*vulnerability.Finding, 0, len(findings))
	for _, f := range findings {
		if !f.IsHeld() {
			out = append(out, f)
		}
	}
	return out
}
