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
// is held once, and a command sends at most one notice about held critical
// findings.
//
// A later run releases the hold: when a completed command is evaluated, the
// held findings its reports sighted again (every sighting path writes the
// report into scan_id) on a host its result does NOT name as throttled go
// back to unchecked, and their created side effects (notifications,
// automations, tickets) run then, once.

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/google/uuid"

	"github.com/openctemio/openctem/server/internal/app/outbox"
	"github.com/openctemio/openctem/server/pkg/domain/asset"
	"github.com/openctemio/openctem/server/pkg/domain/command"
	"github.com/openctemio/openctem/server/pkg/domain/ingestreport"
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

// runReleaser is implemented by the postgres finding repository.
type runReleaser interface {
	ReleaseRunFindings(ctx context.Context, tenantID, commandID shared.ID, gapHosts []string, reasons []string) ([]shared.ID, error)
}

// heldNoticeOnce is implemented by the postgres finding repository: it runs
// send in a transaction that holds the command's notice lock, unless the
// command already has the notice, and reports whether send ran.
type heldNoticeOnce interface {
	OnceHeldNotice(ctx context.Context, tenantID, commandID shared.ID, eventType string, send func(tx *sql.Tx) error) (bool, error)
}

// heldNoticeEnqueuer is the outbox (integrations: Slack, email, webhooks).
type heldNoticeEnqueuer interface {
	EnqueueInTx(ctx context.Context, tx *sql.Tx, params outbox.EnqueueParams) error
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
	hosts, _ := resultGapHosts(raw)
	return hosts
}

// resultGapHosts is resultHoldHosts, and whether the list is the whole
// story: a result that is missing or unreadable, or whose gap list was cut
// (coverage_gaps_total above what it lists), may leave a throttled host out,
// so it releases nothing. A readable result without gaps is complete.
func resultGapHosts(raw json.RawMessage) ([]string, bool) {
	if len(raw) == 0 {
		return nil, false
	}
	var r struct {
		Metadata struct {
			CoverageGaps      json.RawMessage `json:"coverage_gaps"`
			CoverageGapsTotal int             `json:"coverage_gaps_total"`
		} `json:"metadata"`
	}
	if json.Unmarshal(raw, &r) != nil {
		return nil, false
	}
	if len(r.Metadata.CoverageGaps) == 0 {
		return nil, r.Metadata.CoverageGapsTotal == 0
	}
	var listed []json.RawMessage
	if json.Unmarshal(r.Metadata.CoverageGaps, &listed) != nil {
		return nil, false
	}
	gaps, total := scanrun.ParseCoverageGaps(r.Metadata.CoverageGaps, r.Metadata.CoverageGapsTotal)
	complete := len(gaps) == len(listed) && total <= len(listed)
	var hosts []string
	for _, g := range gaps {
		if !slices.Contains(vulnerability.HoldGapReasons, g.Reason) {
			continue
		}
		if h := asset.HostOf(g.Host); h != "" && !slices.Contains(hosts, h) {
			hosts = append(hosts, h)
		}
	}
	return hosts, complete
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

// noticeHeldCritical sends the notice for the critical findings among held:
// they send no new-finding message until they are checked. A command sends
// at most one (its reports are held one by one, and its evaluation runs from
// both ends): the notice is keyed on the command (aggregate scan, id the
// command), and written under the command's notice lock only when the
// command has none yet.
func (s *Service) noticeHeldCritical(ctx context.Context, tenantID, commandID shared.ID, held []vulnerability.HeldFinding) {
	n := 0
	for _, h := range held {
		if h.Severity == vulnerability.SeverityCritical.String() {
			n++
		}
	}
	once, ok := s.findingRepo.(heldNoticeOnce)
	if n == 0 || s.heldOutbox == nil || !ok {
		return
	}
	title := "Critical finding held: the target throttled the scan"
	if n > 1 {
		title = fmt.Sprintf("%d critical findings held: the target throttled the scan", n)
	}
	aggregate, perr := uuid.Parse(commandID.String())
	if perr != nil {
		return
	}
	eventType := string(integration.EventTypeFindingHeldCritical)
	_, err := once.OnceHeldNotice(ctx, tenantID, commandID, eventType, func(tx *sql.Tx) error {
		return s.heldOutbox.EnqueueInTx(ctx, tx, outbox.EnqueueParams{
			TenantID: tenantID, EventType: eventType, AggregateType: heldNoticeAggregate, AggregateID: &aggregate,
			Title:    title,
			Body:     "The match came while the target was throttling or blocking the scan, so it may be the target's limit page. It is kept, held out of scores, SLA and tickets until it is checked.",
			Severity: vulnerability.SeverityCritical.String(), URL: "/findings?verification_state=held",
			Metadata: map[string]any{"held_critical": n, "held_findings": len(held), keyCommandID: commandID.String(), "reason": vulnerability.HoldTargetThrottled},
		})
	})
	if err != nil {
		s.logger.Warn("held findings: notice not enqueued", "tenant_id", tenantID.String(), "error", logger.SanitizeError(err))
	}
}

// heldNoticeAggregate is the aggregate type of the held-critical notice (its
// id is the command's).
const heldNoticeAggregate = "scan"

// releaseRunFindings releases the held findings a completed command's
// reports sighted again on hosts its result does not name as throttled
// (every host when it names none), and runs their created side effects
// once. A command that did not complete, stopped early, or whose result
// does not list every gap releases nothing.
func (s *Service) releaseRunFindings(ctx context.Context, tenantID, commandID shared.ID, cov *ingestreport.CommandCoverage) []shared.ID {
	repo, ok := s.findingRepo.(runReleaser)
	if !ok || cov == nil || cov.CommandStatus != string(command.CommandStatusCompleted) {
		return nil
	}
	if stopped, _ := command.RunStopped(cov.Result); stopped {
		return nil
	}
	hosts, complete := resultGapHosts(cov.Result)
	if !complete {
		return nil
	}
	released, err := repo.ReleaseRunFindings(ctx, tenantID, commandID, hosts, runHoldReasons)
	if err != nil {
		s.logger.Warn("held findings: could not release the findings a later run saw again",
			keyCommandID, commandID.String(), "error", logger.SanitizeError(err))
		return nil
	}
	if len(released) == 0 {
		return nil
	}
	s.logger.Info("held findings released by a later run", keyCommandID, commandID.String(), "released_findings", len(released))
	if s.findingProcessor != nil {
		s.findingProcessor.announceReleased(ctx, tenantID, released)
	}
	return released
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

// announceReleased runs, once, the created side effects (notifications,
// automation rules, tickets) of findings whose hold was released: they sent
// none while held. Like new findings, a finding decided meanwhile (false
// positive, accepted), closed, branch-only or already reported sends none.
// Queued like new findings when the queue is wired, run directly otherwise.
func (p *FindingProcessor) announceReleased(ctx context.Context, tenantID shared.ID, ids []shared.ID) {
	if len(ids) == 0 || (p.findingCreatedCallback == nil && p.sideEffects == nil) {
		return
	}
	loader, ok := p.repo.(ReleasedLoader)
	if !ok {
		return
	}
	fs, err := loader.GetByIDs(ctx, tenantID, ids)
	if err != nil {
		p.logger.Warn("held findings: released findings not loaded; their notifications are not sent",
			"tenant_id", tenantID.String(), "error", logger.SanitizeError(err))
		return
	}
	open := make([]*vulnerability.Finding, 0, len(fs))
	for _, f := range withoutDecided(withoutHeld(fs)) {
		if vulnerability.IsOpenStatus(f.Status()) {
			open = append(open, f)
		}
	}
	counting := p.withoutReported(ctx, tenantID, p.withoutBranchOnly(ctx, tenantID, open))
	if len(counting) == 0 {
		return
	}
	if p.sideEffects != nil {
		p.enqueueCreated(ctx, tenantID, counting)
		return
	}
	p.findingCreatedCallback(ctx, tenantID, counting)
}
