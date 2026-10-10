package controller

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	moduledom "github.com/openctemio/openctem/api/pkg/domain/module"
	"github.com/openctemio/openctem/api/pkg/domain/reportschedule"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/report"
)

// ReportScheduleStore is the persistence surface the scheduler needs.
type ReportScheduleStore interface {
	ListDue(ctx context.Context, now time.Time) ([]*reportschedule.ReportSchedule, error)
	// ClaimDue moves next_run_at from seen to next and reports whether this
	// caller won the slot. Every replica runs this controller; only the winner
	// renders and delivers.
	ClaimDue(ctx context.Context, tenantID, id shared.ID, seen *time.Time, next time.Time) (bool, error)
	Update(ctx context.Context, s *reportschedule.ReportSchedule) error
}

// ReportStatsSource provides the finding aggregates a summary report renders.
type ReportStatsSource interface {
	GetStats(ctx context.Context, tenantID shared.ID, dataScopeUserID *shared.ID, filter vulnerability.FindingStatsFilter) (*vulnerability.FindingStats, error)
	// CountWindow returns new (created) vs resolved finding counts over the
	// trailing `days` window — the digest's trend line.
	// A non-nil scope counts only findings on in-scope assets.
	CountWindow(ctx context.Context, tenantID shared.ID, scope *shared.DataScope, days int) (newCount, resolvedCount int64, err error)
}

// ReportScopeResolver resolves the data scope of a user outside a request
// (datascope.Enforcer.ForUser): nil when the user is unrestricted.
type ReportScopeResolver interface {
	ForUser(ctx context.Context, tenantID, userID shared.ID) (*shared.DataScope, error)
}

// errNoReportCreator: a schedule with no recorded creator has no scope to
// render under, so it is not rendered (fail closed).
var errNoReportCreator = errors.New("schedule has no creator to render under")

// reportWindowDays is the trailing window the digest's new-vs-resolved trend covers.
const reportWindowDays = 7

// ReportEmailer delivers a rendered HTML report to recipients.
type ReportEmailer interface {
	SendReport(ctx context.Context, tenantID string, to []string, subject, htmlBody string) error
	IsConfigured() bool
}

// TenantNamer resolves a tenant's display name for the report header (optional).
type TenantNamer interface {
	GetName(ctx context.Context, tenantID shared.ID) (string, error)
}

// ReportSchedulerConfig configures the controller.
type ReportSchedulerConfig struct {
	Interval time.Duration
}

// ReportScheduler runs due report schedules: render → deliver → record next run.
// This is the controller that was missing — schedules could be created but never
// executed because nothing invoked ListDue().
type ReportScheduler struct {
	store   ReportScheduleStore
	stats   ReportStatsSource
	emailer ReportEmailer
	tenants TenantNamer // optional; nil → tenant id used as the name
	config  ReportSchedulerConfig
	logger  *logger.Logger
	// moduleGuard skips schedules whose tenant has not subscribed to the reports
	// module. Optional — nil means "never skip" (fully backward compatible).
	moduleGuard ModuleGuard
	// recipients re-checks every recipient at send time (a member may have
	// left, a domain may have been removed): owner decision D12. Nil: no
	// check (tests).
	recipients reportschedule.RecipientPolicy
	// scope renders each report under its creator's data scope (owner
	// decision D6): a restricted member's schedule reports only their
	// assets. Nil: tenant-wide (tests).
	scope ReportScopeResolver
}

// SetRecipientPolicy wires the send-time recipient check.
func (c *ReportScheduler) SetRecipientPolicy(p reportschedule.RecipientPolicy) { c.recipients = p }

// SetScopeResolver wires rendering under the schedule creator's data scope.
func (c *ReportScheduler) SetScopeResolver(r ReportScopeResolver) { c.scope = r }

// NewReportScheduler builds the controller. moduleGuard is optional (nil = never
// skip); when set, schedules for tenants without the reports module are skipped.
func NewReportScheduler(store ReportScheduleStore, stats ReportStatsSource, emailer ReportEmailer, tenants TenantNamer, moduleGuard ModuleGuard, cfg ReportSchedulerConfig, log *logger.Logger) *ReportScheduler {
	if cfg.Interval <= 0 {
		cfg.Interval = time.Minute
	}
	return &ReportScheduler{
		store:       store,
		stats:       stats,
		emailer:     emailer,
		tenants:     tenants,
		moduleGuard: moduleGuard,
		config:      cfg,
		logger:      log.With("controller", "report-scheduler"),
	}
}

func (c *ReportScheduler) Name() string            { return "report-scheduler" }
func (c *ReportScheduler) Interval() time.Duration { return c.config.Interval }

// Reconcile renders and delivers every due schedule, then records the run +
// next fire time. Each due slot is first claimed (ClaimDue): every API replica
// runs this controller and lists the same due rows, and without the claim each
// replica emailed the report. One failing schedule never aborts the others.
func (c *ReportScheduler) Reconcile(ctx context.Context) (int, error) {
	now := time.Now()
	due, err := c.store.ListDue(ctx, now)
	if err != nil {
		return 0, fmt.Errorf("list due schedules: %w", err)
	}

	modules := newTenantModuleCache(c.moduleGuard)
	processed := 0
	for _, s := range due {
		// Compute-level independence: skip schedules whose tenant has not
		// subscribed to the reports module. The next-run time is still advanced
		// below-guard by RecordRun only for tenants we process; a skipped
		// tenant's schedule is left untouched (it will simply be re-evaluated
		// next tick and skipped again while unsubscribed — cheap, cached).
		if modules.disabled(ctx, s.TenantID().String(), moduledom.ModuleReports) {
			c.logger.Debug("skipping report schedule: reports module not subscribed",
				"schedule_id", s.ID().String(), "tenant_id", s.TenantID().String())
			continue
		}

		// Compute the next fire time first; even if delivery fails we must
		// advance next_run_at, otherwise the schedule busy-loops every tick.
		next := c.nextRun(s, now)

		won, err := c.store.ClaimDue(ctx, s.TenantID(), s.ID(), s.NextRunAt(), *next)
		if err != nil {
			c.logger.Error("failed to claim report schedule", "schedule_id", s.ID().String(), "error", err)
			continue
		}
		if !won {
			// Another replica claimed this slot (or the schedule changed since
			// it was listed); it delivers, this replica does not.
			c.logger.Debug("report schedule slot claimed elsewhere", "schedule_id", s.ID().String())
			continue
		}

		status := c.runOne(ctx, s)
		s.RecordRun(status, next)
		if err := c.store.Update(ctx, s); err != nil {
			c.logger.Error("failed to persist schedule run", "schedule_id", s.ID().String(), "error", err)
			continue
		}
		processed++
	}
	return processed, nil
}

// nextRun returns the schedule's next fire after now in its own timezone
// (ReportSchedule.NextFireAfter). Falls back to +24h on a bad expression
// (logged) so the schedule keeps moving rather than busy-looping or stalling.
func (c *ReportScheduler) nextRun(s *reportschedule.ReportSchedule, now time.Time) *time.Time {
	t, err := s.NextFireAfter(now)
	if err != nil {
		c.logger.Warn("invalid cron expression; defaulting next run to +24h",
			"schedule_id", s.ID().String(), "cron", s.CronExpression(), "error", err)
		t = now.Add(24 * time.Hour)
	}
	return &t
}

// runOne renders + delivers a single schedule and returns the status to record.
func (c *ReportScheduler) runOne(ctx context.Context, s *reportschedule.ReportSchedule) string {
	if !c.supportsType(s.ReportType()) {
		c.logger.Debug("unsupported report type; skipping render",
			"schedule_id", s.ID().String(), "report_type", s.ReportType())
		return "unsupported"
	}

	html, err := c.render(ctx, s)
	if err != nil {
		c.logger.Error("failed to render report", "schedule_id", s.ID().String(), "error", err)
		return "failed"
	}

	switch s.DeliveryChannel() {
	case "", "email":
		to := recipientEmails(s.Recipients())
		if refused, err := reportschedule.RefusedRecipients(ctx, c.recipients, s.TenantID(), s.Recipients()); err != nil {
			c.logger.Error("failed to check report recipients", "schedule_id", s.ID().String(), "error", err)
			return "failed"
		} else if len(refused) > 0 {
			drop := make(map[string]bool, len(refused))
			for _, e := range refused {
				drop[e] = true
			}
			kept := to[:0]
			for _, e := range to {
				if !drop[strings.ToLower(strings.TrimSpace(e))] {
					kept = append(kept, e)
				}
			}
			to = kept
			c.logger.Warn("report recipients not allowed were skipped (not a member, not an allowed domain)",
				"schedule_id", s.ID().String(), "skipped", len(refused))
		}
		if len(to) == 0 {
			c.logger.Warn("schedule has no recipients", "schedule_id", s.ID().String())
			return "no_recipients"
		}
		if !c.emailer.IsConfigured() {
			c.logger.Warn("email not configured; cannot deliver report", "schedule_id", s.ID().String())
			return "failed"
		}
		subject := fmt.Sprintf("OpenCTEM Security Report — %s", s.Name())
		if err := c.emailer.SendReport(ctx, s.TenantID().String(), to, subject, html); err != nil {
			c.logger.Error("failed to email report", "schedule_id", s.ID().String(), "error", err)
			return "failed"
		}
		return "completed"
	default:
		c.logger.Warn("unsupported delivery channel",
			"schedule_id", s.ID().String(), "channel", s.DeliveryChannel())
		return "unsupported"
	}
}

// render builds the executive-summary HTML from the tenant's finding stats.
func (c *ReportScheduler) render(ctx context.Context, s *reportschedule.ReportSchedule) (string, error) {
	// The report shows what its creator can see, decided now (they may have
	// lost access, or left the organization: then nothing is rendered).
	var scope *shared.DataScope
	var statsUser *shared.ID
	filter := vulnerability.FindingStatsFilter{}
	if c.scope != nil {
		creator := s.CreatedBy()
		if creator == nil {
			return "", errNoReportCreator
		}
		sc, err := c.scope.ForUser(ctx, s.TenantID(), *creator)
		if err != nil {
			return "", fmt.Errorf("resolve creator scope: %w", err)
		}
		switch {
		case sc.Restricted():
			scope, statsUser = sc, creator
		case sc != nil:
			// Unrestricted but private program findings hidden from the
			// creator (RFC-065 §15.3).
			scope = sc
			filter.HiddenFor = creator
		}
	}
	stats, err := c.stats.GetStats(ctx, s.TenantID(), statsUser, filter)
	if err != nil {
		return "", fmt.Errorf("get finding stats: %w", err)
	}

	bySev := make(map[string]int64, len(stats.BySeverity))
	for sev, n := range stats.BySeverity {
		bySev[strings.ToLower(string(sev))] = n
	}

	name := s.TenantID().String()
	if c.tenants != nil {
		if n, err := c.tenants.GetName(ctx, s.TenantID()); err == nil && n != "" {
			name = n
		}
	}

	// Trend over the trailing window. Best-effort: a failure here just omits the
	// window card (WindowDays stays 0) rather than failing the whole report.
	var windowDays int
	var newInWindow, resolvedInWindow int64
	if n, res, werr := c.stats.CountWindow(ctx, s.TenantID(), scope, reportWindowDays); werr == nil {
		windowDays, newInWindow, resolvedInWindow = reportWindowDays, n, res
	} else {
		c.logger.Warn("report window counts failed; omitting trend", "tenant_id", s.TenantID().String(), "error", werr)
	}

	return report.GenerateSummaryHTML(report.SummaryInput{
		TenantName:       name,
		GeneratedAt:      time.Now(),
		Total:            stats.Total,
		Open:             stats.OpenCount,
		Resolved:         stats.ResolvedCount,
		BySeverity:       bySev,
		KevOpen:          stats.KevOpen,
		EpssHighOpen:     stats.EpssHighOpen,
		SLABreached:      stats.SLABreached,
		WindowDays:       windowDays,
		NewInWindow:      newInWindow,
		ResolvedInWindow: resolvedInWindow,
	})
}

// supportsType reports whether the controller can render this report type today.
// The generic executive summary covers these; other types (technical, compliance)
// await dedicated generators.
func (c *ReportScheduler) supportsType(reportType string) bool {
	switch strings.ToLower(strings.TrimSpace(reportType)) {
	case "", "executive_summary", "summary", "findings":
		return true
	default:
		return false
	}
}

func recipientEmails(rs []reportschedule.Recipient) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		if e := strings.TrimSpace(r.Email); e != "" {
			out = append(out, e)
		}
	}
	return out
}
