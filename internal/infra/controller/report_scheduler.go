package controller

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/robfig/cron/v3"

	"github.com/openctemio/api/pkg/domain/reportschedule"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/report"
)

// ReportScheduleStore is the persistence surface the scheduler needs.
type ReportScheduleStore interface {
	ListDue(ctx context.Context, now time.Time) ([]*reportschedule.ReportSchedule, error)
	Update(ctx context.Context, s *reportschedule.ReportSchedule) error
}

// ReportStatsSource provides the finding aggregates a summary report renders.
type ReportStatsSource interface {
	GetStats(ctx context.Context, tenantID shared.ID, dataScopeUserID *shared.ID, assetID *shared.ID) (*vulnerability.FindingStats, error)
}

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
	store    ReportScheduleStore
	stats    ReportStatsSource
	emailer  ReportEmailer
	tenants  TenantNamer // optional; nil → tenant id used as the name
	config   ReportSchedulerConfig
	cronspec cron.Parser
	logger   *logger.Logger
}

// NewReportScheduler builds the controller.
func NewReportScheduler(store ReportScheduleStore, stats ReportStatsSource, emailer ReportEmailer, tenants TenantNamer, cfg ReportSchedulerConfig, log *logger.Logger) *ReportScheduler {
	if cfg.Interval <= 0 {
		cfg.Interval = time.Minute
	}
	return &ReportScheduler{
		store:   store,
		stats:   stats,
		emailer: emailer,
		tenants: tenants,
		config:  cfg,
		// Standard 5-field cron (minute hour dom month dow), matching what the
		// schedule UI collects.
		cronspec: cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow),
		logger:   log.With("controller", "report-scheduler"),
	}
}

func (c *ReportScheduler) Name() string            { return "report-scheduler" }
func (c *ReportScheduler) Interval() time.Duration { return c.config.Interval }

// Reconcile renders and delivers every due schedule, then records the run +
// next fire time. Idempotent at the run level: next_run_at advances past now,
// so a schedule is not re-picked until its next slot. One failing schedule never
// aborts the others.
func (c *ReportScheduler) Reconcile(ctx context.Context) (int, error) {
	now := time.Now()
	due, err := c.store.ListDue(ctx, now)
	if err != nil {
		return 0, fmt.Errorf("list due schedules: %w", err)
	}

	processed := 0
	for _, s := range due {
		// Compute the next fire time first; even if delivery fails we must
		// advance next_run_at, otherwise the schedule busy-loops every tick.
		next := c.nextRun(s, now)

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

// nextRun parses the cron expression and returns the next fire after now.
// Falls back to +24h on a bad expression (logged) so the schedule keeps moving
// rather than busy-looping or stalling.
func (c *ReportScheduler) nextRun(s *reportschedule.ReportSchedule, now time.Time) *time.Time {
	sched, err := c.cronspec.Parse(s.CronExpression())
	if err != nil {
		c.logger.Warn("invalid cron expression; defaulting next run to +24h",
			"schedule_id", s.ID().String(), "cron", s.CronExpression(), "error", err)
		t := now.Add(24 * time.Hour)
		return &t
	}
	t := sched.Next(now)
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
	stats, err := c.stats.GetStats(ctx, s.TenantID(), nil, nil)
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

	return report.GenerateSummaryHTML(report.SummaryInput{
		TenantName:  name,
		GeneratedAt: time.Now(),
		Total:       stats.Total,
		Open:        stats.OpenCount,
		Resolved:    stats.ResolvedCount,
		BySeverity:  bySev,
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
