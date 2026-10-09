package retest

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/openctemio/openctem/api/internal/app/outbox"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// ChangeKind is what happened to a finding that people should hear about
// (RFC-039 §7.4, §7.5).
type ChangeKind string

const (
	// ChangeFixed: a retest found the issue gone and resolved the finding.
	ChangeFixed ChangeKind = "fixed"
	// ChangeRegression: a finding closed as fixed was seen again and reopened.
	ChangeRegression ChangeKind = "regression"
	// ChangeFixRejected: a finding marked fix_applied was still detected.
	ChangeFixRejected ChangeKind = "fix_rejected"
)

// Change is one finding change to announce.
type Change struct {
	TenantID  shared.ID
	FindingID shared.ID
	Kind      ChangeKind
	// Source is what observed it: "retest" or "scan".
	Source string
	// Detail is a short platform-written explanation (template, reason). It
	// is never scanner evidence.
	Detail string
}

// Announcer tells people about a fix or a regression.
type Announcer interface {
	Announce(ctx context.Context, c Change)
}

// TicketCommenter comments on the ticket linked to a finding
// (*jira.SyncService.CommentOnFinding). Opt-in per integration.
type TicketCommenter interface {
	CommentOnFinding(ctx context.Context, tenantID, findingID shared.ID, body string) error
}

// NotificationEnqueuer queues a notification (*outbox.Service).
type NotificationEnqueuer interface {
	Enqueue(ctx context.Context, params outbox.EnqueueParams) error
}

// ChangeAnnouncer comments on the linked ticket and queues a finding_fixed /
// finding_reopened notification, which the tenant's notification integrations
// route by their event filters. Best-effort: a failure is logged, never fails
// the change that was announced.
type ChangeAnnouncer struct {
	findings FindingReader
	tickets  TicketCommenter
	notify   NotificationEnqueuer
	logger   *logger.Logger
}

// NewChangeAnnouncer wires the announcer. tickets or notify may be nil (that
// channel is then skipped).
func NewChangeAnnouncer(findings FindingReader, tickets TicketCommenter, notify NotificationEnqueuer, log *logger.Logger) *ChangeAnnouncer {
	return &ChangeAnnouncer{findings: findings, tickets: tickets, notify: notify, logger: log.With("component", "finding-change-announcer")}
}

// maxDetail bounds the free text carried into a ticket or notification.
const maxDetail = 300

// Announce implements Announcer.
func (a *ChangeAnnouncer) Announce(ctx context.Context, c Change) {
	f, err := a.findings.GetByID(ctx, c.TenantID, c.FindingID)
	if err != nil {
		a.logger.Warn("announce: finding lookup failed", "finding_id", c.FindingID.String(), "error", err)
		return
	}
	title := strings.TrimSpace(f.Title())
	if title == "" {
		title = f.ID().String()
	}
	detail := cleanDetail(c.Detail)
	headline, eventType := changeHeadline(c, title)

	if a.tickets != nil {
		body := headline
		if detail != "" {
			body += "\n\n" + detail
		}
		body += fmt.Sprintf("\n\nObserved by OpenCTEM (%s) at %s.", c.Source, time.Now().UTC().Format(time.RFC3339))
		if err := a.tickets.CommentOnFinding(ctx, c.TenantID, c.FindingID, body); err != nil {
			a.logger.Warn("announce: ticket comment failed", "finding_id", c.FindingID.String(), "error", err)
		}
	}
	if a.notify != nil {
		fid, err := uuid.Parse(c.FindingID.String())
		if err != nil {
			return
		}
		if err := a.notify.Enqueue(ctx, outbox.EnqueueParams{
			TenantID:      c.TenantID,
			EventType:     eventType,
			AggregateType: "finding",
			AggregateID:   &fid,
			Title:         headline,
			Body:          detail,
			Severity:      string(f.Severity()),
			Metadata: map[string]any{
				"finding_id": c.FindingID.String(),
				"change":     string(c.Kind),
				"source":     c.Source,
				"status":     string(f.Status()),
			},
		}); err != nil {
			a.logger.Warn("announce: notification not queued", "finding_id", c.FindingID.String(), "error", err)
		}
	}
}

// cleanDetail bounds and flattens free text before it reaches a ticket or a
// notification. Part of it can come from a sensor's summary (the retest
// reason), so control characters and line breaks are dropped and the length is
// capped: one line of plain text, never a payload.
func cleanDetail(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > maxDetail {
		s = string(r[:maxDetail]) + "…"
	}
	return s
}

func changeHeadline(c Change, title string) (string, string) {
	switch c.Kind {
	case ChangeFixed:
		return fmt.Sprintf("Fixed: %q is no longer detected", title), "finding_fixed"
	case ChangeFixRejected:
		return fmt.Sprintf("Fix did not hold: %q is still detected", title), "finding_reopened"
	default:
		return fmt.Sprintf("Regression: %q was detected again and reopened", title), "finding_reopened"
	}
}

// RegressionSLA restarts the SLA of reopened findings (*sla.RegressionRestarter).
type RegressionSLA interface {
	RestartForRegression(ctx context.Context, tenantID shared.ID, findingIDs []shared.ID, trigger string) (int, error)
}

// maxAnnouncedPerScan bounds the announcements one scan's regressions produce;
// a scan that reopens hundreds of findings must not page anyone hundreds of
// times. The SLA restart is not capped (it is bookkeeping, not a message).
const maxAnnouncedPerScan = 50

// ScanRegressions handles the regressions an ingested scan produced (the scan
// reopened findings closed as fixed): fresh SLA (RFC-039 D2) and an
// announcement. A validated_fixed finding reopened by a scan refutes a
// validation downgrade; it was never closed, so its SLA keeps running.
type ScanRegressions struct {
	sla      RegressionSLA
	announce Announcer
	logger   *logger.Logger
}

// NewScanRegressions wires the handler. Either collaborator may be nil.
func NewScanRegressions(sla RegressionSLA, announce Announcer, log *logger.Logger) *ScanRegressions {
	return &ScanRegressions{sla: sla, announce: announce, logger: log.With("component", "scan-regressions")}
}

// HandleRegressions implements the ingest regression seam.
func (h *ScanRegressions) HandleRegressions(ctx context.Context, tenantID shared.ID, reopened []vulnerability.ReopenedFinding, scanner string) {
	ids := make([]shared.ID, 0, len(reopened))
	for _, rf := range reopened {
		if rf.PreviousStatus == vulnerability.FindingStatusResolved {
			ids = append(ids, rf.ID)
		}
	}
	if len(ids) == 0 {
		return
	}
	if h.sla != nil {
		if _, err := h.sla.RestartForRegression(ctx, tenantID, ids, "scan"); err != nil {
			h.logger.Warn("scan regressions: SLA restart failed", "tenant_id", tenantID.String(), "error", err)
		}
	}
	if h.announce == nil {
		return
	}
	for i, id := range ids {
		if i == maxAnnouncedPerScan {
			h.logger.Info("scan regressions: announcements capped", "tenant_id", tenantID.String(),
				"announced", maxAnnouncedPerScan, "not_announced", len(ids)-maxAnnouncedPerScan)
			break
		}
		detail := "Seen again by a scan"
		if scanner != "" {
			detail += " (" + scanner + ")"
		}
		h.announce.Announce(ctx, Change{TenantID: tenantID, FindingID: id, Kind: ChangeRegression, Source: "scan", Detail: detail + "."})
	}
}
