package scan

// Schedule misfires made visible (research/468 D17, RFC-046 §6.1): a skipped
// occurrence is kept on the scan (last_missed_at, last_missed_reason), sent as
// a scan.schedule_missed notification event, and offered as [Run now] in the
// console. The note clears when a later scheduled run starts.

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/openctemio/openctem/server/internal/app/outbox"
	"github.com/openctemio/openctem/server/pkg/domain/integration"
	"github.com/openctemio/openctem/server/pkg/domain/scan"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// Names shared by the log lines and the event payload below.
const (
	logKeyScanID     = "scan_id"
	misfireAggregate = "scan"
)

// misfireStore is the scan repository's misfire note (postgres.ScanRepository).
// Both calls are tenant-scoped.
type misfireStore interface {
	RecordScheduleMisfire(ctx context.Context, tenantID, id shared.ID, missedAt time.Time, reason string) error
	ClearScheduleMisfire(ctx context.Context, tenantID, id shared.ID) error
}

// ScheduleMissEvents hands the scan.schedule_missed event to the notification
// outbox (*outbox.Service).
type ScheduleMissEvents interface {
	Enqueue(ctx context.Context, params outbox.EnqueueParams) error
}

// SetScheduleMissEvents wires the notification event of a missed occurrence.
func (s *Service) SetScheduleMissEvents(e ScheduleMissEvents) { s.misfireEvents = e }

// misfireReason is the code stored for a skipped occurrence of sc.
func misfireReason(sc *scan.Scan) string {
	if sc.ScheduleType == scan.ScheduleOnce {
		return scan.MissReasonOnceGraceExceeded
	}
	return scan.MissReasonPlatformUnavailable
}

// recordMisfire keeps the skipped occurrence on the scan and sends the event.
// It runs once per missed occurrence: the caller won the next_run_at claim.
// Failures are logged; the skip itself already happened.
func (s *ScanScheduler) recordMisfire(ctx context.Context, sc *scan.Scan, occurrence time.Time, next *time.Time) {
	reason := misfireReason(sc)
	if m, ok := s.scanRepo.(misfireStore); ok {
		if err := m.RecordScheduleMisfire(ctx, sc.TenantID, sc.ID, occurrence, reason); err != nil {
			s.logger.Error("failed to record the schedule misfire", logKeyScanID, sc.ID.String(), "error", logger.SanitizeError(err))
		}
	}
	ev := s.scanService.misfireEvents
	if ev == nil {
		return
	}
	meta := map[string]any{
		logKeyScanID: sc.ID.String(),
		"scan_name":  sc.Name,
		"missed_at":  occurrence.UTC().Format(time.RFC3339),
		"reason":     reason,
	}
	if next != nil {
		meta["next_run_at"] = next.UTC().Format(time.RFC3339)
	}
	aggregate, perr := uuid.Parse(sc.ID.String())
	if perr != nil {
		return
	}
	if err := ev.Enqueue(ctx, outbox.EnqueueParams{
		TenantID:      sc.TenantID,
		EventType:     string(integration.EventTypeScanScheduleMissed),
		AggregateType: misfireAggregate,
		AggregateID:   &aggregate,
		Title:         "Scheduled scan missed: " + sc.Name,
		Body:          "The scheduled run of " + sc.Name + " at " + occurrence.UTC().Format(time.RFC3339) + " was skipped because it was missed by more than one interval. Run it now, or wait for the next scheduled run.",
		Severity:      "medium",
		URL:           "/scans/" + sc.ID.String(),
		Metadata:      meta,
	}); err != nil {
		s.logger.Warn("schedule misfire event not enqueued", logKeyScanID, sc.ID.String(), "error", logger.SanitizeError(err))
	}
}

// clearMisfire drops the note once a scheduled run of sc has started.
func (s *ScanScheduler) clearMisfire(ctx context.Context, sc *scan.Scan) {
	if sc.LastMissedAt == nil {
		return
	}
	if m, ok := s.scanRepo.(misfireStore); ok {
		if err := m.ClearScheduleMisfire(ctx, sc.TenantID, sc.ID); err != nil {
			s.logger.Warn("failed to clear the schedule misfire", logKeyScanID, sc.ID.String(), "error", logger.SanitizeError(err))
		}
	}
}
