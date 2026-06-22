package controller

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/api/pkg/domain/reportschedule"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/logger"
)

type fakeStore struct {
	due     []*reportschedule.ReportSchedule
	updated []*reportschedule.ReportSchedule
}

func (f *fakeStore) ListDue(_ context.Context, _ time.Time) ([]*reportschedule.ReportSchedule, error) {
	return f.due, nil
}
func (f *fakeStore) Update(_ context.Context, s *reportschedule.ReportSchedule) error {
	f.updated = append(f.updated, s)
	return nil
}

type fakeStats struct{}

func (fakeStats) GetStats(_ context.Context, _ shared.ID, _, _ *shared.ID) (*vulnerability.FindingStats, error) {
	st := vulnerability.NewFindingStats()
	st.Total, st.OpenCount, st.ResolvedCount = 10, 7, 3
	st.BySeverity[vulnerability.SeverityHigh] = 4
	st.KevOpen, st.EpssHighOpen, st.SLABreached = 2, 3, 1
	return st, nil
}

func (fakeStats) CountWindow(_ context.Context, _ shared.ID, _ int) (int64, int64, error) {
	return 5, 2, nil // new, resolved
}

type fakeEmailer struct {
	configured bool
	sentTo     [][]string
}

func (f *fakeEmailer) IsConfigured() bool { return f.configured }
func (f *fakeEmailer) SendReport(_ context.Context, _ string, to []string, _, _ string) error {
	f.sentTo = append(f.sentTo, to)
	return nil
}

func newSchedule(t *testing.T, reportType, cron string, recipients ...string) *reportschedule.ReportSchedule {
	t.Helper()
	s, err := reportschedule.NewReportSchedule(shared.NewID(), "Weekly", reportType, "html", cron)
	if err != nil {
		t.Fatalf("NewReportSchedule: %v", err)
	}
	rs := make([]reportschedule.Recipient, 0, len(recipients))
	for _, e := range recipients {
		rs = append(rs, reportschedule.Recipient{Email: e})
	}
	s.SetRecipients(rs)
	return s
}

func newTestScheduler(store ReportScheduleStore, em ReportEmailer) *ReportScheduler {
	return NewReportScheduler(store, fakeStats{}, em, nil, ReportSchedulerConfig{}, logger.NewNop())
}

func TestReportScheduler_RendersDeliversAndAdvances(t *testing.T) {
	s := newSchedule(t, "executive_summary", "0 9 * * 1", "ciso@acme.com")
	store := &fakeStore{due: []*reportschedule.ReportSchedule{s}}
	em := &fakeEmailer{configured: true}

	n, err := newTestScheduler(store, em).Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if n != 1 {
		t.Fatalf("processed = %d, want 1", n)
	}
	if len(em.sentTo) != 1 || em.sentTo[0][0] != "ciso@acme.com" {
		t.Fatalf("expected one email to ciso@acme.com, got %v", em.sentTo)
	}
	if len(store.updated) != 1 {
		t.Fatalf("schedule must be persisted once, got %d", len(store.updated))
	}
	got := store.updated[0]
	if got.LastStatus() != "completed" {
		t.Errorf("status = %q, want completed", got.LastStatus())
	}
	if got.NextRunAt() == nil || !got.NextRunAt().After(time.Now()) {
		t.Errorf("next_run_at must advance into the future, got %v", got.NextRunAt())
	}
}

func TestReportScheduler_NoRecipients_StillReschedules(t *testing.T) {
	s := newSchedule(t, "executive_summary", "0 9 * * 1") // no recipients
	store := &fakeStore{due: []*reportschedule.ReportSchedule{s}}
	em := &fakeEmailer{configured: true}

	if _, err := newTestScheduler(store, em).Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(em.sentTo) != 0 {
		t.Errorf("must not send with no recipients")
	}
	if len(store.updated) != 1 || store.updated[0].LastStatus() != "no_recipients" {
		t.Errorf("expected status no_recipients + persisted; got %d updates", len(store.updated))
	}
	if store.updated[0].NextRunAt() == nil {
		t.Errorf("must still advance next_run_at so it doesn't busy-loop")
	}
}

func TestReportScheduler_UnsupportedType_Skips(t *testing.T) {
	s := newSchedule(t, "technical", "0 9 * * 1", "x@acme.com")
	store := &fakeStore{due: []*reportschedule.ReportSchedule{s}}
	em := &fakeEmailer{configured: true}

	if _, err := newTestScheduler(store, em).Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(em.sentTo) != 0 {
		t.Errorf("unsupported type must not render/send")
	}
	if store.updated[0].LastStatus() != "unsupported" {
		t.Errorf("status = %q, want unsupported", store.updated[0].LastStatus())
	}
}

func TestReportScheduler_BadCron_FallsBackTo24h(t *testing.T) {
	// NewReportSchedule allows any non-empty cron; an unparseable one must not
	// stall the schedule — next run defaults to +24h.
	s := newSchedule(t, "executive_summary", "not a cron", "x@acme.com")
	store := &fakeStore{due: []*reportschedule.ReportSchedule{s}}
	em := &fakeEmailer{configured: true}

	before := time.Now().Add(23 * time.Hour)
	if _, err := newTestScheduler(store, em).Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	nr := store.updated[0].NextRunAt()
	if nr == nil || !nr.After(before) {
		t.Errorf("bad cron should default next run ~+24h, got %v", nr)
	}
}
