package controller

import (
	"context"
	"errors"
	"testing"
	"time"

	moduledom "github.com/openctemio/openctem/api/pkg/domain/module"
	"github.com/openctemio/openctem/api/pkg/domain/reportschedule"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type fakeStore struct {
	due     []*reportschedule.ReportSchedule
	updated []*reportschedule.ReportSchedule
	// lostClaims makes ClaimDue report that another replica won the slot.
	lostClaims bool
}

func (f *fakeStore) ListDue(_ context.Context, _ time.Time) ([]*reportschedule.ReportSchedule, error) {
	return f.due, nil
}
func (f *fakeStore) ClaimDue(_ context.Context, _, _ shared.ID, _ *time.Time, _ time.Time) (bool, error) {
	return !f.lostClaims, nil
}
func (f *fakeStore) Update(_ context.Context, s *reportschedule.ReportSchedule) error {
	f.updated = append(f.updated, s)
	return nil
}

type fakeStats struct{}

func (fakeStats) GetStats(_ context.Context, _ shared.ID, _ *shared.ID, _ vulnerability.FindingStatsFilter) (*vulnerability.FindingStats, error) {
	st := vulnerability.NewFindingStats()
	st.Total, st.OpenCount, st.ResolvedCount = 10, 7, 3
	st.BySeverity[vulnerability.SeverityHigh] = 4
	st.KevOpen, st.EpssHighOpen, st.SLABreached = 2, 3, 1
	return st, nil
}

func (fakeStats) CountWindow(_ context.Context, _ shared.ID, _ *shared.DataScope, _ int) (int64, int64, error) {
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
	// Reconstitute (not NewReportSchedule) so these scheduler tests can build
	// schedules with intentionally-invalid report_type/cron — simulating rows
	// already persisted (e.g. created before validation existed) — to exercise
	// the scheduler's defensive runtime handling. Creation-time validation lives
	// in NewReportSchedule and is covered by entity_validation_test.go.
	now := time.Now()
	s := reportschedule.ReconstituteReportSchedule(
		shared.NewID(), shared.NewID(),
		"Weekly", reportType, "html",
		map[string]any{}, nil, "email", nil,
		cron, "UTC", true,
		nil, nil, "", 0, nil, now, now,
	)
	rs := make([]reportschedule.Recipient, 0, len(recipients))
	for _, e := range recipients {
		rs = append(rs, reportschedule.Recipient{Email: e})
	}
	s.SetRecipients(rs)
	return s
}

func newTestScheduler(store ReportScheduleStore, em ReportEmailer) *ReportScheduler {
	return NewReportScheduler(store, fakeStats{}, em, nil, nil, ReportSchedulerConfig{}, logger.NewNop())
}

// newTestSchedulerWithGuard is like newTestScheduler but wires a ModuleGuard so
// the reports-module compute guard can be exercised.
func newTestSchedulerWithGuard(store ReportScheduleStore, em ReportEmailer, guard ModuleGuard) *ReportScheduler {
	return NewReportScheduler(store, fakeStats{}, em, nil, guard, ReportSchedulerConfig{}, logger.NewNop())
}

// TestReportScheduler_SkipsUnsubscribedTenant proves the compute guard: a due
// schedule whose tenant has NOT subscribed to the reports module is skipped —
// no render, no delivery, no persistence.
func TestReportScheduler_SkipsUnsubscribedTenant(t *testing.T) {
	s := newSchedule(t, "executive_summary", "0 9 * * 1", "ciso@acme.com")
	tenantID := s.TenantID().String()
	store := &fakeStore{due: []*reportschedule.ReportSchedule{s}}
	em := &fakeEmailer{configured: true}

	guard := &fakeModuleGuard{disabledByTenant: map[string]map[string]bool{
		tenantID: {moduledom.ModuleReports: true},
	}}

	n, err := newTestSchedulerWithGuard(store, em, guard).Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if n != 0 {
		t.Fatalf("processed = %d, want 0 (tenant unsubscribed from reports)", n)
	}
	if len(em.sentTo) != 0 {
		t.Fatalf("expected no report delivered, got %d", len(em.sentTo))
	}
	if len(store.updated) != 0 {
		t.Fatalf("a skipped schedule must not be updated, got %d", len(store.updated))
	}
}

// TestReportScheduler_RunsForSubscribedTenant proves the guard is a no-op when
// the tenant's disabled set does not contain the reports module.
func TestReportScheduler_RunsForSubscribedTenant(t *testing.T) {
	s := newSchedule(t, "executive_summary", "0 9 * * 1", "ciso@acme.com")
	store := &fakeStore{due: []*reportschedule.ReportSchedule{s}}
	em := &fakeEmailer{configured: true}

	// Empty per-tenant disabled sets → nothing skipped (all-on subscription).
	guard := &fakeModuleGuard{disabledByTenant: map[string]map[string]bool{}}

	n, err := newTestSchedulerWithGuard(store, em, guard).Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if n != 1 {
		t.Fatalf("processed = %d, want 1", n)
	}
	if len(em.sentTo) != 1 {
		t.Fatalf("expected 1 report delivered, got %d", len(em.sentTo))
	}
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
	// A schedule already persisted with an unparseable cron (validation now
	// rejects these at creation, but older rows may exist) must not stall the
	// scheduler — next run defaults to +24h.
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

// TestReportScheduler_NextRunHonoursScheduleTimezone: the schedule's timezone is
// validated and stored (the UI pre-fills the browser's zone), but the cron used
// to be evaluated in the server's zone (UTC), so "0 9 * * *" for an
// Asia/Ho_Chi_Minh tenant fired at 16:00 local instead of 09:00.
func TestReportScheduler_NextRunHonoursScheduleTimezone(t *testing.T) {
	now := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC) // 07:00 in Ho Chi Minh City
	mk := func(tz string) *reportschedule.ReportSchedule {
		return reportschedule.ReconstituteReportSchedule(
			shared.NewID(), shared.NewID(), "Daily", "executive_summary", "html",
			map[string]any{}, nil, "email", nil,
			"0 9 * * *", tz, true, nil, nil, "", 0, nil, now, now,
		)
	}
	c := newTestScheduler(&fakeStore{}, &fakeEmailer{configured: true})

	cases := []struct {
		tz   string
		want time.Time
	}{
		{"Asia/Ho_Chi_Minh", time.Date(2026, 10, 2, 2, 0, 0, 0, time.UTC)},  // 09:00 +07
		{"America/New_York", time.Date(2026, 10, 2, 13, 0, 0, 0, time.UTC)}, // 09:00 EDT (-04)
		{"UTC", time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)},
		{"", time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)},          // unset = UTC
		{"Not/AZone", time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)}, // unloadable = UTC, not a stall
	}
	for _, tc := range cases {
		got := c.nextRun(mk(tc.tz), now)
		if got == nil || !got.Equal(tc.want) {
			t.Errorf("tz=%q: next run = %v, want %v", tc.tz, got, tc.want)
		}
	}
}

// A slot another replica claimed is neither delivered nor recorded here.
func TestReportScheduler_LostClaimSkipsDelivery(t *testing.T) {
	store := &fakeStore{
		due:        []*reportschedule.ReportSchedule{newSchedule(t, "executive_summary", "0 8 * * 1", "a@example.invalid")},
		lostClaims: true,
	}
	em := &fakeEmailer{configured: true}
	n, err := newTestScheduler(store, em).Reconcile(context.Background())
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if n != 0 || len(em.sentTo) != 0 || len(store.updated) != 0 {
		t.Fatalf("lost claim: processed=%d sent=%d updated=%d, want all 0", n, len(em.sentTo), len(store.updated))
	}
}

// allowOnly is a recipient policy that admits a fixed set of addresses.
type allowOnly map[string]bool

func (a allowOnly) AllowedRecipients(_ context.Context, _ shared.ID, emails []string) (map[string]bool, error) {
	out := map[string]bool{}
	for _, e := range emails {
		out[e] = a[e]
	}
	return out, nil
}

// Recipients are re-checked at send time (D12): an address that is no
// longer a member or in an allowed domain is skipped, the others still get
// the report, and with nobody left nothing is sent.
func TestReportScheduler_SkipsRecipientsNoLongerAllowed(t *testing.T) {
	s := newSchedule(t, "executive_summary", "0 9 * * 1", "ciso@acme.com", "Leaver@Gmail.com")
	store := &fakeStore{due: []*reportschedule.ReportSchedule{s}}
	em := &fakeEmailer{configured: true}
	sch := newTestScheduler(store, em)
	sch.SetRecipientPolicy(allowOnly{"ciso@acme.com": true})
	if _, err := sch.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(em.sentTo) != 1 || len(em.sentTo[0]) != 1 || em.sentTo[0][0] != "ciso@acme.com" {
		t.Fatalf("sent to %v, want only ciso@acme.com", em.sentTo)
	}

	s2 := newSchedule(t, "executive_summary", "0 9 * * 1", "leaver@gmail.com")
	store2 := &fakeStore{due: []*reportschedule.ReportSchedule{s2}}
	em2 := &fakeEmailer{configured: true}
	sch2 := newTestScheduler(store2, em2)
	sch2.SetRecipientPolicy(allowOnly{})
	if _, err := sch2.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(em2.sentTo) != 0 {
		t.Fatalf("a schedule with no allowed recipient sent mail: %v", em2.sentTo)
	}
	if got := store2.updated[0].LastStatus(); got != "no_recipients" {
		t.Errorf("status = %q, want no_recipients", got)
	}
}

// recordingStats records the scope each render asks for.
type recordingStats struct {
	user   *shared.ID
	strict bool
	scope  *shared.DataScope
}

func (r *recordingStats) GetStats(_ context.Context, _ shared.ID, u *shared.ID, f vulnerability.FindingStatsFilter) (*vulnerability.FindingStats, error) {
	r.user, r.strict = u, f.ScopeStrict
	return vulnerability.NewFindingStats(), nil
}

func (r *recordingStats) CountWindow(_ context.Context, _ shared.ID, sc *shared.DataScope, _ int) (int64, int64, error) {
	r.scope = sc
	return 0, 0, nil
}

type fakeScope struct {
	restricted map[shared.ID]bool
	err        error
}

func (f fakeScope) ForUser(_ context.Context, tenantID, userID shared.ID) (*shared.DataScope, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.restricted[userID] {
		return &shared.DataScope{TenantID: tenantID, UserID: userID}, nil
	}
	return nil, nil
}

// A report renders under its creator's data scope (owner decision D6): a
// restricted creator's report counts only their assets; an unrestricted
// creator's counts the organization; with no creator, or when the creator
// cannot be resolved (left the organization), nothing is sent.
func TestReportScheduler_RendersUnderCreatorScope(t *testing.T) {
	run := func(s *reportschedule.ReportSchedule, sc fakeScope) (*recordingStats, *fakeEmailer, string) {
		t.Helper()
		stats := &recordingStats{}
		store := &fakeStore{due: []*reportschedule.ReportSchedule{s}}
		em := &fakeEmailer{configured: true}
		c := NewReportScheduler(store, stats, em, nil, nil, ReportSchedulerConfig{}, logger.NewNop())
		c.SetScopeResolver(sc)
		if _, err := c.Reconcile(context.Background()); err != nil {
			t.Fatal(err)
		}
		return stats, em, store.updated[0].LastStatus()
	}

	member, admin := shared.NewID(), shared.NewID()
	s := newSchedule(t, "executive_summary", "0 9 * * 1", "ciso@acme.com")
	s.SetCreatedBy(member)
	stats, em, status := run(s, fakeScope{restricted: map[shared.ID]bool{member: true}})
	if stats.user == nil || *stats.user != member || !stats.strict || stats.scope == nil || stats.scope.UserID != member {
		t.Errorf("restricted creator: stats user=%v strict=%v window scope=%v, want the creator's strict scope", stats.user, stats.strict, stats.scope)
	}
	if status != "completed" || len(em.sentTo) != 1 {
		t.Errorf("restricted creator: status %q, sent %v", status, em.sentTo)
	}

	s2 := newSchedule(t, "executive_summary", "0 9 * * 1", "ciso@acme.com")
	s2.SetCreatedBy(admin)
	if stats, _, _ := run(s2, fakeScope{}); stats.user != nil || stats.strict || stats.scope != nil {
		t.Errorf("unrestricted creator rendered with a scope: %+v", stats)
	}

	s3 := newSchedule(t, "executive_summary", "0 9 * * 1", "ciso@acme.com")
	if _, em, status := run(s3, fakeScope{}); status != "failed" || len(em.sentTo) != 0 {
		t.Errorf("schedule without a creator: status %q, sent %v; want failed, nothing sent", status, em.sentTo)
	}

	s4 := newSchedule(t, "executive_summary", "0 9 * * 1", "ciso@acme.com")
	s4.SetCreatedBy(member)
	if _, em, status := run(s4, fakeScope{err: errors.New("not a member")}); status != "failed" || len(em.sentTo) != 0 {
		t.Errorf("creator who cannot be resolved: status %q, sent %v; want failed, nothing sent", status, em.sentTo)
	}
}
