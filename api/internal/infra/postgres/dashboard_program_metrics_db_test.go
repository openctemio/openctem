package postgres

import (
	"context"
	"database/sql"
	"math"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Fixtures for the CTEM program metrics. Every timestamp is an explicit offset
// from one Go-side `base`, so expected durations are exact (not "about 6h").
// Each test seeds a noise tenant with data that WOULD change the answer if the
// query leaked across tenants.

const pmHour = time.Hour
const pmDay = 24 * time.Hour

type pmFixture struct {
	ctx  context.Context
	t    *testing.T
	db   *sql.DB
	base time.Time
}

func newPMFixture(t *testing.T) (*pmFixture, *DashboardRepository) {
	t.Helper()
	db := openGroupsDB(t)
	return &pmFixture{
		ctx:  context.Background(),
		t:    t,
		db:   db,
		base: time.Now().UTC().Truncate(time.Second),
	}, NewDashboardRepository(db)
}

func (f *pmFixture) exec(q string, args ...any) {
	f.t.Helper()
	if _, err := f.db.ExecContext(f.ctx, q, args...); err != nil {
		f.t.Fatalf("seed: %v\n%s", err, q)
	}
}

func (f *pmFixture) at(offset time.Duration) time.Time { return f.base.Add(offset) }

// asset seeds an asset; exposureChangedAt may be nil.
func (f *pmFixture) asset(tenant shared.ID, exposure string, internet bool, status string, firstSeen time.Time, exposureChangedAt *time.Time) shared.ID {
	f.t.Helper()
	id := shared.NewID()
	var ec any
	if exposureChangedAt != nil {
		ec = *exposureChangedAt
	}
	f.exec(`INSERT INTO assets (id, tenant_id, name, asset_type, exposure, is_internet_accessible, status, first_seen, exposure_changed_at)
		VALUES ($1, $2, $3, 'host', $4, $5, $6, $7, $8)`,
		id.String(), tenant.String(), "pm-"+id.String(), exposure, internet, status, firstSeen, ec)
	return id
}

// finding seeds a finding; asset, resolvedAt and slaDeadline may be nil.
func (f *pmFixture) finding(tenant shared.ID, asset *shared.ID, status string, firstDetected time.Time, resolvedAt, slaDeadline *time.Time) shared.ID {
	f.t.Helper()
	id := shared.NewID()
	var a, r, s any
	if asset != nil {
		a = asset.String()
	}
	if resolvedAt != nil {
		r = *resolvedAt
	}
	if slaDeadline != nil {
		s = *slaDeadline
	}
	f.exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status, first_detected_at, resolved_at, sla_deadline)
		VALUES ($1, $2, $3, 'sca', 'test', 'msg', 'high', $4, $5, $6, $7, $8)`,
		id.String(), tenant.String(), a, id.String(), status, firstDetected, r, s)
	return id
}

func (f *pmFixture) evidence(tenant, finding shared.ID, outcome string, createdAt time.Time) {
	f.t.Helper()
	f.exec(`INSERT INTO validation_evidence (tenant_id, finding_id, executor_kind, outcome, created_at)
		VALUES ($1, $2, 'nuclei', $3, $4)`, tenant.String(), finding.String(), outcome, createdAt)
}

func (f *pmFixture) assigned(tenant, finding shared.ID, assignee *shared.ID, at time.Time) {
	f.t.Helper()
	changes := `{}`
	if assignee != nil {
		changes = `{"assignee_id":"` + assignee.String() + `","assignee_name":"x"}`
	}
	f.exec(`INSERT INTO finding_activities (tenant_id, finding_id, activity_type, actor_type, changes, created_at)
		VALUES ($1, $2, 'assigned', 'user', $3::jsonb, $4)`, tenant.String(), finding.String(), changes, at)
}

func (f *pmFixture) activity(tenant, finding, actor shared.ID, activityType string, at time.Time) {
	f.t.Helper()
	f.exec(`INSERT INTO finding_activities (tenant_id, finding_id, activity_type, actor_type, actor_id, created_at)
		VALUES ($1, $2, $3, 'user', $4, $5)`, tenant.String(), finding.String(), activityType, actor.String(), at)
}

func ptrT(t time.Time) *time.Time { return &t }

func assertHours(t *testing.T, name string, got *float64, want float64) {
	t.Helper()
	if got == nil {
		t.Fatalf("%s: want %v h, got nil", name, want)
	}
	if math.Abs(*got-want) > 1e-6 {
		t.Fatalf("%s: want %v h, got %v h", name, want, *got)
	}
}

// MTTD: 4 timed assets {6h, 48h, 12h, 0h} → mean 16.5h, median 9h; 1 with no
// stop signal (unmeasured); out-of-window, non-internet-facing, archived and
// other-tenant assets ignored.
func TestProgramMetrics_MTTDInternetFacing(t *testing.T) {
	f, repo := newPMFixture(t)
	tenant := seedTestTenant(f.ctx, t, f.db)
	noise := seedTestTenant(f.ctx, t, f.db)

	// A1: classified public 6h after first seen.
	f.asset(tenant, "public", false, "active", f.at(-10*pmDay), ptrT(f.at(-10*pmDay+6*pmHour)))

	// A2: exposure still 'unknown' but flagged internet-accessible; the earliest
	// signal is a state-history row 48h after first_seen (a later finding at
	// +10d must not win). History is >30d old so tenant cleanup may delete it.
	a2 := f.asset(tenant, "unknown", true, "active", f.at(-60*pmDay), nil)
	f.exec(`INSERT INTO asset_state_history (tenant_id, asset_id, change_type, field, old_value, new_value, source, changed_at)
		VALUES ($1, $2, 'internet_exposure_changed', 'is_internet_accessible', 'false', 'true', 'system', $3)`,
		tenant.String(), a2.String(), f.at(-60*pmDay+48*pmHour))
	f.finding(tenant, &a2, "new", f.at(-50*pmDay), nil, nil)

	// A3: no classification stamp; first finding at +12h beats the exposure
	// event at +24h.
	a3 := f.asset(tenant, "public", false, "active", f.at(-20*pmDay), nil)
	f.finding(tenant, &a3, "new", f.at(-20*pmDay+12*pmHour), nil, nil)
	f.exec(`INSERT INTO exposure_events (tenant_id, asset_id, event_type, title, fingerprint, source, first_seen_at)
		VALUES ($1, $2, 'port_open', 'p', $3, 'test', $4)`,
		tenant.String(), a3.String(), "fp-"+a3.String(), f.at(-20*pmDay+24*pmHour))

	// A4: classified before it was first seen → known at discovery → 0h.
	f.asset(tenant, "public", false, "active", f.at(-5*pmDay), ptrT(f.at(-6*pmDay)))

	// A5: internet-facing, no signal at all → unmeasured.
	f.asset(tenant, "public", false, "active", f.at(-3*pmDay), nil)

	// Ignored: first seen outside the window / not internet-facing / archived.
	f.asset(tenant, "public", false, "active", f.at(-200*pmDay), ptrT(f.at(-150*pmDay)))
	a7 := f.asset(tenant, "private", false, "active", f.at(-5*pmDay), nil)
	f.finding(tenant, &a7, "new", f.at(-4*pmDay), nil, nil)
	f.asset(tenant, "public", false, "archived", f.at(-5*pmDay), ptrT(f.at(-1*pmDay)))

	// Other tenant: would add a 1000h sample if leaked.
	f.asset(noise, "public", false, "active", f.at(-50*pmDay), ptrT(f.at(-50*pmDay+1000*pmHour)))

	m, err := repo.GetProgramMetrics(f.ctx, tenant, 90)
	if err != nil {
		t.Fatalf("GetProgramMetrics: %v", err)
	}
	got := m.MTTDInternetFacing
	if got.SampleSize != 4 || got.Unmeasured != 1 {
		t.Fatalf("MTTD sample/unmeasured: want 4/1, got %d/%d", got.SampleSize, got.Unmeasured)
	}
	assertHours(t, "MTTD mean", got.MeanHours, 16.5)
	assertHours(t, "MTTD median", got.MedianHours, 9)
}

// MTTR validated: {72h, 24h, 12h} → mean 36h, median 24h. Unvalidated,
// not-remediated, out-of-window, resolved-before-validation and other-tenant
// findings ignored.
func TestProgramMetrics_MTTRValidated(t *testing.T) {
	f, repo := newPMFixture(t)
	tenant := seedTestTenant(f.ctx, t, f.db)
	noise := seedTestTenant(f.ctx, t, f.db)

	// F1: first reproducing validation 72h before resolution (a later one at
	// 24h before must not be used).
	f1 := f.finding(tenant, nil, "resolved", f.at(-30*pmDay), ptrT(f.at(-5*pmDay)), nil)
	f.evidence(tenant, f1, "detected", f.at(-5*pmDay-72*pmHour))
	f.evidence(tenant, f1, "detected", f.at(-5*pmDay-24*pmHour))

	// F2: verified 24h after validation; an earlier not_detected run is not a
	// confirmation of exploitability.
	f2 := f.finding(tenant, nil, "resolved", f.at(-30*pmDay), ptrT(f.at(-10*pmDay)), nil)
	f.evidence(tenant, f2, "not_detected", f.at(-20*pmDay))
	f.evidence(tenant, f2, "detected", f.at(-10*pmDay-24*pmHour))

	// F8: 12h.
	f8 := f.finding(tenant, nil, "resolved", f.at(-3*pmDay), ptrT(f.at(-1*pmDay)), nil)
	f.evidence(tenant, f8, "detected", f.at(-1*pmDay-12*pmHour))

	// Ignored.
	f3 := f.finding(tenant, nil, "resolved", f.at(-30*pmDay), ptrT(f.at(-2*pmDay)), nil) // never reproduced
	f.evidence(tenant, f3, "not_detected", f.at(-3*pmDay))
	f4 := f.finding(tenant, nil, "false_positive", f.at(-30*pmDay), ptrT(f.at(-2*pmDay)), nil) // not remediation
	f.evidence(tenant, f4, "detected", f.at(-3*pmDay))
	f5 := f.finding(tenant, nil, "resolved", f.at(-300*pmDay), ptrT(f.at(-200*pmDay)), nil) // out of window
	f.evidence(tenant, f5, "detected", f.at(-210*pmDay))
	f6 := f.finding(tenant, nil, "resolved", f.at(-30*pmDay), ptrT(f.at(-3*pmDay)), nil) // validated after fix
	f.evidence(tenant, f6, "detected", f.at(-2*pmDay))
	f7 := f.finding(tenant, nil, "confirmed", f.at(-30*pmDay), nil, nil) // still open
	f.evidence(tenant, f7, "detected", f.at(-3*pmDay))

	fn := f.finding(noise, nil, "resolved", f.at(-30*pmDay), ptrT(f.at(-1*pmDay)), nil)
	f.evidence(noise, fn, "detected", f.at(-1*pmDay-900*pmHour))

	m, err := repo.GetProgramMetrics(f.ctx, tenant, 90)
	if err != nil {
		t.Fatalf("GetProgramMetrics: %v", err)
	}
	got := m.MTTRValidated
	if got.SampleSize != 3 {
		t.Fatalf("MTTR validated sample: want 3, got %d", got.SampleSize)
	}
	assertHours(t, "MTTR validated mean", got.MeanHours, 36)
	assertHours(t, "MTTR validated median", got.MedianHours, 24)
}

// Owner acceptance: accepted 3, missed 1, pending 1, excluded 4 → 75%.
func TestProgramMetrics_OwnerAcceptance(t *testing.T) {
	f, repo := newPMFixture(t)
	tenant := seedTestTenant(f.ctx, t, f.db)
	noise := seedTestTenant(f.ctx, t, f.db)
	u1 := seedGroupsUser(f.ctx, t, f.db, "pm-u1.test")
	u2 := seedGroupsUser(f.ctx, t, f.db, "pm-u2.test")

	pastSLA := ptrT(f.at(-1 * pmDay))
	futureSLA := ptrT(f.at(5 * pmDay))

	// G1 accepted: assignee changed status within the SLA window.
	g1 := f.finding(tenant, nil, "in_progress", f.at(-11*pmDay), nil, pastSLA)
	f.assigned(tenant, g1, &u1, f.at(-10*pmDay))
	f.activity(tenant, g1, u1, "status_changed", f.at(-9*pmDay))

	// G2 missed: only a non-assignee acted in time; the assignee acted after
	// the deadline.
	g2 := f.finding(tenant, nil, "new", f.at(-11*pmDay), nil, pastSLA)
	f.assigned(tenant, g2, &u1, f.at(-10*pmDay))
	f.activity(tenant, g2, u2, "comment_added", f.at(-9*pmDay))
	f.activity(tenant, g2, u1, "comment_added", f.at(-12*pmHour))

	// G3 pending: no action yet, deadline still ahead.
	g3 := f.finding(tenant, nil, "new", f.at(-3*pmDay), nil, futureSLA)
	f.assigned(tenant, g3, &u1, f.at(-2*pmDay))

	// G4 accepted before a future deadline.
	g4 := f.finding(tenant, nil, "new", f.at(-3*pmDay), nil, futureSLA)
	f.assigned(tenant, g4, &u1, f.at(-2*pmDay))
	f.activity(tenant, g4, u1, "comment_added", f.at(-1*pmDay))

	// G5 excluded: no SLA deadline.
	g5 := f.finding(tenant, nil, "new", f.at(-3*pmDay), nil, nil)
	f.assigned(tenant, g5, &u1, f.at(-2*pmDay))

	// G6: u1 reassigned away before acting → excluded; u2 then accepted.
	g6 := f.finding(tenant, nil, "in_progress", f.at(-11*pmDay), nil, pastSLA)
	f.assigned(tenant, g6, &u1, f.at(-10*pmDay))
	f.assigned(tenant, g6, &u2, f.at(-8*pmDay))
	f.activity(tenant, g6, u2, "status_changed", f.at(-7*pmDay))

	// G7 excluded: assigned after the deadline had already passed.
	g7 := f.finding(tenant, nil, "new", f.at(-30*pmDay), nil, ptrT(f.at(-20*pmDay)))
	f.assigned(tenant, g7, &u1, f.at(-10*pmDay))

	// G10 excluded: someone else resolved it before the deadline.
	g10 := f.finding(tenant, nil, "resolved", f.at(-11*pmDay), ptrT(f.at(-9*pmDay)), pastSLA)
	f.assigned(tenant, g10, &u1, f.at(-10*pmDay))

	// Skipped entirely: no assignee recorded / assigned outside the window.
	g8 := f.finding(tenant, nil, "new", f.at(-11*pmDay), nil, pastSLA)
	f.assigned(tenant, g8, nil, f.at(-10*pmDay))
	g9 := f.finding(tenant, nil, "new", f.at(-300*pmDay), nil, ptrT(f.at(-250*pmDay)))
	f.assigned(tenant, g9, &u1, f.at(-260*pmDay))

	// Other tenant: 2 missed assignments that would drop the rate if leaked.
	for range 2 {
		gn := f.finding(noise, nil, "new", f.at(-11*pmDay), nil, pastSLA)
		f.assigned(noise, gn, &u1, f.at(-10*pmDay))
	}

	m, err := repo.GetProgramMetrics(f.ctx, tenant, 90)
	if err != nil {
		t.Fatalf("GetProgramMetrics: %v", err)
	}
	got := m.OwnerAcceptance
	if got.Accepted != 3 || got.Missed != 1 || got.Pending != 1 || got.Excluded != 4 {
		t.Fatalf("owner acceptance: want accepted/missed/pending/excluded 3/1/1/4, got %d/%d/%d/%d",
			got.Accepted, got.Missed, got.Pending, got.Excluded)
	}
	if got.RatePct == nil || math.Abs(*got.RatePct-75) > 1e-9 {
		t.Fatalf("owner acceptance rate: want 75, got %v", got.RatePct)
	}
}

// A tenant with no data: every metric is "not measurable" (nil), never 0 / 100.
func TestProgramMetrics_EmptyTenantIsNotMeasured(t *testing.T) {
	f, repo := newPMFixture(t)
	tenant := seedTestTenant(f.ctx, t, f.db)

	m, err := repo.GetProgramMetrics(f.ctx, tenant, 90)
	if err != nil {
		t.Fatalf("GetProgramMetrics: %v", err)
	}
	if m.PeriodDays != 90 {
		t.Fatalf("period: want 90, got %d", m.PeriodDays)
	}
	for name, d := range map[string]struct {
		mean, median *float64
		n            int
	}{
		"mttd": {m.MTTDInternetFacing.MeanHours, m.MTTDInternetFacing.MedianHours, m.MTTDInternetFacing.SampleSize},
		"mttr": {m.MTTRValidated.MeanHours, m.MTTRValidated.MedianHours, m.MTTRValidated.SampleSize},
	} {
		if d.mean != nil || d.median != nil || d.n != 0 {
			t.Fatalf("%s: want nil/nil/0 on empty tenant, got %v/%v/%d", name, d.mean, d.median, d.n)
		}
	}
	oa := m.OwnerAcceptance
	if oa.RatePct != nil || oa.Accepted+oa.Missed+oa.Pending+oa.Excluded != 0 {
		t.Fatalf("owner acceptance: want nil rate and zero counts, got %+v", oa)
	}

	// Only pending assignments: still undecided → nil, not 0%.
	u := seedGroupsUser(f.ctx, t, f.db, "pm-pending.test")
	g := f.finding(tenant, nil, "new", f.at(-2*pmDay), nil, ptrT(f.at(5*pmDay)))
	f.assigned(tenant, g, &u, f.at(-1*pmDay))
	m, err = repo.GetProgramMetrics(f.ctx, tenant, 90)
	if err != nil {
		t.Fatalf("GetProgramMetrics: %v", err)
	}
	if m.OwnerAcceptance.RatePct != nil || m.OwnerAcceptance.Pending != 1 {
		t.Fatalf("pending-only: want nil rate / 1 pending, got %+v", m.OwnerAcceptance)
	}
}

func TestProgramMetrics_WindowClamp(t *testing.T) {
	f, repo := newPMFixture(t)
	tenant := seedTestTenant(f.ctx, t, f.db)
	for _, days := range []int{0, -5, 366, 100000} {
		m, err := repo.GetProgramMetrics(f.ctx, tenant, days)
		if err != nil {
			t.Fatalf("days=%d: %v", days, err)
		}
		if m.PeriodDays != 90 {
			t.Fatalf("days=%d: want clamped to 90, got %d", days, m.PeriodDays)
		}
	}
}
