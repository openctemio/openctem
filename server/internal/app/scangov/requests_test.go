package scangov

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scangov"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// --- fakes ---

type memRepo struct {
	mu   sync.Mutex
	rows []*scangov.Request
}

func clone(r *scangov.Request) *scangov.Request {
	c := *r
	c.Approvals = slices.Clone(r.Approvals)
	return &c
}

func (m *memRepo) Create(_ context.Context, r *scangov.Request) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r.Status == scangov.StatusPending {
		for _, x := range m.rows {
			if x.ScanID == r.ScanID && x.Status == scangov.StatusPending {
				return scangov.ErrNotPending
			}
		}
	}
	m.rows = append(m.rows, clone(r))
	return nil
}

func (m *memRepo) Update(_ context.Context, r *scangov.Request, expect scangov.Status) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, x := range m.rows {
		if x.TenantID == r.TenantID && x.ID == r.ID {
			if x.Status != expect {
				return false, nil
			}
			m.rows[i] = clone(r)
			return true, nil
		}
	}
	return false, nil
}

func (m *memRepo) find(f func(*scangov.Request) bool) *scangov.Request {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := len(m.rows) - 1; i >= 0; i-- {
		if f(m.rows[i]) {
			return clone(m.rows[i])
		}
	}
	return nil
}

func (m *memRepo) Get(_ context.Context, t, id shared.ID) (*scangov.Request, error) {
	if r := m.find(func(r *scangov.Request) bool { return r.TenantID == t && r.ID == id }); r != nil {
		return r, nil
	}
	return nil, shared.ErrNotFound
}

func (m *memRepo) Pending(_ context.Context, t, s shared.ID) (*scangov.Request, error) {
	return m.find(func(r *scangov.Request) bool {
		return r.TenantID == t && r.ScanID == s && r.Status == scangov.StatusPending
	}), nil
}

func (m *memRepo) ApprovedFor(_ context.Context, t, s shared.ID, d string) (*scangov.Request, error) {
	return m.find(func(r *scangov.Request) bool {
		return r.TenantID == t && r.ScanID == s && r.Status == scangov.StatusApproved && r.Digest == d
	}), nil
}

func (m *memRepo) LastApproved(_ context.Context, t, s shared.ID) (*scangov.Request, error) {
	return m.find(func(r *scangov.Request) bool {
		return r.TenantID == t && r.ScanID == s && r.Status == scangov.StatusApproved && !r.Emergency
	}), nil
}

func (m *memRepo) SupersedePending(_ context.Context, t, s shared.ID, keep string, _ time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.rows {
		if r.TenantID == t && r.ScanID == s && r.Status == scangov.StatusPending && r.Digest != keep {
			r.Status = scangov.StatusSuperseded
		}
	}
	return nil
}

func (m *memRepo) Consume(_ context.Context, t, id shared.ID, now time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.rows {
		if r.TenantID == t && r.ID == id && r.ConsumedAt == nil {
			r.ConsumedAt = &now
			return true, nil
		}
	}
	return false, nil
}

func (m *memRepo) MarkReminded(_ context.Context, t, id shared.ID, now time.Time, iv time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.rows {
		if r.TenantID == t && r.ID == id {
			if r.RemindedAt != nil && now.Sub(*r.RemindedAt) < iv {
				return false, nil
			}
			r.RemindedAt = &now
			return true, nil
		}
	}
	return false, nil
}

func (m *memRepo) ExpireOverdue(context.Context, shared.ID, time.Time) (int, error) { return 0, nil }

func (m *memRepo) List(_ context.Context, f scangov.ListFilter) ([]*scangov.Request, int, error) {
	var out []*scangov.Request
	for _, r := range m.rows {
		if r.TenantID == f.TenantID {
			out = append(out, clone(r))
		}
	}
	return out, len(out), nil
}

func (m *memRepo) LatestByScans(context.Context, shared.ID, []shared.ID) (map[shared.ID]*scangov.Request, error) {
	return nil, nil
}

type fixedModes struct {
	m scangov.Mode
	p scangov.PlatformPolicy
}

func (f *fixedModes) EffectiveMode(context.Context, shared.ID) (scangov.Mode, string, scangov.PlatformPolicy, error) {
	m, src := scangov.Effective(f.m, f.p)
	return m, src, f.p, nil
}

type memSettings struct{ s tenant.ScanGovernanceSettings }

func (m *memSettings) GetScanGovernanceSettings(context.Context, string) (*tenant.ScanGovernanceSettings, error) {
	c := m.s
	return &c, nil
}

func (m *memSettings) UpdateScanGovernanceSettings(_ context.Context, _ string, change func(*tenant.ScanGovernanceSettings) error,
	_ audit.Action, _ string, _ auditapp.AuditContext,
) (*tenant.ScanGovernanceSettings, error) {
	if err := change(&m.s); err != nil {
		return nil, err
	}
	return &m.s, nil
}

type dir []scangov.Approver

func (d dir) ScanApprovers(context.Context, shared.ID) ([]scangov.Approver, error) { return d, nil }

type codeTOTP struct{ used map[string]bool }

func (c *codeTOTP) VerifyFreshTOTP(_ context.Context, user, code string) error {
	if code != "123456" || c.used[user] {
		return errors.New("bad code")
	}
	c.used[user] = true
	return nil
}

type fakeScans struct {
	scans map[shared.ID]*scan.Scan
	facts scangov.Facts
	runs  []string
}

func (f *fakeScans) GovernanceSubject(_ context.Context, t, id shared.ID) (*scan.Scan, scangov.Definition, scangov.Facts, error) {
	sc, ok := f.scans[id]
	if !ok || sc.TenantID != t {
		return nil, scangov.Definition{}, scangov.Facts{}, shared.ErrNotFound
	}
	def, facts, _ := f.GovernanceSubjectOf(context.Background(), sc)
	return sc, def, facts, nil
}

func (f *fakeScans) GovernanceSubjectOf(_ context.Context, sc *scan.Scan) (scangov.Definition, scangov.Facts, error) {
	return scangov.Definition{Targets: sc.Targets, ScanType: "single", ScannerName: sc.ScannerName,
		Intensity: scangov.IntensityName(f.facts.IntensityTier)}, f.facts, nil
}

func (f *fakeScans) RunApproved(_ context.Context, _, id shared.ID, user string) error {
	f.runs = append(f.runs, id.String()+"/"+user)
	return nil
}

const (
	owner  = "11111111-1111-1111-1111-111111111111"
	admin  = "22222222-2222-2222-2222-222222222222"
	admin2 = "33333333-3333-3333-3333-333333333333"
	member = "44444444-4444-4444-4444-444444444444"
)

type rig struct {
	svc   *Service
	repo  *memRepo
	modes *fixedModes
	st    *memSettings
	scans *fakeScans
	tid   shared.ID
	sc    *scan.Scan
}

func newRig(t *testing.T, mode scangov.Mode, approvers dir) *rig {
	t.Helper()
	tid := shared.NewID()
	sc := &scan.Scan{ID: shared.NewID(), TenantID: tid, Name: "prod sweep", Targets: []string{"app.example.com"}, ScannerName: "zap"}
	r := &rig{repo: &memRepo{}, modes: &fixedModes{m: mode, p: scangov.PolicyTenantControlled},
		st:    &memSettings{s: tenant.ScanGovernanceSettings{Mode: mode, Rules: scangov.Preset(scangov.PresetLight)}},
		scans: &fakeScans{scans: map[shared.ID]*scan.Scan{sc.ID: sc}, facts: scangov.Facts{IntensityTier: 2, WidestCIDRPrefix: -1}},
		tid:   tid, sc: sc}
	r.svc = NewService(r.modes, r.st, nil)
	r.svc.SetRequests(r.repo)
	r.svc.SetApprovers(approvers, &codeTOTP{used: map[string]bool{}})
	r.svc.SetScans(r.scans)
	return r
}

func (r *rig) check() error {
	def, facts, _ := r.scans.GovernanceSubjectOf(context.Background(), r.sc)
	return r.svc.CheckRun(context.Background(), r.sc, def, facts, member)
}

func act(u string) Actor { return Actor{UserID: u} }

var team = dir{{UserID: owner, Role: "owner"}, {UserID: admin, Role: "admin"}, {UserID: admin2, Role: "admin"}}

// --- tests ---

func TestGate_OffNeedsNothing(t *testing.T) {
	r := newRig(t, scangov.ModeOff, team)
	if err := r.check(); err != nil {
		t.Fatalf("Off: a run needs no approval: %v", err)
	}
	if _, err := r.svc.Submit(context.Background(), r.tid, r.sc.ID, SubmitInput{Justification: "x"}, act(member)); !errors.Is(err, scangov.ErrGovernanceOff) {
		t.Fatalf("Off: nothing to submit: %v", err)
	}
}

func TestGate_RuleMatchingAndApprovedRuns(t *testing.T) {
	ctx := context.Background()
	r := newRig(t, scangov.ModeOn, team)
	r.scans.facts.IntensityTier = 1
	if err := r.check(); err != nil {
		t.Fatalf("Light: an active scan runs: %v", err)
	}
	r.scans.facts.IntensityTier = 2
	if err := r.check(); !errors.Is(err, scangov.ErrApprovalRequired) {
		t.Fatalf("Light: an intrusive scan needs approval: %v", err)
	}
	if _, err := r.svc.Submit(ctx, r.tid, r.sc.ID, SubmitInput{}, act(member)); err == nil {
		t.Fatal("the Light rule asks a justification")
	}
	req, err := r.svc.Submit(ctx, r.tid, r.sc.ID, SubmitInput{Justification: "quarterly pentest", RunOnApproval: true}, act(member))
	if err != nil {
		t.Fatal(err)
	}
	if err := r.check(); !errors.Is(err, scangov.ErrApprovalPending) {
		t.Fatalf("pending: %v", err)
	}
	if _, err := r.svc.Approve(ctx, r.tid, req.ID, "", act(member)); !errors.Is(err, scangov.ErrOwnRequest) {
		t.Fatalf("the requester never approves: %v", err)
	}
	got, err := r.svc.Approve(ctx, r.tid, req.ID, "ok", act(admin))
	if err != nil || got.Status != scangov.StatusApproved {
		t.Fatalf("approve: %v %+v", err, got)
	}
	if len(r.scans.runs) != 1 || r.scans.runs[0] != r.sc.ID.String()+"/"+member {
		t.Fatalf("run on approval as the requester: %v", r.scans.runs)
	}
	for range 3 {
		if err := r.check(); err != nil {
			t.Fatalf("runs of an approved definition need nothing: %v", err)
		}
	}
	// A change to the definition needs a new approval, with the diff.
	r.sc.Targets = []string{"app.example.com", "*.example.com"}
	if err := r.check(); !errors.Is(err, scangov.ErrApprovalRequired) {
		t.Fatalf("changed definition: %v", err)
	}
	req2, err := r.svc.Submit(ctx, r.tid, r.sc.ID, SubmitInput{Justification: "wider"}, act(member))
	if err != nil || len(req2.Changes) != 1 || req2.Changes[0].Field != "targets" {
		t.Fatalf("re-approval shows the diff: %v %+v", err, req2)
	}
	// Another organization cannot see or decide the request.
	if _, err := r.svc.Approve(ctx, shared.NewID(), req2.ID, "", act(admin)); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant approve: %v", err)
	}
}

func TestGate_StrictNeedsTwoAndRaisesOldApprovals(t *testing.T) {
	ctx := context.Background()
	r := newRig(t, scangov.ModeOn, team)
	req, _ := r.svc.Submit(ctx, r.tid, r.sc.ID, SubmitInput{Justification: "x"}, act(member))
	if _, err := r.svc.Approve(ctx, r.tid, req.ID, "", act(admin)); err != nil {
		t.Fatal(err)
	}
	if err := r.check(); err != nil {
		t.Fatal(err)
	}
	r.modes.m = scangov.ModeStrict
	if err := r.check(); !errors.Is(err, scangov.ErrApprovalRequired) {
		t.Fatalf("Strict: one approval no longer suffices: %v", err)
	}
	req2, err := r.svc.Submit(ctx, r.tid, r.sc.ID, SubmitInput{Justification: "x"}, act(member))
	if err != nil || req2.Evaluation.Approvals != 2 {
		t.Fatalf("strict request: %v %+v", err, req2)
	}
	if _, err := r.svc.Approve(ctx, r.tid, req2.ID, "", act(admin)); err != nil {
		t.Fatal(err)
	}
	if err := r.check(); !errors.Is(err, scangov.ErrApprovalPending) {
		t.Fatalf("one of two: %v", err)
	}
	if _, err := r.svc.Approve(ctx, r.tid, req2.ID, "", act(admin)); !errors.Is(err, scangov.ErrAlreadyApproved) {
		t.Fatalf("the same approver counts once: %v", err)
	}
	if _, err := r.svc.Approve(ctx, r.tid, req2.ID, "", act(admin2)); err != nil {
		t.Fatal(err)
	}
	if err := r.check(); err != nil {
		t.Fatalf("two distinct approvers: %v", err)
	}
}

func TestGate_NamedApproversAndNonApprovers(t *testing.T) {
	ctx := context.Background()
	r := newRig(t, scangov.ModeOn, team)
	r.st.s.Rules[0].Requirement.ApproverUserIDs = []string{admin2}
	req, _ := r.svc.Submit(ctx, r.tid, r.sc.ID, SubmitInput{Justification: "x"}, act(member))
	if _, err := r.svc.Approve(ctx, r.tid, req.ID, "", act(admin)); !errors.Is(err, scangov.ErrNotEligible) {
		t.Fatalf("the rule names another approver: %v", err)
	}
	if _, err := r.svc.Approve(ctx, r.tid, req.ID, "", act("55555555-5555-5555-5555-555555555555")); !errors.Is(err, scangov.ErrNotEligible) {
		t.Fatalf("a non-approver: %v", err)
	}
	if _, err := r.svc.Approve(ctx, r.tid, req.ID, "", act(admin2)); err != nil {
		t.Fatal(err)
	}
}

func TestGate_SoleOwnerSelfApproval(t *testing.T) {
	ctx := context.Background()
	r := newRig(t, scangov.ModeOn, dir{{UserID: owner, Role: "owner"}})
	req, _ := r.svc.Submit(ctx, r.tid, r.sc.ID, SubmitInput{Justification: "x"}, act(owner))
	if _, err := r.svc.SelfApprove(ctx, r.tid, req.ID, "", "123456", act(owner)); err == nil {
		t.Fatal("a reason is required")
	}
	if _, err := r.svc.SelfApprove(ctx, r.tid, req.ID, "only owner", "000000", act(owner)); err == nil {
		t.Fatal("a wrong code")
	}
	got, err := r.svc.SelfApprove(ctx, r.tid, req.ID, "only owner", "123456", act(owner))
	if err != nil || got.Status != scangov.StatusApproved || !got.Approvals[0].Self {
		t.Fatalf("self-approve: %v %+v", err, got)
	}

	// With another approver the owner cannot self-approve.
	r2 := newRig(t, scangov.ModeOn, team)
	req2, _ := r2.svc.Submit(ctx, r2.tid, r2.sc.ID, SubmitInput{Justification: "x"}, act(owner))
	if _, err := r2.svc.SelfApprove(ctx, r2.tid, req2.ID, "r", "123456", act(owner)); !errors.Is(err, scangov.ErrSelfNotAllowed) {
		t.Fatalf("another approver exists: %v", err)
	}
}

func TestGate_EmergencyRunAndRunOnlyValidity(t *testing.T) {
	ctx := context.Background()
	r := newRig(t, scangov.ModeOn, append(team, scangov.Approver{UserID: member, Role: "member"}))
	if _, err := r.svc.Emergency(ctx, r.tid, r.sc.ID, EmergencyInput{Reason: "outage"}, act(member)); !errors.Is(err, scangov.ErrEmergencyNotAdmin) {
		t.Fatalf("a member: %v", err)
	}
	if _, err := r.svc.Emergency(ctx, r.tid, r.sc.ID, EmergencyInput{}, act(admin)); err == nil {
		t.Fatal("a reason is required")
	}
	e, err := r.svc.Emergency(ctx, r.tid, r.sc.ID, EmergencyInput{Reason: "incident", Hours: 2}, act(admin))
	if err != nil || !e.Emergency || len(r.scans.runs) != 1 {
		t.Fatalf("emergency: %v %+v runs %v", err, e, r.scans.runs)
	}
	if err := r.check(); err != nil {
		t.Fatalf("inside the window: %v", err)
	}
	r.svc.SetClock(func() time.Time { return time.Now().Add(3 * time.Hour) })
	if err := r.check(); !errors.Is(err, scangov.ErrApprovalRequired) {
		t.Fatalf("after the window: %v", err)
	}

	// Run-only validity: one run, then a new approval.
	r2 := newRig(t, scangov.ModeOn, team)
	r2.st.s.Rules[0].Requirement.Validity = scangov.ValidityRun
	req, _ := r2.svc.Submit(ctx, r2.tid, r2.sc.ID, SubmitInput{Justification: "x"}, act(member))
	if _, err := r2.svc.Approve(ctx, r2.tid, req.ID, "", act(admin)); err != nil {
		t.Fatal(err)
	}
	if err := r2.check(); err != nil {
		t.Fatalf("first run: %v", err)
	}
	if err := r2.check(); !errors.Is(err, scangov.ErrApprovalRequired) {
		t.Fatalf("second run needs a new approval: %v", err)
	}
}

func TestGate_PlatformForcedMode(t *testing.T) {
	r := newRig(t, scangov.ModeOff, team)
	r.modes.p = scangov.PolicyOn
	if err := r.check(); !errors.Is(err, scangov.ErrApprovalRequired) {
		t.Fatalf("forced on: %v", err)
	}
	if _, err := r.svc.SetMode(context.Background(), r.tid, scangov.ModeOff, "x", auditapp.AuditContext{}); !errors.Is(err, scangov.ErrModeForced) {
		t.Fatalf("the owner cannot go below the forced mode: %v", err)
	}
	r.modes.p = scangov.PolicyOff
	r.modes.m = scangov.ModeStrict
	if err := r.check(); err != nil {
		t.Fatalf("forced off: %v", err)
	}
}

func TestGate_MonitorRulesNeverBlock(t *testing.T) {
	r := newRig(t, scangov.ModeOn, team)
	r.st.s.Rules[0].Monitor = true
	if err := r.check(); err != nil {
		t.Fatalf("monitor mode: %v", err)
	}
}

func TestGate_FailsClosedWithoutStore(t *testing.T) {
	r := newRig(t, scangov.ModeOn, team)
	r.svc.repo = nil
	if err := r.check(); err == nil {
		t.Fatal("no request store: the run must be refused")
	}
}

func TestRemindIsRateLimited(t *testing.T) {
	ctx := context.Background()
	r := newRig(t, scangov.ModeOn, team)
	req, _ := r.svc.Submit(ctx, r.tid, r.sc.ID, SubmitInput{Justification: "x"}, act(member))
	if _, n, err := r.svc.Remind(ctx, r.tid, req.ID, act(member)); err != nil || n != 3 {
		t.Fatalf("remind: %d %v", n, err)
	}
	if _, _, err := r.svc.Remind(ctx, r.tid, req.ID, act(member)); !errors.Is(err, scangov.ErrReminderTooSoon) {
		t.Fatalf("second reminder: %v", err)
	}
}
