package scanwindow

import (
	"context"
	"errors"
	"testing"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/outbox"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	notificationdom "github.com/openctemio/openctem/api/pkg/domain/notification"
	swdom "github.com/openctemio/openctem/api/pkg/domain/scanwindow"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// memPolicies is a tenant-scoped in-memory policy store.
type memPolicies struct{ m map[shared.ID]*swdom.Policy }

func (r *memPolicies) Create(_ context.Context, p *swdom.Policy) error { r.m[p.ID] = p; return nil }
func (r *memPolicies) GetByID(_ context.Context, tenantID, id shared.ID) (*swdom.Policy, error) {
	if p, ok := r.m[id]; ok && p.TenantID == tenantID {
		cp := *p
		return &cp, nil
	}
	return nil, swdom.ErrNotFound
}

func (r *memPolicies) List(_ context.Context, tenantID shared.ID, _ swdom.Filter) ([]*swdom.Policy, error) {
	var out []*swdom.Policy
	for _, p := range r.m {
		if p.TenantID == tenantID {
			out = append(out, p)
		}
	}
	return out, nil
}

func (r *memPolicies) Update(_ context.Context, p *swdom.Policy) error {
	if old, ok := r.m[p.ID]; !ok || old.TenantID != p.TenantID {
		return swdom.ErrNotFound
	}
	r.m[p.ID] = p
	return nil
}

func (r *memPolicies) Delete(_ context.Context, tenantID, id shared.ID) error {
	if p, ok := r.m[id]; !ok || p.TenantID != tenantID {
		return swdom.ErrNotFound
	}
	delete(r.m, id)
	return nil
}

func (r *memPolicies) Count(ctx context.Context, tenantID shared.ID) (int, error) {
	ps, _ := r.List(ctx, tenantID, swdom.Filter{})
	return len(ps), nil
}

type refs struct{ err error }

func (r refs) CheckReferences(context.Context, shared.ID, swdom.Selector) error { return r.err }

type memOverrides struct{ list []*swdom.Override }

func (m *memOverrides) Create(_ context.Context, o *swdom.Override) error {
	m.list = append(m.list, o)
	return nil
}

func (m *memOverrides) GetByID(_ context.Context, tenantID, id shared.ID) (*swdom.Override, error) {
	for _, o := range m.list {
		if o.ID == id && o.TenantID == tenantID {
			return o, nil
		}
	}
	return nil, swdom.ErrOverrideNotFound
}

func (m *memOverrides) ListActive(_ context.Context, tenantID shared.ID, t time.Time) ([]*swdom.Override, error) {
	var out []*swdom.Override
	for _, o := range m.list {
		if o.TenantID == tenantID && o.ActiveAt(t) {
			out = append(out, o)
		}
	}
	return out, nil
}

func (m *memOverrides) ListRecent(_ context.Context, tenantID shared.ID, _ int) ([]*swdom.Override, error) {
	return m.ListActive(context.Background(), tenantID, time.Now())
}

func (m *memOverrides) Revoke(_ context.Context, tenantID, id, by shared.ID, at time.Time) error {
	for _, o := range m.list {
		if o.ID == id && o.TenantID == tenantID && o.RevokedAt == nil {
			o.RevokedAt, o.RevokedBy = &at, &by
			return nil
		}
	}
	return swdom.ErrOverrideNotFound
}

type totp struct {
	err   error
	calls []string
}

func (v *totp) VerifyFreshTOTP(_ context.Context, userID, code string) error {
	v.calls = append(v.calls, userID+":"+code)
	return v.err
}

type audits struct{ actions []auditdom.Action }

func (a *audits) LogEvent(_ context.Context, _ auditapp.AuditContext, e auditapp.AuditEvent) error {
	a.actions = append(a.actions, e.Action)
	return nil
}

type admins []shared.ID

func (a admins) ActiveAdminIDs(context.Context, shared.ID) ([]shared.ID, error) { return a, nil }

type inbox struct {
	got []notificationdom.NotificationParams
}

func (i *inbox) Notify(_ context.Context, p notificationdom.NotificationParams) error {
	i.got = append(i.got, p)
	return nil
}

type channel struct{ got []outbox.EnqueueParams }

func (c *channel) Enqueue(_ context.Context, p outbox.EnqueueParams) error {
	c.got = append(c.got, p)
	return nil
}

type releaser struct{ n int }

func (r *releaser) ReleaseWindowHolds(context.Context, shared.ID) (int64, error) {
	r.n++
	return 0, nil
}

type svcFixture struct {
	svc       *Service
	policies  *memPolicies
	overrides *memOverrides
	totp      *totp
	audit     *audits
	inbox     *inbox
	channel   *channel
	release   *releaser
	tenant    shared.ID
	user      shared.ID
}

func newSvcFixture() *svcFixture {
	f := &svcFixture{policies: &memPolicies{m: map[shared.ID]*swdom.Policy{}}, overrides: &memOverrides{},
		totp: &totp{}, audit: &audits{}, inbox: &inbox{}, channel: &channel{}, release: &releaser{},
		tenant: shared.NewID(), user: shared.NewID()}
	f.svc = NewService(f.policies, refs{}, f.overrides, NewResolver(f.policies, f.overrides), logger.NewNop())
	f.svc.SetAudit(f.audit)
	f.svc.SetTOTP(f.totp)
	f.svc.SetNotifications(admins{shared.NewID(), shared.NewID()}, f.inbox, f.channel)
	f.svc.SetHoldReleaser(f.release)
	f.svc.now = func() time.Time { return mon10 }
	return f
}

func (f *svcFixture) actx() auditapp.AuditContext {
	return auditapp.AuditContext{TenantID: f.tenant.String(), ActorID: f.user.String()}
}

func bizSpec() swdom.Spec {
	return swdom.Spec{Name: "business hours", Kind: swdom.KindAllow, MinTier: 1, Timezone: "Europe/Berlin", Enabled: true,
		Slots: []swdom.Slot{{Days: []int{1, 2, 3, 4, 5}, Start: "09:00", End: "17:00"}}}
}

func TestService_PolicyCRUDIsAuditedAndReleasesHolds(t *testing.T) {
	f := newSvcFixture()
	v, err := f.svc.Create(context.Background(), f.tenant, bizSpec(), f.actx())
	if err != nil {
		t.Fatal(err)
	}
	// Monday 10:00 UTC is 12:00 in Berlin: open until 17:00 CEST (15:00Z).
	if !v.OpenNow || v.NextChange == nil || !v.NextChange.Equal(time.Date(2026, 10, 5, 15, 0, 0, 0, time.UTC)) {
		t.Fatalf("view = %+v", v)
	}
	if _, err := f.svc.Update(context.Background(), f.tenant, v.ID.String(), func(s *swdom.Spec) { s.Enabled = false }, f.actx()); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Delete(context.Background(), f.tenant, v.ID.String(), f.actx()); err != nil {
		t.Fatal(err)
	}
	want := []auditdom.Action{auditdom.ActionScanWindowPolicyCreated, auditdom.ActionScanWindowPolicyUpdated, auditdom.ActionScanWindowPolicyDeleted}
	if len(f.audit.actions) != 3 || f.audit.actions[0] != want[0] || f.audit.actions[1] != want[1] || f.audit.actions[2] != want[2] {
		t.Fatalf("audit = %v", f.audit.actions)
	}
	if f.release.n != 3 {
		t.Fatalf("holds released %d times, want after every change", f.release.n)
	}
}

func TestService_CrossTenantPolicyIsNotFound(t *testing.T) {
	f := newSvcFixture()
	v, _ := f.svc.Create(context.Background(), f.tenant, bizSpec(), f.actx())
	other := shared.NewID()
	if _, err := f.svc.Get(context.Background(), other, v.ID.String()); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("get across tenants: %v", err)
	}
	if _, err := f.svc.Update(context.Background(), other, v.ID.String(), func(*swdom.Spec) {}, f.actx()); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("update across tenants: %v", err)
	}
	if err := f.svc.Delete(context.Background(), other, v.ID.String(), f.actx()); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("delete across tenants: %v", err)
	}
	if _, err := f.svc.CreateOverride(context.Background(), OverrideInput{TenantID: other, UserID: f.user.String(),
		PolicyID: v.ID.String(), Reason: "incident 4711 rescan now", DurationMinutes: 60, TOTPCode: "123456"}, f.actx()); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("override of another tenant's policy: %v", err)
	}
}

func TestService_UnknownSelectorReferenceRefused(t *testing.T) {
	f := newSvcFixture()
	f.svc.refs = refs{err: swdom.ErrUnknownReference}
	spec := bizSpec()
	spec.Selector.AssetGroupIDs = []string{shared.NewID().String()}
	if _, err := f.svc.Create(context.Background(), f.tenant, spec, f.actx()); !errors.Is(err, swdom.ErrUnknownReference) {
		t.Fatalf("create: %v", err)
	}
}

func TestService_OverrideNeedsAFreshCode(t *testing.T) {
	f := newSvcFixture()
	in := OverrideInput{TenantID: f.tenant, UserID: f.user.String(), Reason: "incident 4711 rescan now", DurationMinutes: 60}
	if _, err := f.svc.CreateOverride(context.Background(), in, f.actx()); !errors.Is(err, swdom.ErrOverrideBadCode) {
		t.Fatalf("no code: %v", err)
	}
	in.TOTPCode = "000000"
	f.totp.err = swdom.ErrOverrideBadCode
	if _, err := f.svc.CreateOverride(context.Background(), in, f.actx()); !errors.Is(err, swdom.ErrOverrideBadCode) {
		t.Fatalf("wrong code: %v", err)
	}
	if f.audit.actions[len(f.audit.actions)-1] != auditdom.ActionScanWindowOverrideRefused {
		t.Fatalf("a refused code is audited: %v", f.audit.actions)
	}
	f.totp.err = swdom.ErrOverrideNeedsTOTP
	if _, err := f.svc.CreateOverride(context.Background(), in, f.actx()); !errors.Is(err, swdom.ErrOverrideNeedsTOTP) {
		t.Fatalf("no authenticator: %v", err)
	}
	f.svc.totp = nil
	if _, err := f.svc.CreateOverride(context.Background(), in, f.actx()); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("unwired second factor must refuse: %v", err)
	}
	if len(f.overrides.list) != 0 {
		t.Fatal("an override was stored without a valid code")
	}
}

func TestService_OverrideAuditedNotifiedAndBounded(t *testing.T) {
	f := newSvcFixture()
	v, _ := f.svc.Create(context.Background(), f.tenant, bizSpec(), f.actx())
	o, err := f.svc.CreateOverride(context.Background(), OverrideInput{TenantID: f.tenant, UserID: f.user.String(),
		PolicyID: v.ID.String(), Reason: "incident 4711 rescan now", DurationMinutes: 90, TOTPCode: "123456"}, f.actx())
	if err != nil {
		t.Fatal(err)
	}
	if !o.EndsAt.Equal(mon10.Add(90*time.Minute)) || o.PolicyName != "business hours" || f.totp.calls[0] != f.user.String()+":123456" {
		t.Fatalf("override = %+v, totp calls %v", o, f.totp.calls)
	}
	if f.audit.actions[len(f.audit.actions)-1] != auditdom.ActionScanWindowOverrideStarted {
		t.Fatalf("audit = %v", f.audit.actions)
	}
	if len(f.inbox.got) != 2 || f.inbox.got[0].NotificationType != notificationdom.TypeScanWindowOverride || len(f.channel.got) != 1 {
		t.Fatalf("notified %d admins, %d channel events", len(f.inbox.got), len(f.channel.got))
	}
	if err := f.svc.RevokeOverride(context.Background(), f.tenant, o.ID.String(), f.user.String(), f.actx()); err != nil {
		t.Fatal(err)
	}
	if f.audit.actions[len(f.audit.actions)-1] != auditdom.ActionScanWindowOverrideRevoked {
		t.Fatalf("revoke audit = %v", f.audit.actions)
	}
	for _, d := range []int{5, 1441} {
		if _, err := f.svc.CreateOverride(context.Background(), OverrideInput{TenantID: f.tenant, UserID: f.user.String(),
			Reason: "incident 4711 rescan now", DurationMinutes: d, TOTPCode: "123456"}, f.actx()); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("duration %d accepted: %v", d, err)
		}
	}
	if _, err := f.svc.CreateOverride(context.Background(), OverrideInput{TenantID: f.tenant, UserID: f.user.String(),
		PolicyID: "program:" + shared.NewID().String(), Reason: "incident 4711 rescan now", DurationMinutes: 60, TOTPCode: "123456"}, f.actx()); !errors.Is(err, swdom.ErrOverrideProgram) {
		t.Fatalf("a program window must never be overridable: %v", err)
	}
}

type previewAssets struct {
	total  int
	assets []swdom.TargetAsset
}

func (p previewAssets) MatchingAssets(context.Context, shared.ID, swdom.Selector, int) (int, []swdom.TargetAsset, error) {
	return p.total, p.assets, nil
}

func (p previewAssets) AssetNames(_ context.Context, _ shared.ID, ids []shared.ID) (map[shared.ID]string, error) {
	out := map[shared.ID]string{}
	for _, a := range p.assets {
		for _, id := range ids {
			if a.ID == id.String() {
				out[id] = a.Name
			}
		}
	}
	return out, nil
}

type scopeOf struct {
	full    bool
	visible map[string]bool
}

func (s scopeOf) FullDataCaller(context.Context, shared.ID) (bool, error) { return s.full, nil }
func (s scopeOf) FilterForCaller(context.Context, shared.ID, []shared.ID) (func(shared.ID) bool, error) {
	return func(id shared.ID) bool { return s.visible[id.String()] }, nil
}

// The preview and the evaluation of assets show only what the caller may
// see; an asset out of the caller's data scope is not found.
func TestService_PreviewAndEvaluateRespectDataScope(t *testing.T) {
	f := newSvcFixture()
	a, b := shared.NewID(), shared.NewID()
	assets := previewAssets{total: 2, assets: []swdom.TargetAsset{{ID: a.String(), Name: "a.example"}, {ID: b.String(), Name: "b.example"}}}
	f.svc.SetAssets(assets, scopeOf{visible: map[string]bool{a.String(): true}})
	spec := bizSpec()
	spec.Selector.Tags = []string{"prod"}
	p, err := f.svc.PreviewPolicy(context.Background(), f.tenant, spec)
	if err != nil {
		t.Fatal(err)
	}
	if p.MatchedAssets != 1 || len(p.Assets) != 1 || p.Assets[0].Name != "a.example" || !p.Truncated || len(p.Openings) == 0 {
		t.Fatalf("restricted preview = %+v", p)
	}
	if _, err := f.svc.Evaluate(context.Background(), EvaluateInput{TenantID: f.tenant, AssetIDs: []string{b.String()}}); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("evaluate an asset out of scope: %v", err)
	}
	out, err := f.svc.Evaluate(context.Background(), EvaluateInput{TenantID: f.tenant, AssetIDs: []string{a.String()}, Targets: []string{"c.example"}})
	if err != nil || len(out) != 2 || out[1].AssetID != a.String() || out[1].Target != "a.example" {
		t.Fatalf("evaluate = %+v, %v", out, err)
	}
	f.svc.SetAssets(assets, scopeOf{full: true})
	if p, _ := f.svc.PreviewPolicy(context.Background(), f.tenant, spec); p.MatchedAssets != 2 || p.Truncated {
		t.Fatalf("full-access preview = %+v", p)
	}
}
