package scanpolicy

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/scangov"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// memShared is a Repository with the shared sensor store.
type memShared struct {
	setting   *SharedSensorsSetting
	version   int
	failGet   bool
	access    map[shared.ID]string
	failAcc   bool
	setCalled bool
}

func (m *memShared) GetDefault(context.Context) (scangov.PlatformPolicy, int, error) {
	return "", 0, ErrNotFound
}
func (m *memShared) SetDefault(context.Context, scangov.PlatformPolicy, int, shared.ID, time.Time) (int, error) {
	return 0, nil
}
func (m *memShared) GetOverride(context.Context, shared.ID) (*scangov.PlatformPolicy, error) {
	return nil, nil
}
func (m *memShared) SetOverride(context.Context, shared.ID, *scangov.PlatformPolicy) error {
	return nil
}
func (m *memShared) ListFollowingDefault(context.Context) ([]shared.ID, error) { return nil, nil }

func (m *memShared) GetSharedSensors(context.Context) (SharedSensorsSetting, int, error) {
	if m.failGet {
		return SharedSensorsSetting{}, 0, errors.New("db down")
	}
	if m.setting == nil {
		return SharedSensorsSetting{}, 0, ErrNotFound
	}
	return *m.setting, m.version, nil
}

func (m *memShared) SetSharedSensors(_ context.Context, v SharedSensorsSetting, expected int, _ string, _ time.Time) (int, error) {
	m.setCalled = true
	if expected != m.version {
		return 0, ErrVersionConflict
	}
	m.setting, m.version = &v, m.version+1
	return m.version, nil
}

func (m *memShared) GetSharedSensorsAccess(_ context.Context, id shared.ID) (string, error) {
	if m.failAcc {
		return "", errors.New("db down")
	}
	d, ok := m.access[id]
	if !ok {
		return "", shared.ErrNotFound
	}
	return d, nil
}

func (m *memShared) SetSharedSensorsAccess(_ context.Context, id shared.ID, d string) error {
	if _, ok := m.access[id]; !ok {
		return shared.ErrNotFound
	}
	m.access[id] = d
	return nil
}

type optOuts struct {
	out  map[shared.ID]bool
	fail bool
}

func (o optOuts) SharedSensorsOptedOut(_ context.Context, id shared.ID) (bool, error) {
	if o.fail {
		return false, errors.New("db down")
	}
	return o.out[id], nil
}

type auditRows struct{ rows []*admin.AuditLog }

func (a *auditRows) Create(_ context.Context, l *admin.AuditLog) error {
	a.rows = append(a.rows, l)
	return nil
}

// The rollout gate refuses every organization whatever the settings say,
// with its own reason, never an edition.
func TestSharedSensorsAllowed_GateClosed(t *testing.T) {
	if sharedSensorsReady {
		t.Skip("the rollout gate is open")
	}
	tid := shared.NewID()
	repo := &memShared{setting: &SharedSensorsSetting{Enabled: true, NewOrgs: boolp(true)}, version: 1,
		access: map[shared.ID]string{tid: SharedSensorsAllow}}
	svc := NewService(repo, nil, nil, nil, nil, logger.NewNop())
	svc.SetSharedSensorsOptOut(optOuts{})
	if ok, why := svc.sharedSensorsPolicy(context.Background(), tid); !ok {
		t.Fatalf("precondition: the layers allow, got %q", why)
	}
	ok, why := svc.SharedSensorsAllowed(context.Background(), tid)
	if ok || why != ReasonSharedSensorsNotReady {
		t.Fatalf("gate closed: %v %q", ok, why)
	}
	if SharedSensorsReady() {
		t.Fatal("SharedSensorsReady must report the closed gate")
	}
}

// The three layers of RFC-100 §5 beneath the gate.
func TestSharedSensorsPolicy_Layers(t *testing.T) {
	ctx := context.Background()
	tid := shared.NewID()
	on := func(newOrgs bool) *SharedSensorsSetting {
		return &SharedSensorsSetting{Enabled: true, NewOrgs: &newOrgs}
	}
	cases := []struct {
		name    string
		setting *SharedSensorsSetting
		failGet bool
		access  string
		failAcc bool
		optOut  bool
		failOpt bool
		noOpt   bool
		want    bool
		reason  string
	}{
		{name: "nothing stored: off", setting: nil, reason: ReasonSharedSensorsOff},
		{name: "switch off", setting: &SharedSensorsSetting{Enabled: false, NewOrgs: boolp(true)}, access: SharedSensorsAllow, reason: ReasonSharedSensorsOff},
		{name: "setting unreadable", failGet: true, reason: ReasonSharedSensorsUnavailable},
		{name: "default on, no decision", setting: on(true), want: true},
		{name: "default off, no decision", setting: on(false), reason: ReasonSharedSensorsNotEnabled},
		{name: "default off, allowed", setting: on(false), access: SharedSensorsAllow, want: true},
		{name: "default unset, no decision: refused", setting: &SharedSensorsSetting{Enabled: true}, reason: ReasonSharedSensorsNotEnabled},
		{name: "default unset, allowed", setting: &SharedSensorsSetting{Enabled: true}, access: SharedSensorsAllow, want: true},
		{name: "default on, denied: deny wins", setting: on(true), access: SharedSensorsDeny, reason: ReasonSharedSensorsNotEnabled},
		{name: "decision unreadable", setting: on(true), failAcc: true, reason: ReasonSharedSensorsUnavailable},
		{name: "unknown decision value", setting: on(true), access: "maybe", reason: ReasonSharedSensorsUnavailable},
		{name: "opted out", setting: on(true), access: SharedSensorsAllow, optOut: true, reason: ReasonSharedSensorsOptedOut},
		{name: "opt-out unreadable", setting: on(true), failOpt: true, reason: ReasonSharedSensorsUnavailable},
		{name: "opt-out not wired", setting: on(true), noOpt: true, reason: ReasonSharedSensorsUnavailable},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			repo := &memShared{setting: c.setting, version: 1, failGet: c.failGet, failAcc: c.failAcc,
				access: map[shared.ID]string{tid: c.access}}
			svc := NewService(repo, nil, nil, nil, nil, logger.NewNop())
			if !c.noOpt {
				svc.SetSharedSensorsOptOut(optOuts{out: map[shared.ID]bool{tid: c.optOut}, fail: c.failOpt})
			}
			ok, why := svc.sharedSensorsPolicy(ctx, tid)
			if ok != c.want || why != c.reason {
				t.Fatalf("got %v %q, want %v %q", ok, why, c.want, c.reason)
			}
		})
	}

	// Another organization's decision never applies: tenant B is denied,
	// tenant A (no decision, default on) is allowed.
	other := shared.NewID()
	repo := &memShared{setting: on(true), version: 1, access: map[shared.ID]string{tid: "", other: SharedSensorsDeny}}
	svc := NewService(repo, nil, nil, nil, nil, logger.NewNop())
	svc.SetSharedSensorsOptOut(optOuts{out: map[shared.ID]bool{}})
	if ok, _ := svc.sharedSensorsPolicy(ctx, tid); !ok {
		t.Error("organization A refused by B's deny")
	}
	if ok, _ := svc.sharedSensorsPolicy(ctx, other); ok {
		t.Error("organization B allowed despite its deny")
	}
	// An unknown organization is refused.
	if ok, why := svc.sharedSensorsPolicy(ctx, shared.NewID()); ok || why != ReasonSharedSensorsUnavailable {
		t.Errorf("unknown organization: %v %q", ok, why)
	}
}

func TestUpdateSharedSensors(t *testing.T) {
	ctx := context.Background()
	repo := &memShared{access: map[shared.ID]string{}}
	audit := &auditRows{}
	svc := NewService(repo, audit, nil, nil, nil, logger.NewNop())
	actor, _ := admin.NewAdminUser("root@platform.test", "Root", admin.AdminRoleSuperAdmin, nil)

	// Defaults before anything is stored: off, and no default for
	// organizations without a decision (unset refuses them).
	if v, ver, err := svc.SharedSensorsSetting(ctx); err != nil || v != DefaultSharedSensorsSetting() || ver != 0 ||
		v.Enabled || v.NewOrgs != nil {
		t.Fatalf("defaults: %+v %d %v", v, ver, err)
	}
	// A reason is required.
	if _, err := svc.UpdateSharedSensors(ctx, SharedSensorsSetting{NewOrgs: boolp(false)}, 0, Change{Actor: actor}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("no reason: %v", err)
	}
	// Turning the switch on without choosing new_orgs in the same action is
	// refused (never an implicit default), whatever the gate; nothing is
	// written or audited.
	if _, err := svc.UpdateSharedSensors(ctx, SharedSensorsSetting{Enabled: true}, 0, Change{Actor: actor, Reason: "go live"}); !errors.Is(err, ErrNewOrgsChoiceRequired) ||
		!errors.Is(err, shared.ErrValidation) || repo.setCalled || len(audit.rows) != 0 {
		t.Fatalf("switch on without a choice: %v set=%v audit=%d", err, repo.setCalled, len(audit.rows))
	}
	if !sharedSensorsReady {
		// Turning the switch on is refused while the gate is closed, and
		// nothing is written or audited.
		_, err := svc.UpdateSharedSensors(ctx, SharedSensorsSetting{Enabled: true, NewOrgs: boolp(true)}, 0, Change{Actor: actor, Reason: "go live"})
		if !errors.Is(err, ErrSharedSensorsNotReady) || !errors.Is(err, shared.ErrConflict) || repo.setCalled || len(audit.rows) != 0 {
			t.Fatalf("switch on with the gate closed: %v set=%v audit=%d", err, repo.setCalled, len(audit.rows))
		}
	}
	// The default for new organizations may change; audited critical.
	v, err := svc.UpdateSharedSensors(ctx, SharedSensorsSetting{Enabled: false, NewOrgs: boolp(false)}, 0, Change{Actor: actor, Reason: "opt in per organization"})
	if err != nil || v != 1 {
		t.Fatalf("new_orgs off: %d %v", v, err)
	}
	if len(audit.rows) != 1 || audit.rows[0].Action != ActionSharedSensorsChanged {
		t.Fatalf("audit: %+v", audit.rows)
	}
	// A stale version is refused.
	if _, err := svc.UpdateSharedSensors(ctx, SharedSensorsSetting{NewOrgs: boolp(true)}, 0, Change{Actor: actor, Reason: "x"}); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("stale version: %v", err)
	}
}

func TestUpdateSharedSensorsAccess(t *testing.T) {
	ctx := context.Background()
	tid := shared.NewID()
	repo := &memShared{access: map[shared.ID]string{tid: ""}}
	audit := &auditRows{}
	svc := NewService(repo, audit, nil, nil, nil, logger.NewNop())
	actor, _ := admin.NewAdminUser("root@platform.test", "Root", admin.AdminRoleSuperAdmin, nil)

	if err := svc.UpdateSharedSensorsAccess(ctx, tid, "maybe", Change{Actor: actor, Reason: "x"}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("bad decision: %v", err)
	}
	if err := svc.UpdateSharedSensorsAccess(ctx, tid, SharedSensorsDeny, Change{Actor: actor}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("no reason: %v", err)
	}
	if err := svc.UpdateSharedSensorsAccess(ctx, tid, SharedSensorsDeny, Change{Actor: actor, Reason: "data residency"}); err != nil {
		t.Fatal(err)
	}
	if repo.access[tid] != SharedSensorsDeny || len(audit.rows) != 1 || audit.rows[0].Action != ActionSharedSensorsAccessChanged {
		t.Fatalf("deny not stored or audited: %q %d", repo.access[tid], len(audit.rows))
	}
	if err := svc.UpdateSharedSensorsAccess(ctx, shared.NewID(), SharedSensorsAllow, Change{Actor: actor, Reason: "x"}); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("unknown organization: %v", err)
	}
}

func boolp(b bool) *bool { return &b }
