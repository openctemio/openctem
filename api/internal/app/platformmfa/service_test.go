package platformmfa

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	cst "github.com/openctemio/openctem/api/internal/app/consolesetting/consolesettingtest"
	"github.com/openctemio/openctem/api/pkg/domain/platformsetting"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

func newSvc(repo *cst.Repo, managed bool, env string) (*Service, *cst.Audit) {
	audit := &cst.Audit{}
	return NewService(repo, cst.Recorder(audit, &cst.Notifier{}), managed, env), audit
}

func seedMigration(repo *cst.Repo, at time.Time) {
	raw, _ := json.Marshal(map[string]any{"floor": "none", "effective_from": at.UTC().Format(time.RFC3339)})
	repo.Rows[SettingKey] = platformsetting.State{Value: raw, Version: 1, Source: platformsetting.SourceMigration, UpdatedAt: at}
}

// Defaults: a fresh install and a managed service start at admins, the
// environment value wins when valid; an upgraded self-managed install keeps
// none (with a recommendation); a managed service ignores that seeded none
// and keeps only its time as the start of the grace period.
func TestDefaultsAndUpgradeSeed(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		env  string
		want tenant.MFAFloor
	}{{"", tenant.MFAFloorAdmins}, {"everyone", tenant.MFAFloorEveryone}, {"none", tenant.MFAFloorNone}, {"bogus", tenant.MFAFloorAdmins}} {
		svc, _ := newSvc(cst.NewRepo(), false, tc.env)
		p, err := svc.Policy(ctx)
		if err != nil || p.Floor != tc.want || p.GraceExistingDays != 14 || p.GraceNewDays != 7 {
			t.Errorf("env %q: %+v err %v", tc.env, p, err)
		}
	}

	upgraded := time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC)
	repo := cst.NewRepo()
	seedMigration(repo, upgraded)
	self, _ := newSvc(repo, false, "")
	got, _ := self.Get(ctx)
	if got.Floor != tenant.MFAFloorNone || got.Source != SourceMigration || !got.RecommendRaise {
		t.Fatalf("upgraded self-managed: %+v", got)
	}
	managed, _ := newSvc(repo, true, "")
	got, _ = managed.Get(ctx)
	if got.Floor != tenant.MFAFloorAdmins || got.Source != SourceDefault || got.RecommendRaise || !got.EffectiveFrom.Equal(upgraded) {
		t.Fatalf("managed with a seeded row: %+v", got)
	}
}

// A person covered only by the floor is due at the later of effective_from
// plus 14 days and account creation plus 7 days.
func TestDueAt(t *testing.T) {
	from := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	p := Policy{Floor: tenant.MFAFloorAdmins, GraceExistingDays: 14, GraceNewDays: 7, EffectiveFrom: from}
	old := from.AddDate(-1, 0, 0)
	if got := p.DueAt(old); !got.Equal(from.AddDate(0, 0, 14)) {
		t.Fatalf("existing member due %v", got)
	}
	fresh := from.AddDate(0, 0, 10)
	if got := p.DueAt(fresh); !got.Equal(fresh.AddDate(0, 0, 7)) {
		t.Fatalf("new account due %v", got)
	}
	noAnchor := Policy{GraceExistingDays: 14, GraceNewDays: 7}
	if got := noAnchor.DueAt(old); !got.Equal(old.AddDate(0, 0, 7)) {
		t.Fatalf("without effective_from only the account grace applies, got %v", got)
	}
}

func TestUpdateGuardsAndGraceStart(t *testing.T) {
	ctx := context.Background()
	repo := cst.NewRepo()
	svc, audit := newSvc(repo, false, "none")
	now := time.Date(2026, 12, 1, 9, 0, 0, 0, time.UTC)
	svc.now = func() time.Time { return now }

	if _, err := svc.Update(ctx, nil, "admins", nil, nil, "r", 0, "", ""); !errors.Is(err, ErrNoActor) {
		t.Fatalf("no actor: %v", err)
	}
	if _, err := svc.Update(ctx, cst.SuperAdmin(t), "most", nil, nil, "r", 0, "", ""); !errors.Is(err, ErrInvalidFloor) {
		t.Fatalf("bad floor: %v", err)
	}
	bad := 365
	if _, err := svc.Update(ctx, cst.SuperAdmin(t), "admins", &bad, nil, "r", 0, "", ""); !errors.Is(err, ErrInvalidGrace) {
		t.Fatalf("bad grace: %v", err)
	}
	if _, err := svc.Update(ctx, cst.SuperAdmin(t), "admins", nil, nil, " ", 0, "", ""); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("no reason: %v", err)
	}

	got, err := svc.Update(ctx, cst.SuperAdmin(t), "admins", nil, nil, "launch policy", 0, "", "")
	if err != nil || got.Floor != tenant.MFAFloorAdmins || !got.EffectiveFrom.Equal(now) {
		t.Fatalf("raise: %+v %v", got, err)
	}
	// A change that does not raise keeps the earlier start.
	svc.now = func() time.Time { return now.AddDate(0, 0, 30) }
	g := 3
	got, err = svc.Update(ctx, cst.SuperAdmin(t), "admins", &g, nil, "shorter grace", got.Version, "", "")
	if err != nil || !got.EffectiveFrom.Equal(now) || got.GraceExistingDays != 3 {
		t.Fatalf("same floor: %+v %v", got, err)
	}
	// Raising again starts a new grace period.
	got, err = svc.Update(ctx, cst.SuperAdmin(t), "everyone", nil, nil, "everyone", got.Version, "", "")
	if err != nil || !got.EffectiveFrom.Equal(now.AddDate(0, 0, 30)) {
		t.Fatalf("raise again: %+v %v", got, err)
	}
	if len(audit.Entries) != 3 || audit.Entries[0].Action != ActionChanged {
		t.Fatalf("audit entries = %d", len(audit.Entries))
	}
	if _, err := svc.Update(ctx, cst.SuperAdmin(t), "none", nil, nil, "x", 1, "", ""); !errors.Is(err, platformsetting.ErrVersionConflict) {
		t.Fatalf("stale version: %v", err)
	}
}

// A stored value that cannot be understood is an error, never "none".
func TestUnreadableIsAnError(t *testing.T) {
	repo := cst.NewRepo()
	repo.Rows[SettingKey] = platformsetting.State{Value: json.RawMessage(`{"floor":"sometimes"}`), Version: 1, Source: platformsetting.SourceConsole}
	svc, _ := newSvc(repo, false, "")
	if _, err := svc.Policy(context.Background()); err == nil {
		t.Fatal("an unknown stored floor must be an error")
	}
}
