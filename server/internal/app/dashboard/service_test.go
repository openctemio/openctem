package dashboard

import (
	"context"
	"errors"
	"testing"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	domain "github.com/openctemio/openctem/api/pkg/domain/dashboard"
	"github.com/openctemio/openctem/api/pkg/domain/limits"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
)

type limitFn func() (int, error)

func (f limitFn) Limit(context.Context, shared.ID, limits.Key) (int, error) { return f() }

type memSettings struct{ ds tenantdom.DashboardSettings }

func (m *memSettings) GetDashboardSettings(context.Context, string) (*tenantdom.DashboardSettings, error) {
	d := m.ds
	return &d, nil
}

func (m *memSettings) UpdateDashboardSettings(_ context.Context, _ string, ds tenantdom.DashboardSettings, _ auditapp.AuditContext) (*tenantdom.DashboardSettings, error) {
	m.ds = ds
	return &ds, nil
}

func caller() Caller {
	return Caller{TenantID: shared.NewID(), UserID: shared.NewID(), Has: func(string) bool { return false }}
}

func TestRefreshFloor(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name  string
		limit limitFn
		want  time.Duration
		err   bool
	}{
		{"unset", func() (int, error) { return limits.Unlimited, nil }, domain.BaseRefreshFloor, false},
		{"below base", func() (int, error) { return 1, nil }, domain.BaseRefreshFloor, false},
		{"plan floor", func() (int, error) { return 60, nil }, time.Hour, false},
		{"unreadable refuses", func() (int, error) { return 0, errors.New("down") }, 0, true},
	}
	for _, tc := range cases {
		s := NewService(nil, nil)
		s.SetLimitReader(tc.limit)
		got, err := s.RefreshFloor(ctx, shared.NewID())
		if (err != nil) != tc.err || got != tc.want {
			t.Errorf("%s: %v %v, want %v err=%v", tc.name, got, err, tc.want, tc.err)
		}
	}
}

func TestSettings(t *testing.T) {
	ctx := context.Background()
	st := &memSettings{}
	s := NewService(nil, nil)
	s.SetSettingsStore(st)
	s.SetLimitReader(limitFn(func() (int, error) { return 15, nil }))
	c := caller()

	got, err := s.GetSettings(ctx, c)
	if err != nil || got.DefaultInterval != domain.DefaultInterval || got.FloorMinutes != 15 {
		t.Fatalf("defaults = %+v %v", got, err)
	}
	if _, err := s.UpdateSettings(ctx, c, ScheduleInput{Interval: domain.Interval5m}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("below the floor: %v", err)
	}
	if _, err := s.UpdateSettings(ctx, c, ScheduleInput{}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("empty default: %v", err)
	}
	if got, err := s.UpdateSettings(ctx, c, ScheduleInput{Interval: domain.Interval6h}); err != nil || got.DefaultInterval != domain.Interval6h {
		t.Fatalf("6h = %+v %v", got, err)
	}
	s.SetLimitReader(limitFn(func() (int, error) { return 0, errors.New("down") }))
	if _, err := s.UpdateSettings(ctx, c, ScheduleInput{Interval: domain.Interval1h}); err == nil || errors.Is(err, shared.ErrValidation) {
		t.Fatalf("unreadable floor must refuse as an internal error: %v", err)
	}
}

func TestOrgOperationsNeedPermissions(t *testing.T) {
	ctx := context.Background()
	s := NewService(nil, nil) // the repository is never reached
	c := caller()
	if _, err := s.ListOrg(ctx, c); !errors.Is(err, shared.ErrForbidden) {
		t.Errorf("list: %v", err)
	}
	if _, err := s.CreateOrg(ctx, c, CreateInput{Name: "x"}); !errors.Is(err, shared.ErrForbidden) {
		t.Errorf("create: %v", err)
	}
	id := shared.NewID().String()
	if err := s.DeleteOrg(ctx, c, id); !errors.Is(err, shared.ErrForbidden) {
		t.Errorf("delete: %v", err)
	}
	if _, err := s.DuplicateOrg(ctx, c, id); !errors.Is(err, shared.ErrForbidden) {
		t.Errorf("duplicate: %v", err)
	}
	// A viewer is still not a manager.
	c.Has = func(p string) bool { return p == "dashboards:org:view" }
	if err := s.SetOrgDefault(ctx, c, id); !errors.Is(err, shared.ErrForbidden) {
		t.Errorf("viewer sets default: %v", err)
	}
	if _, err := s.SetOrgAudience(ctx, c, id, nil); !errors.Is(err, shared.ErrForbidden) {
		t.Errorf("viewer sets audience: %v", err)
	}
	// No user (an organization API key) is refused.
	if _, err := s.ListOrg(ctx, Caller{TenantID: shared.NewID(), Has: func(string) bool { return true }}); !errors.Is(err, shared.ErrForbidden) {
		t.Errorf("user-less caller: %v", err)
	}
}

func TestFreeName(t *testing.T) {
	taken := map[string]bool{"A": true, "A (2)": true}
	if n := freeName("A", taken); n != "A (3)" {
		t.Fatalf("freeName = %q", n)
	}
	if n := freeName("B", taken); n != "B" {
		t.Fatalf("freeName = %q", n)
	}
}
