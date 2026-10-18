package dashboard

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestKinds(t *testing.T) {
	tid, uid := shared.NewID(), shared.NewID()
	p, err := NewDashboard(tid, uid, "Mine", "", 2, nil)
	if err != nil || p.Kind() != KindPersonal || p.UserID() != uid || p.Origin() != OriginUser {
		t.Fatalf("personal = %+v, %v", p, err)
	}
	o, err := NewOrgDashboard(tid, "CISO", "", 2, []Widget{{WidgetType: "kpi", W: 1, H: 1, Config: map[string]any{"a": 1}}})
	if err != nil || o.Kind() != KindOrganization || !o.UserID().IsZero() {
		t.Fatalf("organization = %+v, %v", o, err)
	}
	// A copy carries the layout only, for the new owner, never the kind.
	c, err := o.CopyFor(uid, "CISO", OriginDuplicated)
	if err != nil {
		t.Fatal(err)
	}
	if c.Kind() != KindPersonal || c.UserID() != uid || c.Origin() != OriginDuplicated || c.IsOrgDefault() || len(c.Widgets()) != 1 {
		t.Fatalf("copy = %+v", c)
	}
	c.Widgets()[0].WidgetType = "changed"
	if o.Widgets()[0].WidgetType != "kpi" {
		t.Fatal("copy shares the widget slice with its source")
	}
}

func TestWidgetConfigCap(t *testing.T) {
	big := map[string]any{"x": strings.Repeat("a", maxWidgetConfigBytes)}
	_, err := NewDashboard(shared.NewID(), shared.NewID(), "B", "", 2, []Widget{{WidgetType: "t", W: 1, H: 1, Config: big}})
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("oversized config: %v, want ErrValidation", err)
	}
	ok := map[string]any{"x": strings.Repeat("a", 100)}
	if _, err := NewDashboard(shared.NewID(), shared.NewID(), "B", "", 2, []Widget{{WidgetType: "t", W: 1, H: 1, Config: ok}}); err != nil {
		t.Fatalf("small config: %v", err)
	}
}

func TestNewSchedule(t *testing.T) {
	m := func(v int) *int { return &v }
	cases := []struct {
		name     string
		interval Interval
		daily    *int
		floor    time.Duration
		ok       bool
	}{
		{"default", IntervalDefault, nil, BaseRefreshFloor, true},
		{"manual under any floor", IntervalManual, nil, 24 * time.Hour, true},
		{"5m at base floor", Interval5m, nil, BaseRefreshFloor, true},
		{"5m below a 15m floor", Interval5m, nil, 15 * time.Minute, false},
		{"15m at a 15m floor", Interval15m, nil, 15 * time.Minute, true},
		{"15m below a 1h floor", Interval15m, nil, time.Hour, false},
		{"1h at a 1h floor", Interval1h, nil, time.Hour, true},
		{"daily needs a minute", IntervalDaily, nil, BaseRefreshFloor, false},
		{"daily minute in range", IntervalDaily, m(90), BaseRefreshFloor, true},
		{"daily minute out of range", IntervalDaily, m(1440), BaseRefreshFloor, false},
		{"minute without daily", Interval1h, m(5), BaseRefreshFloor, false},
		{"unknown", Interval("2m"), nil, BaseRefreshFloor, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewSchedule(tc.interval, tc.daily, tc.floor)
			if tc.ok != (err == nil) {
				t.Fatalf("err = %v, want ok=%v", err, tc.ok)
			}
			if err != nil && !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("err = %v, want ErrValidation", err)
			}
		})
	}
}

func TestScheduleNext(t *testing.T) {
	now := time.Date(2026, 10, 18, 10, 30, 0, 0, time.UTC)
	if n := (Schedule{Interval: IntervalManual}).Next(now); n != nil {
		t.Fatalf("manual next = %v", n)
	}
	if n := (Schedule{Interval: Interval15m}).Next(now); n == nil || !n.Equal(now.Add(15*time.Minute)) {
		t.Fatalf("15m next = %v", n)
	}
	early, late := 9*60, 11*60
	if n := (Schedule{Interval: IntervalDaily, DailyMinute: &early}).Next(now); n == nil || !n.Equal(time.Date(2026, 10, 19, 9, 0, 0, 0, time.UTC)) {
		t.Fatalf("daily 09:00 next = %v", n)
	}
	if n := (Schedule{Interval: IntervalDaily, DailyMinute: &late}).Next(now); n == nil || !n.Equal(time.Date(2026, 10, 18, 11, 0, 0, 0, time.UTC)) {
		t.Fatalf("daily 11:00 next = %v", n)
	}
}

func TestValidateAudience(t *testing.T) {
	id := shared.NewID()
	if err := ValidateAudience(nil); err != nil {
		t.Fatalf("empty audience: %v", err)
	}
	if err := ValidateAudience([]AudienceEntry{{Type: PrincipalRole, ID: id}, {Type: PrincipalGroup, ID: id}}); err != nil {
		t.Fatalf("role and team with one id: %v", err)
	}
	bad := [][]AudienceEntry{
		{{Type: "user", ID: id}},
		{{Type: PrincipalRole}},
		{{Type: PrincipalRole, ID: id}, {Type: PrincipalRole, ID: id}},
	}
	for i, b := range bad {
		if err := ValidateAudience(b); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("case %d: %v, want ErrValidation", i, err)
		}
	}
	many := make([]AudienceEntry, MaxAudience+1)
	for i := range many {
		many[i] = AudienceEntry{Type: PrincipalGroup, ID: shared.NewID()}
	}
	if err := ValidateAudience(many); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("too many: %v", err)
	}
}
