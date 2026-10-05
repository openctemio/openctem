package scanfreeze

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestNewWindow_Validation(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	at := func(h int) *time.Time { v := now.Add(time.Duration(h) * time.Hour); return &v }
	ok := Spec{Name: " Patch night ", Timezone: "Europe/Berlin", Recurrence: RecurrenceWeekly,
		Days: []int{7, 6, 6}, StartTime: "22:00", EndTime: "06:00", Enabled: true}

	w, err := NewWindow(shared.NewID(), nil, ok, nil, now)
	if err != nil {
		t.Fatalf("valid weekly window refused: %v", err)
	}
	if w.Name != "Patch night" || w.StartMinute != 22*60 || w.EndMinute != 6*60 {
		t.Errorf("window = %+v", w)
	}
	if len(w.Days) != 2 || w.Days[0] != 6 || w.Days[1] != 7 {
		t.Errorf("days = %v, want sorted and deduplicated [6 7]", w.Days)
	}

	bad := map[string]func(s *Spec){
		"empty name":           func(s *Spec) { s.Name = "  " },
		"long name":            func(s *Spec) { s.Name = strings.Repeat("x", 101) },
		"long description":     func(s *Spec) { s.Description = strings.Repeat("x", 1001) },
		"no timezone":          func(s *Spec) { s.Timezone = "" },
		"Local timezone":       func(s *Spec) { s.Timezone = "Local" },
		"unknown timezone":     func(s *Spec) { s.Timezone = "Mars/Olympus" },
		"unknown recurrence":   func(s *Spec) { s.Recurrence = "daily" },
		"no days":              func(s *Spec) { s.Days = nil },
		"day 0":                func(s *Spec) { s.Days = []int{0} },
		"day 8":                func(s *Spec) { s.Days = []int{8} },
		"bad start":            func(s *Spec) { s.StartTime = "24:00" },
		"bad end":              func(s *Spec) { s.EndTime = "6pm" },
		"once without times":   func(s *Spec) { s.Recurrence = RecurrenceOnce },
		"once ends before":     func(s *Spec) { s.Recurrence, s.StartsAt, s.EndsAt = RecurrenceOnce, at(5), at(4) },
		"once longer than 31d": func(s *Spec) { s.Recurrence, s.StartsAt, s.EndsAt = RecurrenceOnce, at(1), at(1+31*24+1) },
		"once already ended":   func(s *Spec) { s.Recurrence, s.StartsAt, s.EndsAt = RecurrenceOnce, at(-5), at(-1) },
	}
	for name, mutate := range bad {
		s := ok
		mutate(&s)
		if _, err := NewWindow(shared.NewID(), nil, s, nil, now); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%s: err = %v, want a validation error", name, err)
		}
	}

	once := Spec{Name: "cutover", Timezone: "UTC", Recurrence: RecurrenceOnce, StartsAt: at(-1), EndsAt: at(3), Days: []int{1}, StartTime: "01:00"}
	w, err = NewWindow(shared.NewID(), nil, once, nil, now)
	if err != nil {
		t.Fatalf("one-off window already running refused: %v", err)
	}
	if w.Days != nil || w.StartMinute != 0 {
		t.Errorf("weekly fields kept on a one-off window: %+v", w)
	}
}

func TestWindow_UpdateKeepsZoneAndRollsBackOnError(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	zone := shared.NewID()
	w, err := NewWindow(shared.NewID(), &zone, Spec{Name: "n", Timezone: "UTC", Recurrence: RecurrenceWeekly,
		Days: []int{1}, StartTime: "01:00", EndTime: "02:00", Enabled: true}, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	spec := w.Spec()
	spec.Timezone = "nowhere"
	if err := w.Update(spec, now); err == nil {
		t.Fatal("invalid update accepted")
	}
	if w.Timezone != "UTC" {
		t.Errorf("a refused update changed the window: %+v", w)
	}
	spec = w.Spec()
	spec.EndTime = "03:30"
	if err := w.Update(spec, now); err != nil {
		t.Fatal(err)
	}
	if w.EndMinute != 210 || w.ScanZoneID == nil || *w.ScanZoneID != zone {
		t.Errorf("update = %+v", w)
	}
}

func TestLatest(t *testing.T) {
	t1, t2 := time.Unix(100, 0), time.Unix(200, 0)
	a, b, c := &Window{ActiveUntil: &t1}, &Window{ActiveUntil: &t2}, &Window{}
	if Latest([]*Window{a, c, b}) != b {
		t.Error("Latest did not pick the window that stays active the longest")
	}
	if Latest([]*Window{c}) != nil {
		t.Error("Latest picked an inactive window")
	}
}

func TestMinuteFormat(t *testing.T) {
	for in, want := range map[string]int{"00:00": 0, "06:30": 390, "23:59": 1439} {
		got, err := ParseMinute(in)
		if err != nil || got != want {
			t.Errorf("ParseMinute(%q) = %d, %v", in, got, err)
		}
		if FormatMinute(want) != in {
			t.Errorf("FormatMinute(%d) = %q", want, FormatMinute(want))
		}
	}
}
