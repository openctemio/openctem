package findinglifecycle

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

func validInput() SubStatusInput {
	return SubStatusInput{
		Key: "in_review", Name: "In review", Color: "blue", CanonicalStatus: "in_progress",
		Labels: map[string]string{"vi": "Đang xem xét"}, Description: "A reviewer is looking at the fix",
	}
}

func TestNewSubStatus_Valid(t *testing.T) {
	now := time.Now()
	actor := shared.NewID()
	s, err := NewSubStatus(shared.NewID(), validInput(), &actor, now)
	if err != nil {
		t.Fatal(err)
	}
	if s.CanonicalStatus() != vulnerability.FindingStatusInProgress || s.ClosureReason() != "" || s.Key() != "in_review" {
		t.Errorf("got %s %q %s", s.CanonicalStatus(), s.ClosureReason(), s.Key())
	}
	if s.Labels()["vi"] != "Đang xem xét" || s.IsArchived() {
		t.Errorf("labels %v archived %v", s.Labels(), s.IsArchived())
	}
}

// A closed status binds one of its own closure reasons; an open one binds
// none. The category decides what a metric counts, so it is checked here and
// by the database.
func TestNewSubStatus_ClosureReasonBinding(t *testing.T) {
	cases := []struct {
		name, status, reason string
		ok                   bool
	}{
		{"open with none", "confirmed", "", true},
		{"open with a reason", "in_progress", "fixed", false},
		{"resolved fixed", "resolved", "fixed", true},
		{"resolved mitigated", "resolved", "mitigated", true},
		{"resolved without reason", "resolved", "", false},
		{"resolved with a false-positive reason", "resolved", "detection_error", false},
		{"resolved unknown", "resolved", "unknown", false},
		{"accepted wont_fix", "accepted", "wont_fix", true},
		{"wont_fix under resolved", "resolved", "wont_fix", false},
		{"false positive detection error", "false_positive", "detection_error", true},
		{"duplicate", "duplicate", "duplicate", true},
		{"pentest draft", "draft", "", false},
		{"unknown status", "done", "", false},
	}
	for _, c := range cases {
		in := validInput()
		in.CanonicalStatus, in.ClosureReason = c.status, c.reason
		_, err := NewSubStatus(shared.NewID(), in, nil, time.Now())
		if (err == nil) != c.ok {
			t.Errorf("%s: err = %v, want ok=%v", c.name, err, c.ok)
		}
		if err != nil && !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%s: err %v is not a validation error", c.name, err)
		}
	}
}

func TestNewSubStatus_PresentationRules(t *testing.T) {
	cases := map[string]func(*SubStatusInput){
		"empty name":         func(in *SubStatusInput) { in.Name = "  " },
		"long name":          func(in *SubStatusInput) { in.Name = strings.Repeat("a", 65) },
		"markup in name":     func(in *SubStatusInput) { in.Name = "<b>Done</b>" },
		"control char":       func(in *SubStatusInput) { in.Name = "Done\nnow" },
		"free css color":     func(in *SubStatusInput) { in.Color = "#ff0000" },
		"bad key":            func(in *SubStatusInput) { in.Key = "In Review" },
		"key starting digit": func(in *SubStatusInput) { in.Key = "1review" },
		"bad language":       func(in *SubStatusInput) { in.Labels = map[string]string{"vietnamese": "x"} },
		"markup label":       func(in *SubStatusInput) { in.Labels = map[string]string{"vi": "<script>"} },
		"long description":   func(in *SubStatusInput) { in.Description = strings.Repeat("d", 501) },
		"negative order":     func(in *SubStatusInput) { in.SortOrder = -1 },
	}
	for name, mutate := range cases {
		in := validInput()
		mutate(&in)
		if _, err := NewSubStatus(shared.NewID(), in, nil, time.Now()); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%s: err = %v, want a validation error", name, err)
		}
	}
	in := validInput()
	in.Name = strings.Repeat("ă", 64) // 64 characters, more bytes
	if _, err := NewSubStatus(shared.NewID(), in, nil, time.Now()); err != nil {
		t.Errorf("64-character name refused: %v", err)
	}
}

// An update changes presentation only; the category stays (the struct has
// no way to change it, and the database refuses it too).
func TestSubStatus_UpdateKeepsCategory(t *testing.T) {
	s, err := NewSubStatus(shared.NewID(), validInput(), nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	name, color := "Code review", "violet"
	if err := s.Update(SubStatusUpdate{Name: &name, Color: &color, Labels: map[string]string{}}, nil, time.Now()); err != nil {
		t.Fatal(err)
	}
	if s.Name() != name || s.Color() != color || len(s.Labels()) != 0 || s.CanonicalStatus() != vulnerability.FindingStatusInProgress {
		t.Errorf("after update: %s %s %v %s", s.Name(), s.Color(), s.Labels(), s.CanonicalStatus())
	}
	bad := "#000"
	if err := s.Update(SubStatusUpdate{Color: &bad}, nil, time.Now()); err == nil || s.Color() != color {
		t.Errorf("a refused update changed the color: %v %s", err, s.Color())
	}
}

func TestSubStatus_ArchiveRestore(t *testing.T) {
	s, _ := NewSubStatus(shared.NewID(), validInput(), nil, time.Now())
	s.Archive(nil, time.Now())
	if !s.IsArchived() {
		t.Fatal("not archived")
	}
	s.Restore(nil, time.Now())
	if s.IsArchived() {
		t.Fatal("still archived")
	}
}
