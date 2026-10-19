package remediation

import (
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A campaign completes on its own only from active, when its tasks are all
// closed and one is done; a completed campaign reopens when a task is live
// again. The lifecycle is draft → active → completed, with cancel from draft
// or active and reopen from completed.

func newCampaign(t *testing.T, status CampaignStatus) *Campaign {
	t.Helper()
	c, err := NewCampaign(shared.NewID(), "test", CampaignPriorityHigh)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	switch status {
	case CampaignStatusDraft:
	case CampaignStatusActive:
		_ = c.Activate()
	case CampaignStatusCompleted:
		_ = c.Activate()
		_ = c.Complete()
	case CampaignStatusCanceled:
		_ = c.Cancel()
	}
	if c.Status() != status {
		t.Fatalf("could not drive to %s, stuck at %s", status, c.Status())
	}
	return c
}

func TestCampaignSummary_IsDone(t *testing.T) {
	cases := []struct {
		name string
		s    CampaignSummary
		want bool
	}{
		{"no tasks", CampaignSummary{}, false},
		{"a live task", CampaignSummary{Tasks: 2, LiveTasks: 1, DoneTasks: 1}, false},
		{"all closed, none done", CampaignSummary{Tasks: 2, DoneTasks: 0}, false},
		{"all closed, one done", CampaignSummary{Tasks: 2, DoneTasks: 1}, true},
	}
	for _, tc := range cases {
		if got := tc.s.IsDone(); got != tc.want {
			t.Errorf("%s: IsDone = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestCampaign_TryAutoComplete(t *testing.T) {
	done := CampaignSummary{Tasks: 1, DoneTasks: 1}
	for _, st := range []CampaignStatus{CampaignStatusDraft, CampaignStatusCompleted, CampaignStatusCanceled} {
		c := newCampaign(t, st)
		if c.TryAutoComplete(done) {
			t.Errorf("%s: auto-completed", st)
		}
	}
	c := newCampaign(t, CampaignStatusActive)
	if c.TryAutoComplete(CampaignSummary{Tasks: 1, LiveTasks: 1}) {
		t.Error("active with a live task: auto-completed")
	}
	if !c.TryAutoComplete(done) || c.Status() != CampaignStatusCompleted || c.CompletedAt() == nil {
		t.Errorf("active and done: status %s completed_at %v", c.Status(), c.CompletedAt())
	}
}

func TestCampaign_TryAutoReopen(t *testing.T) {
	c := newCampaign(t, CampaignStatusCompleted)
	if c.TryAutoReopen(CampaignSummary{Tasks: 1, DoneTasks: 1}) {
		t.Error("reopened with no live task")
	}
	if !c.TryAutoReopen(CampaignSummary{Tasks: 2, LiveTasks: 1, DoneTasks: 1}) || c.Status() != CampaignStatusActive || c.CompletedAt() != nil {
		t.Errorf("live task: status %s completed_at %v", c.Status(), c.CompletedAt())
	}
	for _, st := range []CampaignStatus{CampaignStatusDraft, CampaignStatusActive, CampaignStatusCanceled} {
		if newCampaign(t, st).TryAutoReopen(CampaignSummary{Tasks: 1, LiveTasks: 1}) {
			t.Errorf("%s: reopened", st)
		}
	}
}

func TestCampaign_Transitions(t *testing.T) {
	if err := newCampaign(t, CampaignStatusActive).Activate(); err == nil {
		t.Error("activate from active allowed")
	}
	if err := newCampaign(t, CampaignStatusDraft).Complete(); err == nil {
		t.Error("complete from draft allowed")
	}
	if err := newCampaign(t, CampaignStatusCompleted).Cancel(); err == nil {
		t.Error("cancel from completed allowed")
	}
	if err := newCampaign(t, CampaignStatusCanceled).Reopen(); err == nil {
		t.Error("reopen from canceled allowed")
	}
	for st, want := range map[CampaignStatus]bool{
		CampaignStatusDraft: true, CampaignStatusActive: true, CampaignStatusCompleted: false, CampaignStatusCanceled: false,
	} {
		if got := newCampaign(t, st).TakesTasks(); got != want {
			t.Errorf("%s: TakesTasks = %v", st, got)
		}
	}
}

func TestCampaignSummary_Progress(t *testing.T) {
	if p := (CampaignSummary{}).Progress(); p != 0 {
		t.Errorf("empty progress = %v", p)
	}
	if p := (CampaignSummary{Findings: 4, ClosedFindings: 1}).Progress(); p != 25 {
		t.Errorf("progress = %v, want 25", p)
	}
}
