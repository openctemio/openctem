package ingest

import (
	"testing"
	"time"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A sensor's clock never decides which data wins: the report timestamp is
// clamped into [dispatch time, arrival].
func TestClampReportTimestamp(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	dispatched := now.Add(-time.Hour)
	bound := Binding{Kind: BindingCommand, DispatchedAt: dispatched}
	tests := []struct {
		name    string
		ts      time.Time
		binding Binding
		want    time.Time
	}{
		{"within the window stays", now.Add(-10 * time.Minute), bound, now.Add(-10 * time.Minute)},
		{"future-dated is clamped to arrival", now.Add(24 * time.Hour), bound, now},
		{"before the command was dispatched is clamped up", now.Add(-48 * time.Hour), bound, dispatched},
		{"missing timestamp is arrival", time.Time{}, bound, now},
		{"unbound report keeps an old timestamp (it can only lose)", now.Add(-48 * time.Hour), Binding{Kind: BindingUnsolicited}, now.Add(-48 * time.Hour)},
		{"a dispatch time in the future is ignored", now.Add(-time.Minute), Binding{Kind: BindingCommand, DispatchedAt: now.Add(time.Hour)}, now.Add(-time.Minute)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := &ctis.Report{Metadata: ctis.ReportMetadata{Timestamp: tc.ts}}
			clampReportTimestamp(r, tc.binding, now)
			if !r.Metadata.Timestamp.Equal(tc.want) {
				t.Fatalf("timestamp = %s, want %s", r.Metadata.Timestamp, tc.want)
			}
		})
	}
	clampReportTimestamp(nil, bound, now) // no panic
}

func TestCommandBindingDispatchTimeAndRun(t *testing.T) {
	created := time.Date(2026, 10, 10, 9, 0, 0, 0, time.UTC)
	acked := created.Add(5 * time.Minute)
	cmd := &command.Command{ID: shared.NewID(), CreatedAt: created}
	if b := CommandBinding(cmd); !b.DispatchedAt.Equal(created) || b.Run() != cmd.ID.String() {
		t.Fatalf("unacknowledged: dispatched %s run %q", b.DispatchedAt, b.Run())
	}
	cmd.AcknowledgedAt = &acked
	if b := CommandBinding(cmd); !b.DispatchedAt.Equal(acked) {
		t.Fatalf("acknowledged: dispatched %s, want %s", b.DispatchedAt, acked)
	}
	run := shared.NewID()
	if got := CIRunBinding(run, "repo").Run(); got != run.String() {
		t.Fatalf("ci run = %q", got)
	}
	if got := TrustedBinding().Run(); got != "" {
		t.Fatalf("trusted run = %q", got)
	}
}
