package command

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type withheldRepo struct {
	commanddom.Repository
	calls []map[shared.ID]string
	tens  []shared.ID
	err   error
}

func (r *withheldRepo) RecordWithheld(_ context.Context, tenantID shared.ID, reasons map[shared.ID]string) error {
	r.tens = append(r.tens, tenantID)
	r.calls = append(r.calls, reasons)
	return r.err
}

func withheldCmd(payload, intensity string) *commanddom.Command {
	return &commanddom.Command{ID: shared.NewID(), Type: commanddom.CommandTypeScan, Payload: json.RawMessage(payload),
		DispatchGate: &commanddom.DispatchGate{Tier: 1, Intensity: intensity}}
}

// A command the gate withholds is kept out of the poll as before, and its
// placement code is recorded on it for the caller's tenant; the same
// refusal is not written again within the refresh window, and is after it.
func TestKeepAccepted_RecordsRefusals(t *testing.T) {
	repo := &withheldRepo{}
	now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	s := NewService(repo, logger.NewNop())
	s.now = func() time.Time { return now }
	tenant, sensor := shared.NewID(), shared.NewID()
	ok := withheldCmd(`{"scanner":"nuclei","targets":["a.example.com"]}`, "active")
	held := withheldCmd(`{"scanner":"nuclei","targets":["a.example.com"],"custom_templates":[{"id":"x"}]}`, "active")
	g := &dispatchGate{}

	got := s.keepAccepted(context.Background(), tenant, sensor, g, []*commanddom.Command{held, ok})
	if len(got) != 1 || got[0].ID != ok.ID {
		t.Fatalf("kept %v, want only the accepted command", got)
	}
	if len(repo.calls) != 1 || repo.calls[0][held.ID] != commanddom.PlacementIntensity || len(repo.calls[0]) != 1 {
		t.Fatalf("recorded %v, want %s on the withheld command only", repo.calls, commanddom.PlacementIntensity)
	}
	if repo.tens[0] != tenant {
		t.Fatalf("recorded under tenant %s, want the command's tenant", repo.tens[0])
	}

	// Polls within the refresh window write nothing.
	now = now.Add(time.Minute)
	s.keepAccepted(context.Background(), tenant, sensor, g, []*commanddom.Command{held, ok})
	if len(repo.calls) != 1 {
		t.Fatalf("a refusal recorded a minute ago was written again: %v", repo.calls)
	}
	// After it, the same refusal refreshes its time.
	now = now.Add(commanddom.WithheldRefresh)
	s.keepAccepted(context.Background(), tenant, sensor, g, []*commanddom.Command{held})
	if len(repo.calls) != 2 {
		t.Fatalf("calls %d, want the refusal refreshed after the window", len(repo.calls))
	}
}

// A gate that could not read the sensor withholds everything and records
// policy_unavailable; a failed record never changes what the poll returns.
func TestKeepAccepted_ClosedGateAndRecordError(t *testing.T) {
	repo := &withheldRepo{err: errors.New("db down")}
	s := NewService(repo, logger.NewNop())
	c := withheldCmd(`{"scanner":"httpx","targets":["a.example.com"]}`, "")
	got := s.keepAccepted(context.Background(), shared.NewID(), shared.NewID(), &dispatchGate{closed: true}, []*commanddom.Command{c})
	if len(got) != 0 {
		t.Fatalf("a closed gate handed out %v", got)
	}
	if len(repo.calls) != 1 || repo.calls[0][c.ID] != commanddom.PlacementPolicyUnavailable {
		t.Fatalf("recorded %v, want policy_unavailable", repo.calls)
	}
	// No gate (no sensor identity): nothing is withheld or recorded.
	if got := s.keepAccepted(context.Background(), shared.NewID(), shared.NewID(), nil, []*commanddom.Command{c}); len(got) != 1 {
		t.Fatalf("nil gate withheld %v", got)
	}
	if len(repo.calls) != 1 {
		t.Fatal("a nil gate recorded a refusal")
	}
}

// The log is rate-limited per sensor and code: one line per window with the
// count, whatever the number of polls.
func TestWithheldNotes_LogOncePerSensorAndCode(t *testing.T) {
	var n withheldNotes
	now := time.Now()
	a, b := shared.NewID(), shared.NewID()
	refused := map[shared.ID]string{a: "grant_credentials", b: "grant_credentials"}
	_, logs := n.take("s1", refused, now)
	if logs["grant_credentials"] != 2 {
		t.Fatalf("first poll logs %v, want 2 commands under grant_credentials", logs)
	}
	if _, logs = n.take("s1", refused, now.Add(time.Second)); len(logs) != 0 {
		t.Fatalf("second poll logged again: %v", logs)
	}
	if _, logs = n.take("s2", refused, now.Add(time.Second)); logs["grant_credentials"] != 2 {
		t.Fatalf("another sensor's refusals are its own line: %v", logs)
	}
	if _, logs = n.take("s1", refused, now.Add(withheldLogEvery)); len(logs) != 1 {
		t.Fatalf("after the window the sensor logs again: %v", logs)
	}
}
