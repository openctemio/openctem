package command

import (
	"encoding/json"
	"fmt"
	"slices"
	"testing"

	"github.com/openctemio/ctis/outcome"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func scanWithResult(t *testing.T, targets []string, outcomes any) *Command {
	t.Helper()
	payload, _ := json.Marshal(map[string]any{"scanner": "httpx", "targets": targets, "scan_run_id": "r", "step_key": "s"})
	cmd, err := NewCommand(shared.NewID(), CommandTypeScan, CommandPriorityNormal, payload)
	if err != nil {
		t.Fatal(err)
	}
	cmd.SetStepRunID(shared.NewID())
	if outcomes != nil {
		cmd.Result, _ = json.Marshal(map[string]any{"status": "completed", "target_outcomes": outcomes})
	} else {
		cmd.Result = json.RawMessage(`{"status":"completed","findings_count":3}`)
	}
	return cmd
}

func hosts(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("https://h%02d.example", i)
	}
	return out
}

func TestUnfinishedTargets(t *testing.T) {
	targets := hosts(4)
	cmd := scanWithResult(t, targets, []outcome.Target{
		{Target: targets[0], State: outcome.Done},
		{Target: targets[1], State: outcome.Failed, Class: outcome.Timeout},
		{Target: targets[2], State: outcome.Unfinished},
		{Target: "https://injected.example", State: outcome.Unfinished}, // not the command's
		// targets[3]: no outcome -> unfinished
	})
	remaining, settled, ok := UnfinishedTargets(cmd)
	if !ok || settled != 2 || !slices.Equal(remaining, []string{targets[2], targets[3]}) {
		t.Fatalf("remaining %v settled %d ok %v", remaining, settled, ok)
	}
}

// A target the sensor's network confinement kept the tool from reaching
// is settled (failed/egress_refused): the same sensor would refuse it
// again, so it is not handed out again as unfinished.
func TestUnfinishedTargets_EgressRefusedSettles(t *testing.T) {
	targets := hosts(2)
	cmd := scanWithResult(t, targets, []outcome.Target{
		{Target: targets[0], State: outcome.Failed, Class: outcome.EgressRefused},
		{Target: targets[1], State: outcome.Done},
	})
	remaining, settled, ok := UnfinishedTargets(cmd)
	if !ok || settled != 2 || len(remaining) != 0 {
		t.Fatalf("remaining %v settled %d ok %v", remaining, settled, ok)
	}
}

// A result without target_outcomes (a sensor that predates them) covered
// every target: nothing is followed up.
func TestUnfinishedTargets_OlderSensor(t *testing.T) {
	if _, _, ok := UnfinishedTargets(scanWithResult(t, hosts(3), nil)); ok {
		t.Fatal("a result without outcomes was read as partial")
	}
	cmd := scanWithResult(t, hosts(3), []outcome.Target{})
	cmd.IsPlatformJob = true
	if _, _, ok := UnfinishedTargets(cmd); ok {
		t.Fatal("a platform job was followed up")
	}
	cmd = scanWithResult(t, hosts(3), []outcome.Target{})
	cmd.Type = CommandTypeCollect
	if _, _, ok := UnfinishedTargets(cmd); ok {
		t.Fatal("a non-scan command was followed up")
	}
	// A run's command without its step id: its step would settle before
	// the follow-up ran, so it is not followed up.
	cmd = scanWithResult(t, hosts(3), []outcome.Target{})
	cmd.StepRunID = nil
	if _, _, ok := UnfinishedTargets(cmd); ok {
		t.Fatal("a run command without its step id was followed up")
	}
	cmd = scanWithResult(t, hosts(3), nil)
	cmd.Result = json.RawMessage(`{"target_outcomes":"bogus"}`)
	if _, _, ok := UnfinishedTargets(cmd); ok {
		t.Fatal("a malformed result was read")
	}
}

func TestFollowUpAttempts(t *testing.T) {
	if FollowUpAttempts(2, 5) != 2 {
		t.Fatal("a run that settled targets must not charge the rest an attempt")
	}
	if FollowUpAttempts(2, 0) != 3 {
		t.Fatal("a run that settled nothing counts one more attempt")
	}
}

func TestNewFollowUp_PayloadCarriesOnlyRemaining(t *testing.T) {
	targets := hosts(3)
	parent := scanWithResult(t, targets, []outcome.Target{})
	parent.DispatchAttempts = 1
	fu, err := NewFollowUp(parent, targets[1:], 1)
	if err != nil {
		t.Fatal(err)
	}
	if got := PayloadTargets(fu.Payload); !slices.Equal(got, targets[1:]) {
		t.Fatalf("follow-up targets %v", got)
	}
	var p map[string]any
	_ = json.Unmarshal(fu.Payload, &p)
	if p["scanner"] != "httpx" || p["scan_run_id"] != "r" || p["step_key"] != "s" {
		t.Fatalf("payload lost its routing: %v", p)
	}
	if fu.TenantID != parent.TenantID || fu.Status != CommandStatusPending || fu.DispatchAttempts != 1 || fu.ID == parent.ID {
		t.Fatalf("follow-up %+v", fu)
	}

	// A single "target" names the whole job on a sensor: it is replaced
	// with the one target left, or dropped when several are left.
	parent.Payload = json.RawMessage(`{"scanner":"httpx","target":"https://h00.example","targets":["https://h00.example","https://h01.example","https://h02.example"]}`)
	fu, _ = NewFollowUp(parent, []string{"https://h02.example"}, 2)
	if got := PayloadTargets(fu.Payload); !slices.Equal(got, []string{"https://h02.example"}) {
		t.Fatalf("follow-up targets %v (%s)", got, fu.Payload)
	}
	fu, _ = NewFollowUp(parent, []string{"https://h01.example", "https://h02.example"}, 1)
	_ = json.Unmarshal(fu.Payload, &p)
	if _, has := p["target"]; has {
		t.Fatalf("a multi-target follow-up kept the single target: %s", fu.Payload)
	}
	if _, err := NewFollowUp(parent, nil, 3); err == nil {
		t.Fatal("a follow-up without targets was built")
	}
}

// The 2026-10-14 incident, replayed on the chunk rule: 72 httpx targets, a
// run stalls after part of them each time. Before, every attempt restarted
// at target 1 and three stalls exhausted the command. Now each attempt
// settles what it finished, the remaining chunk keeps its attempt count
// while progress is made, and only a chunk that settles nothing is charged:
// one bad host exhausts only itself.
func TestFollowUpChain_IncidentReplay(t *testing.T) {
	const maxAttempts = 3
	all := hosts(72)
	bad := all[40]
	remaining, attempts, settledTotal, generations := all, 0, 0, 0
	for len(remaining) > 0 && attempts < maxAttempts {
		generations++
		// Each run settles up to 30 targets in order and never finishes the
		// bad host; the run stalls there and the targets after it in this
		// run stay unfinished.
		var outs []outcome.Target
		n := 0
		for _, h := range remaining {
			if h == bad || n == 30 {
				break
			}
			outs = append(outs, outcome.Target{Target: h, State: outcome.Done})
			n++
		}
		// After the bad host is first, the rest of the run still goes on
		// past it with native per-request timeouts (batch mode).
		if len(outs) == 0 {
			for _, h := range remaining {
				if h != bad {
					outs = append(outs, outcome.Target{Target: h, State: outcome.Done})
				}
			}
		}
		if slices.Contains(remaining, bad) {
			outs = append(outs, outcome.Target{Target: bad, State: outcome.Unfinished})
		}
		cmd := scanWithResult(t, remaining, outs)
		cmd.DispatchAttempts = attempts
		left, settled, ok := UnfinishedTargets(cmd)
		if !ok {
			t.Fatal("outcomes not read")
		}
		settledTotal += settled
		if len(left) == 0 {
			remaining = nil
			break
		}
		fu, err := NewFollowUp(cmd, left, settled)
		if err != nil {
			t.Fatal(err)
		}
		remaining, attempts = PayloadTargets(fu.Payload), fu.DispatchAttempts
		if generations > 80 {
			t.Fatal("the chain does not end")
		}
	}
	if settledTotal != 71 {
		t.Fatalf("settled %d of 72 targets", settledTotal)
	}
	if !slices.Equal(remaining, []string{bad}) || attempts != maxAttempts {
		t.Fatalf("exhausted chunk %v at %d attempts: only the bad host may exhaust", remaining, attempts)
	}
}
