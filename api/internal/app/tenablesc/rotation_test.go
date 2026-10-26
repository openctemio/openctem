package tenablesc

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/ctis/outcome"

	"github.com/openctemio/openctem/api/internal/app/scancoverage"
	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/ingestreport"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

// License-aware rotation (research/143 §4): the batch carries the license
// guard, settles the ledger per target, and the next batch waits for the
// license to come back (aging), recycles the rotation repository only after
// the previous batch was ingested (recycle), or stalls when it cannot be
// sure.

type fakeLedger struct {
	settled  []scancoverage.BatchSettlement
	tenants  []shared.ID
	eligible int
	assessed int
}

func (f *fakeLedger) SettleConnectorBatch(_ context.Context, tenantID shared.ID, b scancoverage.BatchSettlement) error {
	f.settled = append(f.settled, b)
	f.tenants = append(f.tenants, tenantID)
	return nil
}

func (f *fakeLedger) ConnectorCycleProgress(context.Context, shared.ID, time.Time) (int, int, error) {
	return f.eligible, f.assessed, nil
}

func rotationEnv(t *testing.T, rotation string) (*env, *fakeLedger) {
	t.Helper()
	extra := map[string]any{"coverage_rotation": rotation}
	if rotation != "off" {
		extra["coverage_rotation_acknowledged"] = true
	}
	e := coverageEnv(t, extra)
	l := &fakeLedger{eligible: 10}
	e.svc.SetCoverageLedger(l)
	return e, l
}

func dispatchBatch(t *testing.T, e *env, newAddrs int, targets ...string) (*command.Command, ScanPayload) {
	t.Helper()
	id, err := e.svc.DispatchCoverageBatch(context.Background(), e.tenant, e.intg.ID(), targets, "sess", newAddrs)
	if err != nil {
		t.Fatal(err)
	}
	cmd := e.cmds.rows[id]
	var p ScanPayload
	if err := json.Unmarshal(cmd.Payload, &p); err != nil {
		t.Fatal(err)
	}
	return cmd, p
}

// finishBatch completes cmd with outcomes and license numbers, its report
// ingested, then reads the coverage status (which settles it).
func finishBatch(t *testing.T, e *env, cmd *command.Command, outs []outcome.Target, before, after int) CoverageStatus {
	t.Helper()
	cmd.Status = command.CommandStatusCompleted
	cmd.Result, _ = json.Marshal(map[string]any{"target_outcomes": outs,
		"metadata": map[string]any{"licensed_ips": 100, "active_ips_before": before, "active_ips": after, "coverage": "full"}})
	e.reports.reports[cmd.ID] = []ingestreport.CoverageReport{{State: protov2.StateCompleted, ToolName: ToolName}}
	st, err := e.svc.CoverageStatus(context.Background(), e.intg)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func failBatch(t *testing.T, e *env, cmd *command.Command, msg string) CoverageStatus {
	t.Helper()
	cmd.Status, cmd.ErrorMessage = command.CommandStatusFailed, msg
	st, err := e.svc.CoverageStatus(context.Background(), e.intg)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func TestRotation_ConfigNeedsAcknowledgement(t *testing.T) {
	e := newEnv(t)
	base := map[string]any{"coverage_enabled": true, "coverage_policy_id": float64(1), "coverage_repository_id": float64(5)}
	for name, tc := range map[string]struct {
		extra map[string]any
		ok    bool
	}{
		"off by default":         {nil, true},
		"aging acknowledged":     {map[string]any{"coverage_rotation": "aging", "coverage_rotation_acknowledged": true}, true},
		"recycle acknowledged":   {map[string]any{"coverage_rotation": "recycle", "coverage_rotation_acknowledged": true}, true},
		"aging unacknowledged":   {map[string]any{"coverage_rotation": "aging"}, false},
		"recycle unacknowledged": {map[string]any{"coverage_rotation": "recycle", "coverage_rotation_acknowledged": false}, false},
		"unknown mode":           {map[string]any{"coverage_rotation": "delete", "coverage_rotation_acknowledged": true}, false},
		"wait out of range":      {map[string]any{"coverage_rotation": "aging", "coverage_rotation_acknowledged": true, "coverage_rotation_wait_hours": float64(100)}, false},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := connectorIntegration(e.tenant, e.sensorID, base).Config()
			for k, v := range tc.extra {
				cfg[k] = v
			}
			err := e.svc.ValidateConnector(context.Background(), e.tenant, cfg)
			if (err == nil) != tc.ok {
				t.Fatalf("err %v, ok want %v", err, tc.ok)
			}
			if err != nil && !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("err %v, want a validation error", err)
			}
		})
	}
}

func TestRotation_Off_GuardAndHeadroom(t *testing.T) {
	e, l := rotationEnv(t, "off")
	st, _ := e.svc.CoverageStatus(context.Background(), e.intg)
	// Licensed 100, active 40, margin 2: 58 new addresses fit; already
	// counted assets are rescanned without using any.
	if !st.Ready || st.NewHeadroom != 58 || st.AllNew || st.DefaultBatch != scancoverage.DefaultCoverageBatch {
		t.Fatalf("status %+v", st)
	}
	cmd, p := dispatchBatch(t, e, 3, "10.0.0.1", "10.0.0.2", "10.0.0.3")
	if p.LicenseGuard == nil || p.LicenseGuard.NewAddresses != 3 || p.LicenseGuard.Headroom != 2 || p.RotationRepository || p.RecycleRepository {
		t.Fatalf("payload %+v", p)
	}
	st = finishBatch(t, e, cmd, []outcome.Target{
		{Target: "10.0.0.1", State: outcome.Done},
		{Target: "10.0.0.2", State: outcome.Failed, Class: outcome.Unreachable},
		{Target: "10.0.0.3", State: outcome.Unfinished},
		{Target: "203.0.113.9", State: outcome.Done}, // not the batch's: ignored
	}, 40, 41)
	if len(l.settled) != 1 || l.tenants[0] != e.tenant {
		t.Fatalf("settled %+v", l.settled)
	}
	b := l.settled[0]
	if !slices.Equal(b.Done, []string{"10.0.0.1"}) || !slices.Equal(b.Unreachable, []string{"10.0.0.2"}) || !slices.Equal(b.Unfinished, []string{"10.0.0.3"}) {
		t.Fatalf("settlement %+v", b)
	}
	// Off: no wait; the next batch is sized against the new count.
	if !st.Ready || st.NewHeadroom != 57 {
		t.Fatalf("after: %+v", st)
	}
}

func TestRotation_Aging_WaitsForTheCleanup(t *testing.T) {
	e, _ := rotationEnv(t, "aging")
	cmd, p := dispatchBatch(t, e, 50, "10.0.0.0/26")
	if p.RotationRepository || p.RecycleRepository || p.LicenseGuard.NewAddresses != 50 {
		t.Fatalf("aging payload %+v", p)
	}
	st := finishBatch(t, e, cmd, []outcome.Target{{Target: "10.0.0.0/26", State: outcome.Done}}, 40, 90)
	if st.Ready || !strings.Contains(st.Reason, "nightly cleanup") {
		t.Fatalf("aging must wait: %+v", st)
	}
	s := State(e.intg)
	if s.NextBatchAt == nil || !s.NextBatchAt.Equal(e.now.Add(12*time.Hour)) || s.LastBatchAdded != 50 {
		t.Fatalf("state %+v", s)
	}
	// After the wait: sized as if the batch's 50 left the count (90-50=40
	// outside the rotation repository): 100-2-40 = 58, every address new.
	e.now = e.now.Add(13 * time.Hour)
	st, _ = e.svc.CoverageStatus(context.Background(), e.intg)
	if !st.Ready || st.NewHeadroom != 58 || !st.AllNew || st.DefaultBatch != 58 {
		t.Fatalf("after the wait: %+v", st)
	}
}

func TestRotation_CapacityRefusalWaitsAndRequeues(t *testing.T) {
	e, l := rotationEnv(t, "aging")
	cmd, _ := dispatchBatch(t, e, 4, "10.0.0.1", "10.0.0.2")
	st := failBatch(t, e, cmd, `tenable.sc scan on "sc-prod": LICENCE_CAPACITY: the Tenable.sc license capacity the batch needs is not free yet (licensed 100, active 99, free 1, the batch needs 2 plus 2 headroom)`) //nolint:misspell // the connector's wire code
	if st.Ready || State(e.intg).RotationStalled != "" {
		t.Fatalf("status %+v", st)
	}
	if b := l.settled[0]; len(b.Unfinished) != 2 || len(b.Failed) != 0 {
		t.Fatalf("a guard refusal ran nothing: targets due again, not failed: %+v", b)
	}
	if s := State(e.intg); s.NextBatchAt == nil || !s.NextBatchAt.Equal(e.now.Add(capacityRetry)) {
		t.Fatalf("state %+v", s)
	}
}

func TestRotation_Recycle_OnlyAfterIngest(t *testing.T) {
	e, _ := rotationEnv(t, "recycle")
	cmd, p := dispatchBatch(t, e, 10, "10.0.0.1")
	if !p.RotationRepository || p.RecycleRepository {
		t.Fatalf("first batch: rotation repository, nothing to recycle yet: %+v", p)
	}
	// Completed but not ingested: no recycle decision yet.
	cmd.Status = command.CommandStatusCompleted
	cmd.Result, _ = json.Marshal(map[string]any{"metadata": map[string]any{"licensed_ips": 100, "active_ips": 41, "coverage": "full"}})
	e.reports.reports[cmd.ID] = []ingestreport.CoverageReport{{State: protov2.StateProcessing, ToolName: ToolName}}
	if st, _ := e.svc.CoverageStatus(context.Background(), e.intg); st.Ready || State(e.intg).RecycleNext {
		t.Fatal("recycle decided before the batch was ingested")
	}
	e.reports.reports[cmd.ID][0].State = protov2.StateCompleted
	st, _ := e.svc.CoverageStatus(context.Background(), e.intg)
	if !st.Ready || !State(e.intg).RecycleNext {
		t.Fatalf("ingested: the next batch recycles: %+v %+v", st, State(e.intg))
	}
	cmd2, p2 := dispatchBatch(t, e, 10, "10.0.0.2")
	if !p2.RotationRepository || !p2.RecycleRepository || State(e.intg).RecycleNext {
		t.Fatalf("second batch %+v state %+v", p2, State(e.intg))
	}
	// It failed after launching: its results may not be ingested, so
	// rotation stalls and nothing recycles until an administrator resumes.
	st = failBatch(t, e, cmd2, `tenable.sc scan on "sc-prod": read scan result 777: tenable.sc returned an unreadable row`)
	s := State(e.intg)
	if st.Ready || s.RotationStalled == "" || s.RecycleNext {
		t.Fatalf("status %+v state %+v", st, s)
	}
	e.now = e.now.Add(48 * time.Hour)
	if st, _ := e.svc.CoverageStatus(context.Background(), e.intg); st.Ready {
		t.Fatal("a stalled rotation resumed by itself")
	}
	if _, err := e.svc.ResumeRotation(context.Background(), shared.NewID(), e.intg.ID(), nil); err == nil {
		t.Fatal("another tenant resumed rotation")
	}
	if _, err := e.svc.ResumeRotation(context.Background(), e.tenant, e.intg.ID(), nil); err != nil {
		t.Fatal(err)
	}
	if s := State(e.intg); s.RotationStalled != "" || !s.RecycleNext {
		t.Fatalf("resumed state %+v", s)
	}
	if _, err := e.svc.ResumeRotation(context.Background(), e.tenant, e.intg.ID(), nil); !errors.Is(err, ErrRotationNotStalled) {
		t.Fatalf("second resume: %v", err)
	}
}

func TestRotation_Recycle_RefusedBeforeLaunchDoesNotStall(t *testing.T) {
	e, _ := rotationEnv(t, "recycle")
	cmd, _ := dispatchBatch(t, e, 10, "10.0.0.1")
	failBatch(t, e, cmd, "tenable.sc connector refused the job: scan policy 9 is not allowed by the sensor owner")
	if s := State(e.intg); s.RotationStalled != "" {
		t.Fatalf("nothing launched, nothing to protect: %+v", s)
	}
}

func TestRotation_CycleProgressAndETA(t *testing.T) {
	e, l := rotationEnv(t, "off")
	cmd, _ := dispatchBatch(t, e, 1, "10.0.0.1")
	s := State(e.intg)
	if s.Cycle != 1 || s.CycleStartedAt == nil {
		t.Fatalf("first batch starts cycle 1: %+v", s)
	}
	l.eligible, l.assessed = 10, 4
	e.now = e.now.Add(4 * time.Hour)
	finishBatch(t, e, cmd, []outcome.Target{{Target: "10.0.0.1", State: outcome.Done}}, 40, 41)
	s = State(e.intg)
	if s.CycleAssessed != 4 || s.CycleEligible != 10 || s.CycleETA == nil || !s.CycleETA.Equal(e.now.Add(6*time.Hour)) {
		t.Fatalf("progress %+v", s)
	}
	cmd, _ = dispatchBatch(t, e, 1, "10.0.0.2")
	l.assessed = 10
	finishBatch(t, e, cmd, []outcome.Target{{Target: "10.0.0.2", State: outcome.Done}}, 41, 42)
	if s := State(e.intg); s.Cycle != 2 || s.CycleAssessed != 0 || !s.CycleStartedAt.Equal(e.now) {
		t.Fatalf("a covered cycle starts the next: %+v", s)
	}
}

func TestBatchSettlement_OlderSensorAndFailures(t *testing.T) {
	payload, _ := json.Marshal(map[string]any{"scanner": ToolName, "targets": []string{"10.0.0.1", "10.0.0.2"}})
	mk := func(st command.CommandStatus, result map[string]any, msg string) *command.Command {
		c := &command.Command{Type: command.CommandTypeConnectorScan, Status: st, Payload: payload, ErrorMessage: msg}
		if result != nil {
			c.Result, _ = json.Marshal(result)
		}
		return c
	}
	if b := batchSettlement(mk(command.CommandStatusCompleted, map[string]any{"metadata": map[string]any{"coverage": "full"}}, "")); len(b.Done) != 2 {
		t.Fatalf("older sensor, full: %+v", b)
	}
	if b := batchSettlement(mk(command.CommandStatusCompleted, map[string]any{"metadata": map[string]any{"coverage": "partial"}}, "")); len(b.Unfinished) != 2 {
		t.Fatalf("older sensor, partial: %+v", b)
	}
	// A truncated result covers nothing, whatever it says it finished.
	if b := batchSettlement(mk(command.CommandStatusCompleted, map[string]any{"metadata": map[string]any{"coverage": "full", "truncated": true}}, "")); len(b.Done) != 0 || len(b.Unfinished) != 2 {
		t.Fatalf("truncated, full: %+v", b)
	}
	if b := batchSettlement(mk(command.CommandStatusCompleted, map[string]any{
		"metadata":        map[string]any{"truncated": true},
		"target_outcomes": []map[string]any{{"target": "10.0.0.1", "state": "done"}, {"target": "10.0.0.2", "state": "failed", "class": "unreachable"}},
	}, "")); len(b.Done) != 0 || len(b.Unfinished) != 1 || len(b.Unreachable) != 1 {
		t.Fatalf("truncated with outcomes: %+v", b)
	}
	if b := batchSettlement(mk(command.CommandStatusFailed, nil, "boom")); len(b.Failed) != 2 || b.Error != "boom" {
		t.Fatalf("failed: %+v", b)
	}
	if b := batchSettlement(mk(command.CommandStatusExpired, nil, "")); len(b.Failed) != 2 || b.Error == "" {
		t.Fatalf("expired: %+v", b)
	}
}

// The wire names are the connector's (openctemio/connector-tenable v0.1.0):
// a renamed key would be refused by its strict payload decoder.
func TestRotation_PayloadWireNames(t *testing.T) {
	e, _ := rotationEnv(t, "recycle")
	cmd, _ := dispatchBatch(t, e, 3, "10.0.0.1")
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(cmd.Payload, &raw); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"licence_guard", "rotation_repository"} { //nolint:misspell // wire key
		if _, ok := raw[k]; !ok {
			t.Fatalf("payload misses %q: %s", k, cmd.Payload)
		}
	}
	var g map[string]int
	_ = json.Unmarshal(raw["licence_guard"], &g) //nolint:misspell // wire key
	if g["new_addresses"] != 3 || g["headroom"] != 2 {
		t.Fatalf("guard %v", g)
	}
}
