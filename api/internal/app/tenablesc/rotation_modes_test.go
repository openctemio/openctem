package tenablesc

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/contract/outcome"

	"github.com/openctemio/openctem/api/internal/app/scancoverage"
	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Purge rotation, Blocked imports and the rules that keep rotation from
// stalling when nothing was imported (research 450).

func ingested(t *testing.T, e *env, cmd *command.Command, target string) CoverageStatus {
	t.Helper()
	return finishBatch(t, e, cmd, []outcome.Target{{Target: target, State: outcome.Done}}, 40, 41)
}

func TestRotation_Purge_NamesThePreviousBatchOnlyAfterIngest(t *testing.T) {
	e, _ := rotationEnv(t, "purge")
	cmd1, p1 := dispatchBatch(t, e, 10, "10.0.0.0/30")
	if !p1.RotationRepository || p1.RotationMode != "purge" || p1.Purge != nil || p1.RecycleRepository {
		t.Fatalf("first batch %+v", p1)
	}
	ingested(t, e, cmd1, "10.0.0.0/30")
	if State(e.intg).PurgeFrom != cmd1.ID.String() {
		t.Fatalf("state %+v", State(e.intg))
	}
	cmd2, p2 := dispatchBatch(t, e, 10, "10.0.1.0/30")
	if p2.Purge == nil || p2.Purge.PreviousCommandID != cmd1.ID.String() || !slices.Equal(p2.Purge.Targets, []string{"10.0.0.0/30"}) ||
		State(e.intg).PurgeFrom != "" {
		t.Fatalf("second batch %+v state %+v", p2, State(e.intg))
	}
	// Refused before launch: nothing was purged, the next batch asks again.
	failBatch(t, e, cmd2, "tenable.sc connector refused the job: rotation repository \"openctem-rot\": agent repository")
	if s := State(e.intg); s.RotationStalled != "" || s.PurgeFrom != cmd1.ID.String() {
		t.Fatalf("refused: %+v", s)
	}
	e.now = e.now.Add(time.Hour)
	cmd3, p3 := dispatchBatch(t, e, 10, "10.0.1.0/30")
	if p3.Purge == nil || p3.Purge.PreviousCommandID != cmd1.ID.String() {
		t.Fatalf("third batch %+v", p3)
	}
	// An unconfirmed purge stalls rotation.
	st := failBatch(t, e, cmd3, `tenable.sc scan on "sc-prod": purge_unverified: the purge of the previous batch could not be confirmed (2 of 2 address(es) still in "openctem-rot")`)
	if s := State(e.intg); st.Ready || !strings.Contains(s.RotationStalled, "purge_unverified") || s.PurgeFrom != "" {
		t.Fatalf("unverified: %+v %+v", st, s)
	}
}

func TestRotation_Purge_PreviousBatchIsTenantScoped(t *testing.T) {
	e, _ := rotationEnv(t, "purge")
	other, err := command.NewCommand(shared.NewID(), command.CommandTypeConnectorScan, command.CommandPriorityNormal,
		json.RawMessage(`{"targets":["10.9.9.9"]}`))
	if err != nil {
		t.Fatal(err)
	}
	e.cmds.rows[other.ID] = other
	s := State(e.intg)
	s.PurgeFrom = other.ID.String()
	writeState(e.intg, s)
	_, p := dispatchBatch(t, e, 10, "10.0.0.1")
	if p.Purge != nil {
		t.Fatalf("named another tenant's batch: %+v", p.Purge)
	}
}

func TestRotation_Blocked_ReimportsWithoutStalling(t *testing.T) {
	e, l := rotationEnv(t, "recycle")
	cmd1, _ := dispatchBatch(t, e, 10, "10.0.0.1")
	ingested(t, e, cmd1, "10.0.0.1")
	cmd2, p2 := dispatchBatch(t, e, 7, "10.0.0.2", "10.0.0.3")
	if !p2.RecycleRepository {
		t.Fatalf("second batch %+v", p2)
	}
	st := failBatch(t, e, cmd2, `tenable.sc scan on "sc-prod": IMPORT_BLOCKED: tenable.sc did not import the scan result, the import would exceed the IP licence; nothing was imported (scan_result_id=777) (licensed 100, active 99)`) //nolint:misspell // the connector's wire text
	s := State(e.intg)
	if st.Ready || s.RotationStalled != "" || s.Reimport == nil || s.Reimport.ScanResultID != 777 || s.RecycleNext {
		t.Fatalf("blocked: %+v %+v", st, s)
	}
	if b := l.settled[len(l.settled)-1]; len(b.Unfinished) != 2 || len(b.Failed) != 0 {
		t.Fatalf("nothing imported: targets due again, not failed: %+v", b)
	}
	// The next batch imports that result again with its own targets,
	// whatever the scheduler picked, and recycles nothing.
	e.now = e.now.Add(capacityRetry)
	cmd3, p3 := dispatchBatch(t, e, 3, "10.0.0.9")
	if p3.ReimportScanResultID != 777 || !slices.Equal(p3.Targets, []string{"10.0.0.2", "10.0.0.3"}) || p3.RecycleRepository ||
		p3.LicenseGuard.NewAddresses != 7 {
		t.Fatalf("reimport batch %+v", p3)
	}
	ingested(t, e, cmd3, "10.0.0.2")
	if s := State(e.intg); s.Reimport != nil || !s.RecycleNext {
		t.Fatalf("after the reimport: %+v", s)
	}
}

func TestRotation_Recycle_RefusedKeepsTheRecycle(t *testing.T) {
	e, _ := rotationEnv(t, "recycle")
	cmd1, _ := dispatchBatch(t, e, 10, "10.0.0.1")
	ingested(t, e, cmd1, "10.0.0.1")
	cmd2, p2 := dispatchBatch(t, e, 10, "10.0.0.2")
	if !p2.RecycleRepository || p2.RotationMode != "recycle" {
		t.Fatalf("payload %+v", p2)
	}
	failBatch(t, e, cmd2, `tenable.sc scan on "sc-prod": tenable.sc connector refused the job: rotation repository "openctem-rot-b": replacement 12 fails the checks, nothing was deleted: its IP range does not cover target 10.0.0.2`)
	if s := State(e.intg); s.RotationStalled != "" || !s.RecycleNext {
		t.Fatalf("state %+v", s)
	}
}

func TestBlockedResultID(t *testing.T) {
	for msg, want := range map[string]int{
		"IMPORT_BLOCKED: x (scan_result_id=42) (licensed 1)": 42,
		"IMPORT_BLOCKED: x":                                  0,
		"IMPORT_BLOCKED: x (scan_result_id=0)":               0,
		"IMPORT_BLOCKED: (scan_result_id=99999999999999999)": 0,
	} {
		if got := blockedResultID(msg); got != want {
			t.Fatalf("%q: %d, want %d", msg, got, want)
		}
	}
}

func TestParseTenableConfig_RotationWait(t *testing.T) {
	ack := map[string]any{"coverage_rotation": "aging", "coverage_rotation_acknowledged": true}
	c, err := scancoverage.ParseTenableConfig(ack)
	if err != nil || c.RotationWaitHours != 26 {
		t.Fatalf("default %+v %v", c, err)
	}
	for v, ok := range map[float64]bool{12: false, 23: false, 24: true, 72: true, 73: false} {
		m := map[string]any{"coverage_rotation": "aging", "coverage_rotation_acknowledged": true, "coverage_rotation_wait_hours": v}
		if _, err := scancoverage.ParseTenableConfig(m); (err == nil) != ok {
			t.Fatalf("wait %v: %v", v, err)
		}
	}
	if _, err := scancoverage.ParseTenableConfig(map[string]any{"coverage_rotation": "purge"}); err == nil {
		t.Fatal("purge without the acknowledgement")
	}
	if c, err := scancoverage.ParseTenableConfig(map[string]any{"coverage_rotation": "purge", "coverage_rotation_acknowledged": true}); err != nil || c.Rotation != scancoverage.RotationPurge {
		t.Fatalf("purge %+v %v", c, err)
	}
}
