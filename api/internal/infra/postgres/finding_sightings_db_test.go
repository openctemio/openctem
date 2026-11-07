package postgres

// Finding sightings (docs/architecture/finding-sightings.md): one row per
// finding and source under repeats, every channel writes, tenant isolation,
// the per-finding cap, and the read.

import (
	"errors"
	"fmt"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/ingestreceipt"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func (f *receiptFixture) sensor(tenant shared.ID) shared.ID {
	f.t.Helper()
	id := shared.NewID()
	if _, err := f.db.ExecContext(f.ctx, `INSERT INTO sensors (id, tenant_id, name, api_key_hash, api_key_prefix, status)
		VALUES ($1, $2, $3, $4, 'p', 'active')`, id.String(), tenant.String(), "sensor-"+id.String()[:8], "h-"+id.String()); err != nil {
		f.t.Fatalf("seed sensor: %v", err)
	}
	return id
}

// runCommand seeds a scan definition, a run of it with one step, and a
// command of that step, in tenant.
func (f *receiptFixture) runCommand(tenant shared.ID) (scan, run, step, cmd shared.ID) {
	f.t.Helper()
	scan, run, step, cmd = shared.NewID(), shared.NewID(), shared.NewID(), shared.NewID()
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO scans (id, tenant_id, name, scan_type, scanner_name) VALUES ($1, $2, 'weekly', 'single', 'nuclei')`,
			[]any{scan.String(), tenant.String()}},
		{`INSERT INTO scan_runs (id, tenant_id, scan_id, trigger_type, status, kind) VALUES ($1, $2, $3, 'manual', 'running', 'system')`,
			[]any{run.String(), tenant.String(), scan.String()}},
		{`INSERT INTO scan_run_steps (id, scan_run_id, step_key, step_order, status) VALUES ($1, $2, 's', 1, 'running')`,
			[]any{step.String(), run.String()}},
		{`INSERT INTO commands (id, tenant_id, type, status, payload, scan_run_step_id) VALUES ($1, $2, 'scan', 'running', '{}', $3)`,
			[]any{cmd.String(), tenant.String(), step.String()}},
	} {
		if _, err := f.db.ExecContext(f.ctx, q.sql, q.args...); err != nil {
			f.t.Fatalf("seed run: %v", err)
		}
	}
	return scan, run, step, cmd
}

func (f *receiptFixture) sightings(finding shared.ID) []ingestreceipt.Sighting {
	f.t.Helper()
	rows, err := f.repo.FindingSightings(f.ctx, f.tenant, finding)
	if err != nil {
		f.t.Fatalf("sightings: %v", err)
	}
	return rows
}

// A scan run that reports the same finding in several reports, and a second
// run of the same scan, keep one row: the second run moves last seen and
// the last run, the repeats within one run count once.
func TestFindingSightings_OneRowPerSourceUnderRepeats_DB(t *testing.T) {
	f := newReceiptFixture(t)
	sensor := f.sensor(f.tenant)
	scan, run1, step1, cmd1 := f.runCommand(f.tenant)
	finding := f.finding(f.tenant, f.asset, "fp-repeat", "new")
	inst := ingestreceipt.Instance{Kind: ingestreceipt.InstanceSensor, ID: sensor.String()}
	delta := func(cmd shared.ID) *ingestreceipt.Delta {
		c := cmd
		return &ingestreceipt.Delta{TenantID: f.tenant, Source: ingestreceipt.Source{Kind: ingestreceipt.SourceCommand, CommandID: &c},
			Tool: "nuclei", ToolVersion: "3.4.1", Instance: inst, Reports: 1, Received: 1, StillDetected: []string{"fp-repeat"}}
	}
	for range 3 {
		f.record(delta(cmd1))
	}
	got := f.sightings(finding)
	if len(got) != 1 {
		t.Fatalf("after one run: %d rows, want 1", len(got))
	}
	s := got[0]
	if s.Channel != ingestreceipt.ChannelScan || s.SensorID == nil || *s.SensorID != sensor || s.ScanID == nil || *s.ScanID != scan ||
		s.LastRunID == nil || *s.LastRunID != run1 || s.LastStepRunID == nil || *s.LastStepRunID != step1 ||
		s.LastCommandID == nil || *s.LastCommandID != cmd1 || s.SeenCount != 1 || s.Tool != "nuclei" || s.ToolVersion != "3.4.1" ||
		!s.ReceiptKept || s.Backfilled || s.ScanName != "weekly" || s.SensorName == "" {
		t.Fatalf("sighting after one run = %+v", s)
	}

	// A second run of the same scan: another receipt.
	run2, step2, cmd2 := shared.NewID(), shared.NewID(), shared.NewID()
	for _, q := range []string{
		fmt.Sprintf(`INSERT INTO scan_runs (id, tenant_id, scan_id, trigger_type, status, kind) VALUES ('%s', '%s', '%s', 'manual', 'running', 'system')`, run2, f.tenant, scan),
		fmt.Sprintf(`INSERT INTO scan_run_steps (id, scan_run_id, step_key, step_order, status) VALUES ('%s', '%s', 's', 1, 'running')`, step2, run2),
		fmt.Sprintf(`INSERT INTO commands (id, tenant_id, type, status, payload, scan_run_step_id) VALUES ('%s', '%s', 'scan', 'running', '{}', '%s')`, cmd2, f.tenant, step2),
	} {
		if _, err := f.db.ExecContext(f.ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	f.record(delta(cmd2))
	f.record(delta(cmd2))
	got = f.sightings(finding)
	if len(got) != 1 || got[0].SeenCount != 2 || *got[0].LastRunID != run2 || *got[0].LastCommandID != cmd2 ||
		got[0].FirstSeenAt.After(got[0].LastSeenAt) {
		t.Fatalf("after two runs: %+v", got)
	}
	if n := f.count(`SELECT count(*) FROM finding_sightings WHERE tenant_id = $1`, f.tenant); n != 1 {
		t.Fatalf("rows = %d, want 1", n)
	}
}

// Every channel that books a receipt records its sighting, with its own
// channel and sender; a closure and a coverage decision are not sightings.
func TestFindingSightings_EveryChannelWrites_DB(t *testing.T) {
	f := newReceiptFixture(t)
	sensor := f.sensor(f.tenant)
	_, _, _, inRun := f.runCommand(f.tenant)
	lone := shared.NewID()
	if _, err := f.db.ExecContext(f.ctx, `INSERT INTO commands (id, tenant_id, type, status, payload) VALUES ($1, $2, 'scan', 'running', '{}')`,
		lone.String(), f.tenant.String()); err != nil {
		t.Fatal(err)
	}
	sensorInst := ingestreceipt.Instance{Kind: ingestreceipt.InstanceSensor, ID: sensor.String()}
	cases := []struct {
		name    string
		src     ingestreceipt.Source
		inst    ingestreceipt.Instance
		channel ingestreceipt.Channel
		sender  string
	}{
		{"scan", ingestreceipt.Source{Kind: ingestreceipt.SourceCommand, CommandID: &inRun}, sensorInst, ingestreceipt.ChannelScan, ""},
		{"task", ingestreceipt.Source{Kind: ingestreceipt.SourceCommand, CommandID: &lone}, sensorInst, ingestreceipt.ChannelTask, ""},
		{"sensor", ingestreceipt.Source{Kind: ingestreceipt.SourceSensor, Ref: ingestreceipt.ReportRef(sensor, "r1")}, sensorInst, ingestreceipt.ChannelSensor, ""},
		{"upload", ingestreceipt.Source{Kind: ingestreceipt.SourceUpload, Ref: shared.NewID().String()},
			ingestreceipt.Instance{Kind: ingestreceipt.InstanceImport, ID: ingestreceipt.InstanceImport}, ingestreceipt.ChannelUpload, ""},
		{"ci", ingestreceipt.Source{Kind: ingestreceipt.SourceCIRun, Ref: shared.NewID().String()},
			ingestreceipt.Instance{Kind: ingestreceipt.InstanceCI, ID: "github.com/acme/app"}, ingestreceipt.ChannelCI, "github.com/acme/app"},
		{"connector", ingestreceipt.Source{Kind: ingestreceipt.SourceConnector, Ref: "sync-1"},
			ingestreceipt.Instance{Kind: ingestreceipt.InstanceConnector, ID: "defectdojo"}, ingestreceipt.ChannelConnector, "defectdojo"},
		{"platform", ingestreceipt.Source{Kind: ingestreceipt.SourcePlatform, Ref: "version-match:2026-11-05"},
			ingestreceipt.Instance{Kind: ingestreceipt.InstancePlatform, ID: ingestreceipt.InstancePlatform}, ingestreceipt.ChannelPlatform, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			finding := f.finding(f.tenant, f.asset, "fp-ch-"+c.name, "new")
			f.record(&ingestreceipt.Delta{TenantID: f.tenant, Source: c.src, Tool: "tool-" + c.name, Instance: c.inst,
				Reports: 1, Received: 1, Created: []shared.ID{finding}})
			got := f.sightings(finding)
			if len(got) != 1 || got[0].Channel != c.channel || got[0].Sender != c.sender || got[0].Tool != "tool-"+c.name {
				t.Fatalf("%s: %+v", c.name, got)
			}
			if wantSensor := c.inst.Kind == ingestreceipt.InstanceSensor; wantSensor != (got[0].SensorID != nil) {
				t.Fatalf("%s: sensor = %v", c.name, got[0].SensorID)
			}
		})
	}

	// Not sightings: a closure by a coverage decision, a source mitigation.
	closed := f.finding(f.tenant, f.asset, "fp-closed-only", "resolved")
	cmd := lone
	f.record(&ingestreceipt.Delta{TenantID: f.tenant, Source: ingestreceipt.Source{Kind: ingestreceipt.SourceCommand, CommandID: &cmd},
		Tool: "nuclei", Closed: []shared.ID{closed}, Coverage: ingestreceipt.CoverageFull, CoverageNote: "resolved"})
	f.record(&ingestreceipt.Delta{TenantID: f.tenant, Source: ingestreceipt.Source{Kind: ingestreceipt.SourceCIRun, Ref: shared.NewID().String()},
		Tool: "trivy", Reports: 1, Closed: []shared.ID{closed}})
	if got := f.sightings(closed); len(got) != 0 {
		t.Fatalf("a closure recorded a sighting: %+v", got)
	}
}

// Tenant isolation: a delta can only name its own tenant's findings,
// sensor and command. Another tenant's sensor id is stored as the shared
// platform sender, another tenant's command gives no run or scan, another
// tenant's finding (by id or fingerprint) gets nothing, and the read of
// another tenant's finding is empty.
func TestFindingSightings_TenantIsolation_DB(t *testing.T) {
	f := newReceiptFixture(t)
	other := seedTestTenant(f.ctx, t, f.db)
	otherAsset := seedTestAsset(f.ctx, t, f.db, other)
	otherSensor := f.sensor(other)
	_, _, _, otherCmd := f.runCommand(other)
	mine := f.finding(f.tenant, f.asset, "fp-iso", "new")
	theirs := f.finding(other, otherAsset, "fp-iso", "new")
	theirsByID := f.finding(other, otherAsset, "fp-iso-2", "new")

	f.record(&ingestreceipt.Delta{TenantID: f.tenant, Source: ingestreceipt.Source{Kind: ingestreceipt.SourceSensor, Ref: "r-iso"},
		Tool: "nuclei", Instance: ingestreceipt.Instance{Kind: ingestreceipt.InstanceSensor, ID: otherSensor.String()},
		Reports: 1, Created: []shared.ID{theirsByID}, StillDetected: []string{"fp-iso"}})
	got := f.sightings(mine)
	if len(got) != 1 || got[0].SensorID != nil || got[0].Sender != ingestreceipt.SharedSensorSender {
		t.Fatalf("another tenant's sensor was stored: %+v", got)
	}
	if n := f.count(`SELECT count(*) FROM finding_sightings WHERE finding_id IN ($1, $2)`, theirs, theirsByID); n != 0 {
		t.Fatalf("another tenant's findings got %d sightings", n)
	}

	// Another tenant's command: the receipt write itself refuses it (the
	// command is not found under the tenant), so nothing is recorded.
	c := otherCmd
	if _, err := f.repo.Record(f.ctx, &ingestreceipt.Delta{TenantID: f.tenant, Source: ingestreceipt.Source{Kind: ingestreceipt.SourceCommand, CommandID: &c},
		Tool: "nuclei", Reports: 1, StillDetected: []string{"fp-iso"}}); err == nil {
		t.Fatalf("a delta with another tenant's command was recorded")
	}
	if got := f.sightings(mine); len(got) != 1 || got[0].ScanID != nil || got[0].LastRunID != nil {
		t.Fatalf("another tenant's run leaked: %+v", got)
	}
	// The other tenant reads nothing of mine.
	rows, err := f.repo.FindingSightings(f.ctx, other, mine)
	if !errors.Is(err, shared.ErrNotFound) || len(rows) != 0 {
		t.Fatalf("other tenant read my finding's sightings: %+v %v", rows, err)
	}
}

// At most MaxSightingsPerFinding sources per finding: a new source past the
// cap is not recorded, an existing one still moves.
func TestFindingSightings_PerFindingCap_DB(t *testing.T) {
	f := newReceiptFixture(t)
	finding := f.finding(f.tenant, f.asset, "fp-cap", "new")
	for i := range ingestreceipt.MaxSightingsPerFinding + 3 {
		f.record(&ingestreceipt.Delta{TenantID: f.tenant, Source: ingestreceipt.Source{Kind: ingestreceipt.SourceSensor, Ref: fmt.Sprintf("r-%d", i)},
			Tool: fmt.Sprintf("tool-%02d", i), Reports: 1, StillDetected: []string{"fp-cap"}})
	}
	if n := f.count(`SELECT count(*) FROM finding_sightings WHERE tenant_id = $1 AND finding_id = $2`, f.tenant, finding); n != ingestreceipt.MaxSightingsPerFinding {
		t.Fatalf("rows = %d, want %d", n, ingestreceipt.MaxSightingsPerFinding)
	}
	f.record(&ingestreceipt.Delta{TenantID: f.tenant, Source: ingestreceipt.Source{Kind: ingestreceipt.SourceSensor, Ref: "r-again"},
		Tool: "tool-00", Reports: 1, StillDetected: []string{"fp-cap"}})
	if n := f.count(`SELECT seen_count FROM finding_sightings WHERE tenant_id = $1 AND finding_id = $2 AND tool = 'tool-00'`, f.tenant, finding); n != 2 {
		t.Fatalf("existing source at the cap: seen_count = %d, want 2", n)
	}
}
