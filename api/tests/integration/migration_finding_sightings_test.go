package integration

// Migration finding_sightings: the backfill derives one sighting per
// finding and source from the receipt action log, then from what the
// finding row itself kept (an upload receipt id in scan_id, the platform's
// version-match tool, a sensor, a CI commit, an integration), labeled
// backfilled. A person's finding gets none, another tenant's sensor is
// never stored, and the down migration removes the table.
//
// Runs on a private database: everything, down to before the migration,
// seed, up, down, up.

import (
	"context"
	"math"
	"testing"

	"github.com/openctemio/openctem/api/internal/testdb"
)

func TestMigrationFindingSightingsBackfill(t *testing.T) {
	const dir = "../../migrations"
	v := testdb.MigrationVersion(t, dir, "finding_sightings")
	db := testdb.PrivateDatabase(t, "migsight", dir)
	testdb.Migrate(t, db, dir, v, math.MaxInt, true)

	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(context.Background(), q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	const (
		tenantA   = "a1111111-1111-4111-8111-111111111111"
		tenantB   = "b2222222-2222-4222-8222-222222222222"
		assetA    = "a3333333-3333-4333-8333-333333333333"
		sensorA   = "c1111111-1111-4111-8111-111111111111"
		sensorB   = "c2222222-2222-4222-8222-222222222222"
		scanA     = "d1111111-1111-4111-8111-111111111111"
		runA      = "d2222222-2222-4222-8222-222222222222"
		runRcpt   = "e1111111-1111-4111-8111-111111111111"
		upRcpt    = "e2222222-2222-4222-8222-222222222222"
		fRun      = "f1111111-1111-4111-8111-111111111111"
		fUpload   = "f2222222-2222-4222-8222-222222222222"
		fPlatform = "f3333333-3333-4333-8333-333333333333"
		fSensor   = "f4444444-4444-4444-8444-444444444444"
		fManual   = "f5555555-5555-4555-8555-555555555555"
		fUnknown  = "f6666666-6666-4666-8666-666666666666"
		fCrossSen = "f7777777-7777-4777-8777-777777777777"
	)
	exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'a', 'mig-sight-a'), ($2, 'b', 'mig-sight-b')`, tenantA, tenantB)
	exec(`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, 'app.example.test', 'domain')`, assetA, tenantA)
	exec(`INSERT INTO sensors (id, tenant_id, name, api_key_hash, api_key_prefix, status) VALUES
		($1, $2, 'sa', 'ha', 'p', 'active'), ($3, $4, 'sb', 'hb', 'p', 'active')`, sensorA, tenantA, sensorB, tenantB)
	exec(`INSERT INTO scans (id, tenant_id, name, scan_type, scanner_name) VALUES ($1, $2, 'weekly', 'single', 'nuclei')`, scanA, tenantA)
	exec(`INSERT INTO scan_runs (id, tenant_id, scan_id, trigger_type, status, kind) VALUES ($1, $2, $3, 'manual', 'completed', 'system')`,
		runA, tenantA, scanA)
	exec(`INSERT INTO ingest_receipts (id, tenant_id, source_kind, source_ref, tool_name, status) VALUES
		($1, $2, 'scan_run', $3, 'nuclei', 'completed'), ($4, $2, 'upload', $5, 'nessus', 'completed')`, runRcpt, tenantA, runA, upRcpt, upRcpt)
	exec(`INSERT INTO ingest_receipt_tools (tenant_id, receipt_id, tool, instance_kind, instance_id) VALUES ($1, $2, 'nuclei', 'sensor', $3)`,
		tenantA, runRcpt, sensorA)
	finding := func(id, tool string, extra string, args ...any) {
		t.Helper()
		exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status)
			VALUES ($1, $2, $3, 'dast', $4, 'm', 'high', 'fp-' || $5, 'new')`, id, tenantA, assetA, tool, id)
		if extra != "" {
			exec(`UPDATE findings SET `+extra+` WHERE id = $1`, append([]any{id}, args...)...)
		}
	}
	finding(fRun, "nuclei", "")
	exec(`INSERT INTO finding_ingest_actions (tenant_id, receipt_id, finding_id, action) VALUES ($1, $2, $3, 'created')`, tenantA, runRcpt, fRun)
	finding(fUpload, "nessus", "scan_id = $2", upRcpt)
	finding(fPlatform, "version-match", "")
	finding(fSensor, "naabu", "sensor_id = $2, ingest_channel = 'scanner', last_seen_tool = 'naabu-2'", sensorA)
	finding(fManual, "manual", "ingest_channel = 'manual'")
	finding(fUnknown, "semgrep", "")
	finding(fCrossSen, "nuclei", "sensor_id = $2, ingest_channel = 'scanner'", sensorB)

	testdb.Migrate(t, db, dir, v, math.MaxInt, false)

	type row struct {
		channel, sender, tool, sensor, scan, run, receipt string
		count                                             int
		backfilled                                        bool
	}
	get := func(finding string) []row {
		t.Helper()
		rs, err := db.QueryContext(context.Background(), `SELECT channel, sender, tool, COALESCE(sensor_id::text, ''), COALESCE(scan_id::text, ''),
			COALESCE(last_run_id::text, ''), COALESCE(last_receipt_id::text, ''), seen_count, backfilled
			FROM finding_sightings WHERE finding_id = $1`, finding)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = rs.Close() }()
		var out []row
		for rs.Next() {
			var r row
			if err := rs.Scan(&r.channel, &r.sender, &r.tool, &r.sensor, &r.scan, &r.run, &r.receipt, &r.count, &r.backfilled); err != nil {
				t.Fatal(err)
			}
			out = append(out, r)
		}
		if err := rs.Err(); err != nil {
			t.Fatal(err)
		}
		return out
	}
	want := map[string]row{
		fRun:      {channel: "scan", tool: "nuclei", sensor: sensorA, scan: scanA, run: runA, receipt: runRcpt, count: 1, backfilled: true},
		fUpload:   {channel: "upload", tool: "nessus", receipt: upRcpt, count: 1, backfilled: true},
		fPlatform: {channel: "platform", tool: "version-match", count: 1, backfilled: true},
		fSensor:   {channel: "sensor", tool: "naabu-2", sensor: sensorA, count: 1, backfilled: true},
		fUnknown:  {channel: "unknown", tool: "semgrep", count: 1, backfilled: true},
		// Another tenant's sensor on the finding row is never stored.
		fCrossSen: {channel: "sensor", tool: "nuclei", count: 1, backfilled: true},
	}
	for id, w := range want {
		got := get(id)
		if len(got) != 1 || got[0] != w {
			t.Errorf("finding %s: got %+v, want %+v", id, got, w)
		}
	}
	if got := get(fManual); len(got) != 0 {
		t.Errorf("a person's finding got a sighting: %+v", got)
	}

	// Down removes the table; up again rebuilds the same rows.
	testdb.Migrate(t, db, dir, v, math.MaxInt, true)
	var reg *string
	if err := db.QueryRowContext(context.Background(), `SELECT to_regclass('public.finding_sightings')::text`).Scan(&reg); err != nil || reg != nil {
		t.Fatalf("down left the table: %v %v", reg, err)
	}
	testdb.Migrate(t, db, dir, v, math.MaxInt, false)
	if got := get(fRun); len(got) != 1 || got[0] != want[fRun] {
		t.Fatalf("up again: %+v", got)
	}
}
