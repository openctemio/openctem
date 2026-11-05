package postgres

// The findings list "seen by" filters (docs/architecture/finding-sightings.md):
// each narrows the caller's own findings, never crosses the tenant or the
// data scope, the sensor filter needs sensors:read, and every arm is served
// by an index of finding_sightings (EXPLAIN on a seeded table).

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/ingestreceipt"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/filterspec"
)

func sightingWhere(t *testing.T, actor filterspec.Actor, q string) (*filterspec.Where, error) {
	t.Helper()
	v, err := url.ParseQuery(q)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := filterspec.ParseValues(v, vulnerability.FindingFields, filterspec.Options{Unknown: filterspec.UnknownStrict})
	if err != nil {
		return nil, err
	}
	return filterspec.Compile(spec, vulnerability.FindingFields, actor)
}

func countSighted(t *testing.T, f *receiptFixture, actor filterspec.Actor, q string) int {
	t.Helper()
	where, err := sightingWhere(t, actor, q)
	if err != nil {
		t.Fatalf("compile %q: %v", q, err)
	}
	var n int
	if err := f.db.QueryRowContext(f.ctx, `SELECT count(*) FROM findings WHERE `+where.SQL, where.Args...).Scan(&n); err != nil {
		t.Fatalf("query %q: %v", q, err)
	}
	return n
}

func TestFindingSightings_Filters_DB(t *testing.T) {
	f := newReceiptFixture(t)
	hiddenAsset := seedTestAsset(f.ctx, t, f.db, f.tenant)
	sensor := f.sensor(f.tenant)
	scan, run, _, cmd := f.runCommand(f.tenant)
	visible := f.finding(f.tenant, f.asset, "fp-flt-visible", "new")
	hidden := f.finding(f.tenant, hiddenAsset, "fp-flt-hidden", "new")
	uploaded := f.finding(f.tenant, f.asset, "fp-flt-upload", "new")
	c := cmd
	f.record(&ingestreceipt.Delta{TenantID: f.tenant, Source: ingestreceipt.Source{Kind: ingestreceipt.SourceCommand, CommandID: &c},
		Tool: "nuclei", Instance: ingestreceipt.Instance{Kind: ingestreceipt.InstanceSensor, ID: sensor.String()},
		Reports: 1, Created: []shared.ID{visible, hidden}})
	f.record(&ingestreceipt.Delta{TenantID: f.tenant, Source: ingestreceipt.Source{Kind: ingestreceipt.SourceUpload, Ref: shared.NewID().String()},
		Tool: "nessus", Instance: ingestreceipt.Instance{Kind: ingestreceipt.InstanceImport, ID: ingestreceipt.InstanceImport},
		Reports: 1, Created: []shared.ID{uploaded}, StillDetected: []string{"fp-flt-visible"}})

	// Another tenant: its own sensor, scan and run report its finding.
	other := seedTestTenant(f.ctx, t, f.db)
	otherSensor := f.sensor(other)
	otherScan, otherRun, _, otherCmd := f.runCommand(other)
	otherFinding := f.finding(other, seedTestAsset(f.ctx, t, f.db, other), "fp-flt-other", "new")
	oc := otherCmd
	if _, err := f.repo.Record(f.ctx, &ingestreceipt.Delta{TenantID: other, Source: ingestreceipt.Source{Kind: ingestreceipt.SourceCommand, CommandID: &oc},
		Tool: "nuclei", Instance: ingestreceipt.Instance{Kind: ingestreceipt.InstanceSensor, ID: otherSensor.String()},
		Reports: 1, Created: []shared.ID{otherFinding}}); err != nil {
		t.Fatal(err)
	}

	all := func(string) bool { return true }
	admin, err := filterspec.UserActor(filterspec.UserActorInput{TenantID: f.tenant, UserID: shared.NewID(), IsAdmin: true, Has: all})
	if err != nil {
		t.Fatal(err)
	}
	for q, want := range map[string]int{
		"seen_by_sensor_id=" + sensor.String():      2,
		"seen_by_scan_id=" + scan.String():          2,
		"seen_in_run_id=" + run.String():            2,
		"seen_by_tool=nuclei":                       2,
		"seen_by_tool=nessus":                       2, // the upload created one and saw the visible one again
		"seen_by_tool=nuclei,nessus":                3,
		"seen_by_channel=upload":                    2,
		"seen_by_channel=scan":                      2,
		"seen_by_channel=ci":                        0,
		"seen_by_tool=nessus&seen_by_channel=scan":  1,
		"seen_by_sensor_id=" + otherSensor.String(): 0, // another tenant's sensor
		"seen_by_scan_id=" + otherScan.String():     0,
		"seen_in_run_id=" + otherRun.String():       0,
	} {
		if got := countSighted(t, f, admin, q); got != want {
			t.Errorf("admin %s = %d, want %d", q, got, want)
		}
	}

	// A restricted member sees only the visible asset's findings, whatever
	// the filter: the hidden finding the same sensor reported is not counted.
	user := shared.NewID()
	if _, err := f.db.ExecContext(f.ctx, `INSERT INTO users (id, email, name) VALUES ($1, $2, 'sighting-scope')`,
		user.String(), user.String()+"@sighting.test"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.db.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, user.String())
	})
	if _, err := f.db.ExecContext(f.ctx, `INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id) VALUES ($1, $2, $3)`,
		user.String(), f.tenant.String(), f.asset.String()); err != nil {
		t.Fatal(err)
	}
	withSensors := func(p string) bool { return p == string(permission.SensorsRead) }
	restricted, err := filterspec.UserActor(filterspec.UserActorInput{TenantID: f.tenant, UserID: user,
		Scope: &shared.DataScope{TenantID: f.tenant, UserID: user}, Has: withSensors})
	if err != nil {
		t.Fatal(err)
	}
	for q, want := range map[string]int{
		"seen_by_sensor_id=" + sensor.String(): 1,
		"seen_in_run_id=" + run.String():       1,
		"seen_by_tool=nuclei":                  1,
	} {
		if got := countSighted(t, f, restricted, q); got != want {
			t.Errorf("restricted %s = %d, want %d", q, got, want)
		}
	}

	// Without sensors:read the sensor filter is an unknown field (the same
	// answer as a field that does not exist: no oracle).
	noSensors, err := filterspec.UserActor(filterspec.UserActorInput{TenantID: f.tenant, UserID: shared.NewID(), IsAdmin: false,
		Has: func(string) bool { return false }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sightingWhere(t, noSensors, "seen_by_sensor_id="+sensor.String()); err == nil {
		t.Fatal("sensor filter compiled without sensors:read")
	}
	if _, err := sightingWhere(t, noSensors, "seen_by_tool=nuclei"); err != nil {
		t.Fatalf("tool filter refused: %v", err)
	}
}

// Every sightings filter is served by an index: on a seeded table (another
// tenant holds the bulk) the plan reads finding_sightings through one of its
// indexes, never a sequential scan.
func TestFindingSightings_FiltersUseIndexes_DB(t *testing.T) {
	f := newReceiptFixture(t)
	// The caller's own tenant holds the bulk: 20,000 findings, each seen by
	// another sensor, scan and tool, and 2,000 run receipts acting on them.
	noiseSensor := f.sensor(f.tenant)
	if _, err := f.db.ExecContext(f.ctx, `
		INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status)
		SELECT gen_random_uuid(), $1, $2, 'dast', 'nuclei', 'm', 'high', 'fp-noise-' || g, 'new'
		FROM generate_series(1, 20000) g`, f.tenant.String(), f.asset.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.ExecContext(f.ctx, `
		INSERT INTO finding_sightings (tenant_id, finding_id, channel, sensor_id, sender, tool, scan_id, first_seen_at, last_seen_at)
		SELECT n.tenant_id, n.id, (ARRAY['task','sensor','upload','ci'])[1 + (n.rn % 4)::int], $2::uuid, '',
			'tool-' || (n.rn % 50), gen_random_uuid(), now(), now()
		FROM (SELECT f.tenant_id, f.id, row_number() OVER () AS rn FROM findings f WHERE f.tenant_id = $1) n`,
		f.tenant.String(), noiseSensor.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.ExecContext(f.ctx, `
		WITH r AS (
			INSERT INTO ingest_receipts (id, tenant_id, source_kind, source_ref, status)
			SELECT gen_random_uuid(), $1, 'scan_run', gen_random_uuid()::text, 'completed' FROM generate_series(1, 2000)
			RETURNING id
		), rn AS (SELECT id, row_number() OVER () AS k FROM r),
		fn AS (SELECT id, row_number() OVER () AS k FROM findings WHERE tenant_id = $1)
		INSERT INTO finding_ingest_actions (tenant_id, receipt_id, finding_id, action)
		SELECT $1, rn.id, fn.id, 'still_detected' FROM fn JOIN rn ON rn.k = 1 + (fn.k % 2000)`, f.tenant.String()); err != nil {
		t.Fatal(err)
	}
	sensor := f.sensor(f.tenant)
	scan, run, _, cmd := f.runCommand(f.tenant)
	mine := f.finding(f.tenant, f.asset, "fp-plan", "new")
	c := cmd
	f.record(&ingestreceipt.Delta{TenantID: f.tenant, Source: ingestreceipt.Source{Kind: ingestreceipt.SourceCommand, CommandID: &c},
		Tool: "nuclei", Instance: ingestreceipt.Instance{Kind: ingestreceipt.InstanceSensor, ID: sensor.String()},
		Reports: 1, Created: []shared.ID{mine}})
	for _, tbl := range []string{"findings", "finding_sightings", "finding_ingest_actions", "ingest_receipts"} {
		if _, err := f.db.ExecContext(f.ctx, `ANALYZE `+tbl); err != nil {
			t.Fatal(err)
		}
	}
	admin, err := filterspec.UserActor(filterspec.UserActorInput{TenantID: f.tenant, UserID: shared.NewID(), IsAdmin: true,
		Has: func(string) bool { return true }})
	if err != nil {
		t.Fatal(err)
	}
	for q, index := range map[string]string{
		"seen_by_sensor_id=" + sensor.String(): "idx_finding_sightings_sensor",
		"seen_by_scan_id=" + scan.String():     "idx_finding_sightings_scan",
		"seen_by_tool=nuclei":                  "idx_finding_sightings_tool",
		"seen_by_channel=scan":                 "idx_finding_sightings_channel",
		"seen_in_run_id=" + run.String():       "ux_ingest_receipts_source",
	} {
		where, err := sightingWhere(t, admin, q)
		if err != nil {
			t.Fatalf("compile %q: %v", q, err)
		}
		p := explainPlan(t, f, where)
		if !strings.Contains(p, index) || strings.Contains(p, "Seq Scan on finding_sightings") {
			t.Errorf("%s: plan does not use %s:\n%s", q, index, p)
		}
	}
}

func explainPlan(t *testing.T, f *receiptFixture, where *filterspec.Where) string {
	t.Helper()
	rows, err := f.db.QueryContext(f.ctx, `EXPLAIN SELECT id FROM findings WHERE `+where.SQL, where.Args...)
	if err != nil {
		t.Fatalf("explain: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var plan strings.Builder
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			t.Fatal(err)
		}
		plan.WriteString(line + "\n")
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return plan.String()
}
