package postgres

// The findings list filter retired_source_only
// (docs/architecture/source-retirement.md): every source that reported the
// finding is one of the tenant's live retirements. It narrows what the
// caller already sees: another tenant's retirements and sightings never
// count, and a finding outside the data scope is never returned.

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/sourceretire"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/filterspec"
)

func retiredOnlyIDs(t *testing.T, f *retireFixture, actor filterspec.Actor, q string) map[shared.ID]bool {
	t.Helper()
	v, err := url.ParseQuery(q)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := filterspec.ParseValues(v, vulnerability.FindingFields, filterspec.Options{Unknown: filterspec.UnknownStrict})
	if err != nil {
		t.Fatalf("parse %q: %v", q, err)
	}
	where, err := filterspec.Compile(spec, vulnerability.FindingFields, actor)
	if err != nil {
		t.Fatalf("compile %q: %v", q, err)
	}
	rows, err := f.db.QueryContext(f.ctx, `SELECT id::text FROM findings WHERE `+where.SQL, where.Args...)
	if err != nil {
		t.Fatalf("query %q: %v", q, err)
	}
	defer func() { _ = rows.Close() }()
	out := map[shared.ID]bool{}
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		id, err := shared.IDFromString(s)
		if err != nil {
			t.Fatal(err)
		}
		out[id] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestFindingRetiredSourceOnlyFilter_DB(t *testing.T) {
	f := newRetireFixture(t)
	sensor := f.sensor
	other := seedTestTenant(f.ctx, t, f.db)
	otherSensor := f.receiptFixture.sensor(other)

	// Retired: the junk tool of the sensor, the tool "old" of uploads.
	f.create(f.tenant, f.selector(), sourceretire.Options{})
	f.create(f.tenant, sourceretire.Selector{Kind: sourceretire.KindUpload, Tool: "old"}, sourceretire.Options{})
	restored := f.create(f.tenant, sourceretire.Selector{Kind: sourceretire.KindConnector, Sender: "gone-connector"}, sourceretire.Options{})
	if _, err := f.db.ExecContext(f.ctx, `UPDATE source_retirements SET state = 'restored', restored_at = now() WHERE id = $1`, restored.ID.String()); err != nil {
		t.Fatal(err)
	}

	only := f.seed(f.tenant, "fp-ro-only", "new", "high")
	f.junk(f.tenant, only)
	onlyTwo := f.seed(f.tenant, "fp-ro-two", "confirmed", "low") // two retired sources
	f.junk(f.tenant, onlyTwo)
	f.sight(f.tenant, onlyTwo, "upload", nil, "", "OLD")
	archivedOnly := f.seed(f.tenant, "fp-ro-closed", "resolved", "medium") // a closed finding is still only-retired
	f.junk(f.tenant, archivedOnly)
	mixed := f.seed(f.tenant, "fp-ro-mixed", "new", "high") // retired + live
	f.junk(f.tenant, mixed)
	f.sight(f.tenant, mixed, "scan", &sensor, "", "nuclei")
	restoredOnly := f.seed(f.tenant, "fp-ro-restored", "new", "high") // restored retirement: source live again
	f.sight(f.tenant, restoredOnly, "connector", nil, "gone-connector", "")
	noSighting := f.seed(f.tenant, "fp-ro-none", "new", "high")
	person := f.seed(f.tenant, "fp-ro-person", "new", "high") // a person's channel owns it
	if _, err := f.db.ExecContext(f.ctx, `UPDATE findings SET source = 'pentest' WHERE id = $1`, person.String()); err != nil {
		t.Fatal(err)
	}
	f.junk(f.tenant, person)
	capped := f.seed(f.tenant, "fp-ro-cap", "new", "high") // at the cap another source may be unrecorded
	for i := range sourceretire.MaxSightingCap {
		tool := fmt.Sprintf("cap-%d", i)
		f.create(f.tenant, sourceretire.Selector{Kind: sourceretire.KindUpload, Tool: tool}, sourceretire.Options{})
		f.sight(f.tenant, capped, "upload", nil, "", tool)
	}
	hidden := f.seed(f.tenant, "fp-ro-hidden", "new", "high") // outside a restricted caller's data scope
	hiddenAsset := seedTestAsset(f.ctx, t, f.db, f.tenant)
	if _, err := f.db.ExecContext(f.ctx, `UPDATE findings SET asset_id = $2 WHERE id = $1`, hidden.String(), hiddenAsset.String()); err != nil {
		t.Fatal(err)
	}
	f.junk(f.tenant, hidden)

	// Another tenant: identical data. Its sighting of "junk" by the same
	// tool name must not make this tenant's finding retired-only, and its
	// own finding must never be returned here.
	otherOnly := f.seed(other, "fp-ro-other", "new", "high")
	f.sight(other, otherOnly, "scan", &otherSensor, "", "junk")
	otherRetired := f.seed(other, "fp-ro-other-ret", "new", "high")
	f.sight(other, otherRetired, "scan", &otherSensor, "", "junk")
	if _, err := f.db.ExecContext(f.ctx, `INSERT INTO source_retirements (tenant_id, kind, sensor_id, tool, mode, state, reason)
		VALUES ($1, 'sensor_tool', $2, 'junk', 'archive', 'active', 'other tenant retirement')`, other.String(), otherSensor.String()); err != nil {
		t.Fatal(err)
	}
	// This tenant's finding reported only by a source that only ANOTHER
	// tenant retired (same tool name, same kind): it is not retired here.
	foreign := f.seed(f.tenant, "fp-ro-foreign", "new", "high")
	f.sight(f.tenant, foreign, "upload", nil, "", "nessus")
	if _, err := f.db.ExecContext(f.ctx, `INSERT INTO source_retirements (tenant_id, kind, tool, mode, state, reason)
		VALUES ($1, 'upload', 'nessus', 'archive', 'active', 'other tenant retirement')`, other.String()); err != nil {
		t.Fatal(err)
	}

	all := func(string) bool { return true }
	admin, err := filterspec.UserActor(filterspec.UserActorInput{TenantID: f.tenant, UserID: shared.NewID(), IsAdmin: true, Has: all})
	if err != nil {
		t.Fatal(err)
	}
	got := retiredOnlyIDs(t, f, admin, "retired_source_only=true")
	want := map[shared.ID]bool{only: true, onlyTwo: true, archivedOnly: true, hidden: true}
	if len(got) != len(want) {
		t.Errorf("admin retired_source_only=true returned %d findings, want %d", len(got), len(want))
	}
	for id := range want {
		if !got[id] {
			t.Errorf("admin: finding %s missing", id)
		}
	}
	for name, id := range map[string]shared.ID{"mixed": mixed, "restored": restoredOnly, "no sighting": noSighting,
		"person owned": person, "at the cap": capped, "other tenant": otherOnly, "foreign retirement": foreign} {
		if got[id] {
			t.Errorf("admin: %s finding must not be retired-only", name)
		}
	}

	// =false is the complement within the caller's tenant and scope.
	notOnly := retiredOnlyIDs(t, f, admin, "retired_source_only=false")
	if notOnly[only] || !notOnly[mixed] || !notOnly[foreign] || notOnly[otherOnly] {
		t.Errorf("retired_source_only=false is not the complement: %v", notOnly)
	}

	// A restricted member sees only the visible asset's findings.
	user := shared.NewID()
	if _, err := f.db.ExecContext(f.ctx, `INSERT INTO users (id, email, name) VALUES ($1, $2, 'retired-only-scope')`,
		user.String(), user.String()+"@retired.test"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.db.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, user.String())
	})
	if _, err := f.db.ExecContext(f.ctx, `INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id) VALUES ($1, $2, $3)`,
		user.String(), f.tenant.String(), f.asset.String()); err != nil {
		t.Fatal(err)
	}
	restricted, err := filterspec.UserActor(filterspec.UserActorInput{TenantID: f.tenant, UserID: user,
		Scope: &shared.DataScope{TenantID: f.tenant, UserID: user}, Has: func(string) bool { return false }})
	if err != nil {
		t.Fatal(err)
	}
	scoped := retiredOnlyIDs(t, f, restricted, "retired_source_only=true")
	if scoped[hidden] {
		t.Fatal("a finding outside the caller's data scope was returned")
	}
	if len(scoped) != 3 || !scoped[only] || !scoped[onlyTwo] || !scoped[archivedOnly] {
		t.Errorf("restricted caller got %d findings, want the 3 visible ones", len(scoped))
	}
}

// The predicate is served by the (tenant_id, finding_id) index of
// finding_sightings: on a seeded table, with sequential scans off, the plan
// reads sightings through an index and never scans the table.
func TestFindingRetiredSourceOnlyFilterUsesIndex_DB(t *testing.T) {
	f := newRetireFixture(t)
	if _, err := f.db.ExecContext(f.ctx, `
		INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status)
		SELECT gen_random_uuid(), $1, $2, 'dast', 'nuclei', 'm', 'high', 'fp-ro-noise-' || g, 'new'
		FROM generate_series(1, 20000) g`, f.tenant.String(), f.asset.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.ExecContext(f.ctx, `
		INSERT INTO finding_sightings (tenant_id, finding_id, channel, sensor_id, sender, tool, first_seen_at, last_seen_at)
		SELECT f.tenant_id, f.id, 'scan', $2::uuid, '', 'tool-' || (abs(hashtext(f.id::text)) % 50), now(), now()
		FROM findings f WHERE f.tenant_id = $1`, f.tenant.String(), f.sensor.String()); err != nil {
		t.Fatal(err)
	}
	f.create(f.tenant, f.selector(), sourceretire.Options{})
	owner := testdb.OpenMigrator(t)
	for _, tbl := range []string{"findings", "finding_sightings", "source_retirements"} {
		if _, err := owner.ExecContext(f.ctx, `ANALYZE `+tbl); err != nil {
			t.Fatal(err)
		}
	}
	admin, err := filterspec.UserActor(filterspec.UserActorInput{TenantID: f.tenant, UserID: shared.NewID(), IsAdmin: true,
		Has: func(string) bool { return true }})
	if err != nil {
		t.Fatal(err)
	}
	v, _ := url.ParseQuery("retired_source_only=true&status=new")
	spec, err := filterspec.ParseValues(v, vulnerability.FindingFields, filterspec.Options{Unknown: filterspec.UnknownStrict})
	if err != nil {
		t.Fatal(err)
	}
	where, err := filterspec.Compile(spec, vulnerability.FindingFields, admin)
	if err != nil {
		t.Fatal(err)
	}
	p := explainPlan(t, f.receiptFixture, where)
	if strings.Contains(p, "Seq Scan on finding_sightings") {
		t.Errorf("sightings read by a sequential scan:\n%s", p)
	}
	t.Log(p)
}
