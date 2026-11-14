package postgres

// The address range filters match an asset when its name or any address it
// has is inside the range: a host named web01.example.com with 10.0.26.7 in
// its recorded addresses is inside 10.0.26.0/24. The assets ip filter, the
// findings asset_ip filter and smart group rules (in_cidr, through
// MatchingIDs) give the same answer, pinned to the tenant, from one index.

import (
	"context"
	"database/sql"
	"slices"
	"strings"
	"testing"

	"github.com/openctemio/openctem/server/internal/testdb"
	"github.com/openctemio/openctem/server/pkg/domain/asset"
	"github.com/openctemio/openctem/server/pkg/domain/assetlist"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/server/pkg/filterspec"
)

type rangeFixture struct {
	t      *testing.T
	ctx    context.Context
	db     *sql.DB
	tenant shared.ID
	names  map[shared.ID]string
}

func (f *rangeFixture) add(tenant shared.ID, name, typ, props string) shared.ID {
	f.t.Helper()
	id := shared.NewID()
	if _, err := f.db.ExecContext(f.ctx, `INSERT INTO assets (id, tenant_id, name, asset_type, properties) VALUES ($1, $2, $3, $4, $5::jsonb)`,
		id.String(), tenant.String(), name, typ, props); err != nil {
		f.t.Fatalf("seed %s: %v", name, err)
	}
	if _, err := f.db.ExecContext(f.ctx, `INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status)
		VALUES (gen_random_uuid(), $1, $2, 'sca', 'range-test', 'm', 'high', $3, 'new')`, tenant.String(), id.String(), id.String()); err != nil {
		f.t.Fatalf("seed finding of %s: %v", name, err)
	}
	f.names[id] = name
	return id
}

func (f *rangeFixture) query(q string, args ...any) []string {
	f.t.Helper()
	rows, err := f.db.QueryContext(f.ctx, q, args...)
	if err != nil {
		f.t.Fatalf("query: %v\n%s", err, q)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			f.t.Fatal(err)
		}
		out = append(out, n)
	}
	if err := rows.Err(); err != nil {
		f.t.Fatal(err)
	}
	slices.Sort(out)
	return out
}

// viaAssetsList is the Assets list's ip filter.
func (f *rangeFixture) viaAssetsList(ranges ...string) []string {
	f.t.Helper()
	vals := make([]any, len(ranges))
	for i, r := range ranges {
		vals[i] = r
	}
	w := compileAssets(f.t, filterspec.SystemActor(f.tenant, "range test"), leafDoc("ip", "in", vals))
	//nolint:gosec // G202: compiled from registry constants
	return f.query(`SELECT a.name FROM assets a WHERE a.tenant_id = '`+f.tenant.String()+`' AND a.deleted_at IS NULL AND `+w.SQL, w.Args...)
}

// viaFindings is the findings list's asset_ip filter.
func (f *rangeFixture) viaFindings(ranges ...string) []string {
	f.t.Helper()
	vals := make([]any, len(ranges))
	for i, r := range ranges {
		vals[i] = r
	}
	spec := &filterspec.Spec{Root: &filterspec.Node{Leaf: &filterspec.Leaf{Field: "asset_ip", Op: filterspec.OpIn, Values: vals}}}
	w, err := filterspec.Compile(spec, vulnerability.FindingFields, filterspec.SystemActor(f.tenant, "range test"))
	if err != nil {
		f.t.Fatalf("compile: %v", err)
	}
	//nolint:gosec // G202: compiled from registry constants
	return f.query(`SELECT DISTINCT a.name FROM findings JOIN assets a ON a.id = findings.asset_id
		WHERE findings.tenant_id = '`+f.tenant.String()+`' AND `+w.SQL, w.Args...)
}

// viaGroupRule is what a smart group rule with in_cidr matches.
func (f *rangeFixture) viaGroupRule(ranges ...string) []string {
	f.t.Helper()
	tid := f.tenant.String()
	flt := asset.NewFilter()
	flt.TenantID = &tid
	flt = flt.WithInCIDRs(ranges...)
	ids, err := NewAssetRepository(&DB{DB: f.db}).MatchingIDs(f.ctx, flt, "", 1000)
	if err != nil {
		f.t.Fatal(err)
	}
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, f.names[id])
	}
	slices.Sort(out)
	return out
}

func TestAddressRange_NameOrRecordedAddress_DB(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	f := &rangeFixture{t: t, ctx: ctx, db: db, names: map[shared.ID]string{}}
	f.tenant = seedTestTenant(ctx, t, db)
	other := seedTestTenant(ctx, t, db)

	f.add(f.tenant, "10.0.26.5", "ip_address", `{}`)
	f.add(f.tenant, "10.0.26.6", "host", `{}`)
	f.add(f.tenant, "web01.example.com", "host", `{"ip_addresses": ["10.0.26.7", "2001:db8:26::7"]}`)
	f.add(f.tenant, "db01.example.com", "host", `{"private_ip": "10.0.26.8", "public_ip": "198.51.100.8"}`)
	f.add(f.tenant, "fw01.example.com", "network", `{"ip_addresses": ["10.0.26.12"]}`)
	// A name resolving into the range is not an asset with that address.
	f.add(f.tenant, "www.example.com", "domain", `{"ip_addresses": ["10.0.26.9"]}`)
	f.add(f.tenant, "mail.example.com", "host", `{"ip_addresses": ["192.0.2.10"]}`)
	f.add(f.tenant, "junk.example.com", "host", `{"ip_addresses": ["not-an-address", "10.0.26.0/24", 7]}`)
	moved := f.add(f.tenant, "moved.example.com", "host", `{"ip_addresses": ["10.0.26.10"]}`)
	gone := f.add(f.tenant, "gone.example.com", "host", `{"ip_addresses": ["10.0.26.11"]}`)
	added := f.add(f.tenant, "later.example.com", "host", `{}`)
	// Another organization's host with an address in every range below.
	f.add(other, "web01.example.com", "host", `{"ip_addresses": ["10.0.26.7", "2001:db8:26::7"]}`)

	// An address that leaves (DHCP, a re-scan), a deleted asset, and an
	// address recorded after the asset was created.
	for q, id := range map[string]shared.ID{
		`UPDATE assets SET properties = '{"ip_addresses": ["192.0.2.11"]}' WHERE id = $1`: moved,
		`UPDATE assets SET deleted_at = now() WHERE id = $1`:                              gone,
		`UPDATE assets SET properties = '{"ip_addresses": ["10.0.26.13"]}' WHERE id = $1`: added,
	} {
		if _, err := db.ExecContext(ctx, q, id.String()); err != nil {
			t.Fatal(err)
		}
	}

	for _, c := range []struct {
		ranges []string
		want   []string
	}{
		{[]string{"10.0.26.0/24"}, []string{"10.0.26.5", "10.0.26.6", "db01.example.com", "fw01.example.com", "later.example.com", "web01.example.com"}},
		{[]string{"10.0.26.7"}, []string{"web01.example.com"}},
		{[]string{"10.0.26.7/32", "198.51.100.0/24"}, []string{"db01.example.com", "web01.example.com"}},
		{[]string{"2001:db8::/32"}, []string{"web01.example.com"}},
		{[]string{"2001:db8:26::7"}, []string{"web01.example.com"}},
		{[]string{"192.0.2.0/24"}, []string{"mail.example.com", "moved.example.com"}},
		{[]string{"203.0.113.0/24"}, nil},
	} {
		want := slices.Clone(c.want)
		slices.Sort(want)
		for how, got := range map[string][]string{
			"assets ip":     f.viaAssetsList(c.ranges...),
			"findings":      f.viaFindings(c.ranges...),
			"group in_cidr": f.viaGroupRule(c.ranges...),
		} {
			if !slices.Equal(got, want) {
				t.Errorf("%s %v = %v, want %v", how, c.ranges, got, want)
			}
		}
	}

	// A value that is not an address or a range is refused before any query.
	for _, bad := range []string{"10.0.0.999", "example.com", "10.0.0.0/33"} {
		if _, err := filterspec.ParseDocumentValue(leafDoc("ip", "in", []any{bad}), assetlist.Fields, filterspec.Options{}); err == nil {
			t.Errorf("ip=%s parsed, want a validation error", bad)
		}
	}
}

// An index serves the range on a tenant with many assets: with sequential
// scans disabled the plan still reads the address range index and never
// needs a sequential scan. The plan is logged.
func TestAddressRange_ExplainUsesIndex_DB(t *testing.T) {
	db := openSensorDB(t)
	owner := testdb.OpenMigrator(t)
	ctx := context.Background()
	mine, noise := seedTestTenant(ctx, t, db), seedTestTenant(ctx, t, db)
	for _, tn := range []shared.ID{mine, noise} {
		// 6,000 addresses and 3,000 hosts named by DNS name with two
		// addresses each, one finding per asset.
		for _, q := range []string{
			`INSERT INTO assets (id, tenant_id, name, asset_type)
			 SELECT uuid_generate_v7(), $1, '10.' || (g / 65536) % 256 || '.' || (g / 256) % 256 || '.' || g % 256, 'ip_address'
			 FROM generate_series(1, 6000) g`,
			`INSERT INTO assets (id, tenant_id, name, asset_type, properties)
			 SELECT uuid_generate_v7(), $1, 'h' || g || '.example.com', 'host',
			        jsonb_build_object('ip_addresses', jsonb_build_array('10.1.' || (g / 256) % 256 || '.' || g % 256, '2001:db8::' || to_hex(g)))
			 FROM generate_series(1, 3000) g`,
			`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status)
			 SELECT gen_random_uuid(), a.tenant_id, a.id, 'sca', 'range-test', 'm', 'high', a.id::text, 'new' FROM assets a WHERE a.tenant_id = $1`,
		} {
			if _, err := db.ExecContext(ctx, q, tn.String()); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := owner.ExecContext(ctx, `ANALYZE assets; ANALYZE findings; ANALYZE asset_ip_addresses`); err != nil {
		t.Fatal(err)
	}
	sys := filterspec.SystemActor(mine, "explain test")
	w := compileAssets(t, sys, leafDoc("ip", "in", []any{"10.1.3.0/24"}))
	spec := &filterspec.Spec{Root: &filterspec.Node{Leaf: &filterspec.Leaf{Field: "asset_ip", Op: filterspec.OpIn, Values: []any{"10.1.3.0/24", "2001:db8::/120"}}}}
	fw, err := filterspec.Compile(spec, vulnerability.FindingFields, sys)
	if err != nil {
		t.Fatal(err)
	}
	for name, q := range map[string]struct {
		sql  string
		args []any
	}{
		//nolint:gosec // G202: compiled from registry constants
		"assets ip": {"EXPLAIN (FORMAT JSON) SELECT a.id FROM assets a WHERE a.tenant_id = '" + mine.String() + "' AND a.deleted_at IS NULL AND " + w.SQL, w.Args},
		//nolint:gosec // G202: compiled from registry constants
		"findings asset_ip": {"EXPLAIN (FORMAT JSON) SELECT findings.id FROM findings WHERE findings.tenant_id = '" + mine.String() + "' AND " + fw.SQL, fw.Args},
	} {
		// Planner choice depends on statistics other tests in the same
		// database can change. Turn off the sequential scan for this
		// transaction only, so the plan proves an index path exists and is
		// usable, not that the planner prefers it on a given dataset.
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.ExecContext(ctx, `SET LOCAL enable_seqscan = off`); err != nil {
			_ = tx.Rollback()
			t.Fatal(err)
		}
		var raw []byte
		err = tx.QueryRowContext(ctx, q.sql, q.args...).Scan(&raw)
		_ = tx.Rollback()
		if err != nil {
			t.Fatalf("%s: explain: %v", name, err)
		}
		plan := planText(t, raw)
		t.Logf("%s plan: %s", name, plan)
		// The semi join reads the range from idx_asset_ip_addresses_range or
		// probes pk_asset_ip_addresses (tenant_id, asset_id, addr) per row,
		// whichever the planner sizes cheaper; both are index reads.
		if !strings.Contains(plan, "idx_asset_ip_addresses_range") && !strings.Contains(plan, "pk_asset_ip_addresses") {
			t.Errorf("%s: no index of asset_ip_addresses used: %s", name, plan)
		}
		for _, tbl := range []string{"assets", "findings", "asset_ip_addresses"} {
			if strings.Contains(plan, "Seq Scan on "+tbl+" ") {
				t.Errorf("%s: sequential scan of %s: %s", name, tbl, plan)
			}
		}
	}
}
