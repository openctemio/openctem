package postgres

// The address filter (findings asset_ip, the query language's asset.ip and
// assets ip): a range compiles to one btree range scan per value on
// idx_assets_ip_addr, pinned to the tenant, and matches exactly the
// ip_address assets inside the range.

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/filterspec"
)

func TestAssetIPFilter_IndexAndExactRange(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	mine, other := seedTestTenant(ctx, t, sqlDB), seedTestTenant(ctx, t, sqlDB)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := sqlDB.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	// 5,000 addresses per tenant (10.77.x.y), names and ranges that are not
	// addresses, and one finding per asset.
	for _, tn := range []shared.ID{mine, other} {
		exec(`INSERT INTO assets (id, tenant_id, name, asset_type)
			SELECT gen_random_uuid(), $1, '10.77.' || (g / 250) || '.' || (g % 250), 'ip_address' FROM generate_series(0, 4999) g`, tn.String())
		exec(`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES
			(gen_random_uuid(), $1, '10.77.0.0/16', 'ip_address'), (gen_random_uuid(), $1, 'ipt.example.com', 'domain'),
			(gen_random_uuid(), $1, '2001:db8::7', 'ip_address'), (gen_random_uuid(), $1, '10.77.250.1', 'host')`, tn.String())
		exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status)
			SELECT gen_random_uuid(), a.tenant_id, a.id, 'sca', 'ip-test', 'm', 'high', a.id::text, 'new' FROM assets a WHERE a.tenant_id = $1`, tn.String())
	}
	exec(`ANALYZE assets`)
	exec(`ANALYZE findings`)

	actor := filterspec.SystemActor(mine, "test")
	where := func(ranges ...string) (string, []any) {
		t.Helper()
		vals := make([]any, len(ranges))
		for i, r := range ranges {
			vals[i] = r
		}
		spec := &filterspec.Spec{Root: &filterspec.Node{Leaf: &filterspec.Leaf{Field: "asset_ip", Op: filterspec.OpIn, Values: vals}}}
		w, err := filterspec.Compile(spec, vulnerability.FindingFields, actor)
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		return w.SQL, w.Args
	}
	names := func(ranges ...string) []string {
		t.Helper()
		w, args := where(ranges...)
		rows, err := sqlDB.QueryContext(ctx, `SELECT a.name FROM findings JOIN assets a ON a.id = findings.asset_id WHERE `+w+` ORDER BY 1`, args...) //nolint:gosec // compiled filter
		if err != nil {
			t.Fatalf("query: %v", err)
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var n string
			if err := rows.Scan(&n); err != nil {
				t.Fatal(err)
			}
			out = append(out, n)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return out
	}

	// Exact: one address, a /24 boundary, IPv6; never a range-named asset, a
	// host asset or the other tenant.
	if got := names("10.77.3.17"); !slices.Equal(got, []string{"10.77.3.17"}) {
		t.Errorf("one address = %v", got)
	}
	if got := names("10.77.19.0/24"); len(got) != 250 || got[0] != "10.77.19.0" {
		t.Errorf("/24 = %d rows, first %v", len(got), got[:min(1, len(got))])
	}
	if got := names("10.77.0.0/16"); len(got) != 5000 {
		t.Errorf("/16 = %d rows, want the 5000 addresses of this tenant only", len(got))
	}
	if got := names("2001:db8::/32"); !slices.Equal(got, []string{"2001:db8::7"}) {
		t.Errorf("v6 = %v", got)
	}
	if got := names("10.77.3.17", "10.77.4.0/30"); len(got) != 5 {
		t.Errorf("two values = %v", got)
	}
	if got := names("192.0.2.0/24"); len(got) != 0 {
		t.Errorf("no match = %v", got)
	}

	// Plan shape: the index serves the range, tenant first.
	w, args := where("10.77.19.0/24", "10.77.3.17")
	plan := explainLines(ctx, t, sqlDB, `SELECT findings.id FROM findings WHERE `+w, args...)
	if !strings.Contains(plan, "idx_assets_ip_addr") {
		t.Fatalf("plan does not use idx_assets_ip_addr:\n%s", plan)
	}
	if strings.Contains(plan, "Seq Scan on assets") {
		t.Fatalf("plan reads every asset:\n%s", plan)
	}
}
