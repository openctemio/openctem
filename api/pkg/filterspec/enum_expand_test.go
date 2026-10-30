package filterspec

import (
	"database/sql/driver"
	"net/url"
	"strings"
	"testing"
)

// A value with EnumExpand also matches the stored values it names: one
// reporting bucket (Informational) kept as two stored values (info, none).
func TestEnumExpandMatchesTheWholeBucket(t *testing.T) {
	reg := MustRegistry(Registry{Name: "x", TenantSQL: "t.tenant_id", IDSQL: "t.id", Unscoped: "test"},
		Field{Name: "severity", Type: TypeEnum, Enum: []string{"high", "info", "none"}, Ops: []Op{OpIn, OpNotIn}, SQL: "t.severity",
			EnumExpand: map[string][]string{"info": {"none"}}})
	cases := []struct {
		raw, wantSQL, wantArg string
	}{
		{"severity=info", "(t.severity = ANY($2::text[]))", `{"info","none"}`},
		{"severity=high,info", "(t.severity = ANY($2::text[]))", `{"high","info","none"}`},
		{"severity=info,none", "(t.severity = ANY($2::text[]))", `{"info","none"}`},
		{"severity_not=info", "(t.severity <> ALL($2::text[]))", `{"info","none"}`},
		// A value without an expansion compiles as before.
		{"severity=high", "(t.severity = $2)", "high"},
		{"severity=none", "(t.severity = $2)", "none"},
	}
	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			q, err := url.ParseQuery(tc.raw)
			if err != nil {
				t.Fatal(err)
			}
			spec, err := ParseValues(q, reg, Options{Unknown: UnknownStrict})
			if err != nil {
				t.Fatal(err)
			}
			w, err := Compile(spec, reg, SystemActor(tenantA, "test"))
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(w.SQL, tc.wantSQL) {
				t.Fatalf("want %q in %s", tc.wantSQL, w.SQL)
			}
			got := w.Args[len(w.Args)-1]
			if v, ok := got.(driver.Valuer); ok {
				got, _ = v.Value()
			}
			var s string
			switch g := got.(type) {
			case string:
				s = g
			case []byte:
				s = string(g)
			}
			if s != tc.wantArg {
				t.Fatalf("arg = %v, want %s", got, tc.wantArg)
			}
			// The parsed spec is not changed by compiling it.
			if leaves := spec.Leaves(); len(leaves[0].Values) > 2 {
				t.Fatalf("spec values changed: %v", leaves[0].Values)
			}
		})
	}
}
