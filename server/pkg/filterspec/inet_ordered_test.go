package filterspec

import (
	"net/url"
	"slices"
	"strings"
	"testing"
)

const inetTpl = "f.asset_id IN (SELECT a.id FROM assets a WHERE a.tenant_id = {tenant} AND ip(a.name) BETWEEN lo({arg}) AND hi({arg}))"

func inetRegistry(t *testing.T) *Registry {
	t.Helper()
	reg, err := NewRegistry(Registry{Name: "findings", TenantSQL: "f.tenant_id", ScopeAssetSQL: "f.asset_id", IDSQL: "f.id"},
		Field{Name: "asset_ip", Type: TypeInet, Ops: []Op{OpIn}, SQL: "f.asset_id", Templates: map[Op]string{OpIn: inetTpl}},
		Field{Name: "severity", Type: TypeEnum, Enum: []string{"critical", "high", "medium", "low", "info"}, Ordered: true, Ops: []Op{OpIn, OpNotIn}, SQL: "f.severity"},
		Field{Name: "status", Type: TypeEnum, Enum: []string{"new", "resolved"}, Ops: []Op{OpIn}, SQL: "f.status"},
	)
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	return reg
}

func TestParseInet(t *testing.T) {
	ok := map[string]string{
		"10.1.2.3":                "10.1.2.3",
		" 10.0.0.0/8 ":            "10.0.0.0/8",
		"10.1.2.3/8":              "10.0.0.0/8", // masked
		"192.168.0.1/32":          "192.168.0.1/32",
		"2001:DB8::1":             "2001:db8::1",
		"[2001:db8::1]":           "2001:db8::1",
		"2001:db8::/32":           "2001:db8::/32",
		"::ffff:10.1.2.3":         "10.1.2.3",
		"::ffff:10.0.0.0/104":     "10.0.0.0/8",
		"0.0.0.0/0":               "0.0.0.0/0",
		"255.255.255.255":         "255.255.255.255",
		"fe80::1234:5678:9abc:de": "fe80::1234:5678:9abc:de",
	}
	for in, want := range ok {
		got, err := ParseInet(in)
		if err != nil || got != want {
			t.Errorf("ParseInet(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "10.0.0", "10.0.0.256", "10.0.0.0/33", "fe80::1%eth0", "example.com", "10.0.0.0/8; DROP", "1.2.3.4/", "/8", strings.Repeat("1", 70)} {
		if got, err := ParseInet(bad); err == nil {
			t.Errorf("ParseInet(%q) = %q, want an error", bad, got)
		} else if err != errInet { //nolint:errorlint // the one constant error
			t.Errorf("ParseInet(%q): error is not the constant message: %v", bad, err)
		}
	}
}

func TestInetField_CompilesOneBoundRangePerValue(t *testing.T) {
	reg := inetRegistry(t)
	spec, err := ParseValues(url.Values{"asset_ip": {"10.0.0.0/8,192.168.1.7"}}, reg, Options{Unknown: UnknownStrict})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	w, err := Compile(spec, reg, adminActor(t))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	// Two values: an OR of the template, each value bound once as inet and
	// used for both bounds.
	if strings.Count(w.SQL, "BETWEEN") != 2 || !strings.Contains(w.SQL, " OR ") {
		t.Fatalf("SQL = %s", w.SQL)
	}
	if strings.Contains(w.SQL, "10.0.0.0") || strings.Contains(w.SQL, "192.168") {
		t.Fatalf("a value reached the SQL text: %s", w.SQL)
	}
	if !strings.Contains(w.SQL, "lo($2::inet) AND hi($2::inet)") || !strings.Contains(w.SQL, "lo($3::inet) AND hi($3::inet)") {
		t.Fatalf("values not bound once per template: %s", w.SQL)
	}
	if !slices.Contains(w.Args, any("10.0.0.0/8")) || !slices.Contains(w.Args, any("192.168.1.7")) {
		t.Fatalf("args = %v", w.Args)
	}

	// A bad address is a 400 that does not run.
	if _, err := ParseValues(url.Values{"asset_ip": {"10.0.0.300"}}, reg, Options{Unknown: UnknownStrict}); err == nil {
		t.Fatal("a bad address parsed")
	}
	// Documents take the same values.
	if _, err := ParseDocument([]byte(`{"v":1,"filter":{"field":"asset_ip","op":"in","value":["2001:db8::/32"]}}`), reg, Options{Unknown: UnknownStrict}); err != nil {
		t.Fatalf("document: %v", err)
	}
	for _, doc := range []string{
		`{"v":1,"filter":{"field":"asset_ip","op":"eq","value":"10.0.0.1"}}`,
		`{"v":1,"filter":{"field":"asset_ip","op":"in","value":[167772161]}}`,
	} {
		if _, err := ParseDocument([]byte(doc), reg, Options{Unknown: UnknownStrict}); err == nil {
			t.Errorf("document %s parsed", doc)
		}
	}
}

func TestInetField_Validation(t *testing.T) {
	base := Registry{Name: "x", TenantSQL: "t.tenant_id", ScopeAssetSQL: "t.asset_id", IDSQL: "t.id"}
	for name, f := range map[string]Field{
		"no template": {Name: "ip", Type: TypeInet, Ops: []Op{OpIn}, SQL: "t.ip"},
		"not_in":      {Name: "ip", Type: TypeInet, Ops: []Op{OpIn, OpNotIn}, SQL: "t.ip", Templates: map[Op]string{OpIn: "t.ip <<= {arg}"}},
		"range op":    {Name: "ip", Type: TypeInet, Ops: []Op{OpGte}, SQL: "t.ip"},
		"sortable":    {Name: "ip", Type: TypeInet, Ops: []Op{OpIn}, SQL: "t.ip", Sortable: true, Templates: map[Op]string{OpIn: "t.ip <<= {arg}"}},
		"ordered str": {Name: "s", Type: TypeString, Ordered: true, Ops: []Op{OpIn}, SQL: "t.s"},
		"glob enum":   {Name: "s", Type: TypeEnum, Enum: []string{"a"}, Glob: true, Ops: []Op{OpIn}, SQL: "t.s"},
	} {
		if _, err := NewRegistry(base, f); err == nil {
			t.Errorf("%s: registry accepted", name)
		}
	}
}

func TestOrderedValues(t *testing.T) {
	reg := inetRegistry(t)
	sev, _ := reg.Field("severity")
	cases := []struct {
		op   Op
		v    string
		want []string
	}{
		{OpGte, "high", []string{"critical", "high"}},
		{OpGte, "HIGH", []string{"critical", "high"}},
		{OpGt, "high", []string{"critical"}},
		{OpLte, "medium", []string{"medium", "low", "info"}},
		{OpLt, "medium", []string{"low", "info"}},
		{OpGte, "info", []string{"critical", "high", "medium", "low", "info"}},
		{OpGt, "critical", []string{}},
	}
	for _, c := range cases {
		got, ok := sev.OrderedValues(c.op, c.v)
		if !ok || !slices.Equal(got, c.want) {
			t.Errorf("%s %s = %v, %v; want %v", c.op, c.v, got, ok, c.want)
		}
	}
	if _, ok := sev.OrderedValues(OpIn, "high"); ok {
		t.Error("in is not a range")
	}
	if _, ok := sev.OrderedValues(OpGte, "urgent"); ok {
		t.Error("unknown value accepted")
	}
	st, _ := reg.Field("status")
	if _, ok := st.OrderedValues(OpGte, "new"); ok {
		t.Error("unordered enum answered")
	}
}

func TestDescribe_InetType(t *testing.T) {
	d := inetRegistry(t).Describe(func(string) bool { return true })
	for _, f := range d.Fields {
		if f.Name == "asset_ip" && f.Type != "inet" {
			t.Fatalf("asset_ip type = %q", f.Type)
		}
	}
}
