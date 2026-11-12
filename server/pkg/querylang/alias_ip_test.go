package querylang

import (
	"reflect"
	"testing"

	"github.com/openctemio/openctem/server/pkg/domain/permission"
	"github.com/openctemio/openctem/server/pkg/filterspec"
)

func TestAliasesAndAddressPaths(t *testing.T) {
	// Former names keep working and build the same filter as the path.
	for _, pair := range [][2]string{
		{`findings where asset_domain = "example.com"`, `findings where asset.domain = "example.com"`},
		{`findings where asset_name = "api-*"`, `findings where asset.name = "api-*"`},
	} {
		a, b := mustBuild(t, pair[0], memberAll()), mustBuild(t, pair[1], memberAll())
		if !reflect.DeepEqual(a.Document()["filter"], b.Document()["filter"]) {
			t.Errorf("%q and %q differ: %v vs %v", pair[0], pair[1], a.Document(), b.Document())
		}
	}
	p := mustBuild(t, `findings where asset.ip in ("10.0.0.0/8", "192.168.1.7")`, memberAll())
	leaf := p.UserFilter().Root.Leaf
	if leaf == nil || leaf.Field != "asset_ip" || !reflect.DeepEqual(leaf.Values, []any{"10.0.0.0/8", "192.168.1.7"}) {
		t.Fatalf("asset.ip leaf = %+v", leaf)
	}
	if _, err := build(t, `findings where asset.ip = "10.0.0.300"`, memberAll()); err == nil {
		t.Fatal("bad address built")
	}
	// Assets take ip.
	if p := mustBuild(t, `assets where ip = "2001:db8::/32"`, memberAll()); p.UserFilter().Root.Leaf.Field != "ip" {
		t.Fatal("assets ip")
	}
	// Asset attributes need assets:read: without it they are unknown,
	// under their path and their former name alike.
	for _, src := range []string{`findings where asset.ip = "10.0.0.1"`, `findings where asset_domain = "example.com"`, `findings where asset.name = "api-*"`} {
		if _, err := build(t, src, member(permission.FindingsRead.String())); err == nil {
			t.Errorf("%s built without assets:read", src)
		}
	}
}

func TestEntityAliasValidation(t *testing.T) {
	reg := filterspec.MustRegistry(filterspec.Registry{Name: "x", TenantSQL: "x.tenant_id", ScopeAssetSQL: "x.asset_id", IDSQL: "x.id"},
		filterspec.Field{Name: "severity", Type: filterspec.TypeEnum, Enum: []string{"high"}, Ops: []filterspec.Op{filterspec.OpIn}, SQL: "x.severity"},
		filterspec.Field{Name: "asset_type", Type: filterspec.TypeEnum, Enum: []string{"host"}, Ops: []filterspec.Op{filterspec.OpIn}, SQL: "x.asset_type"},
	)
	for name, aliases := range map[string]map[string]string{
		"shadows a field":   {"severity": "asset.type"},
		"shadows a path":    {"asset.type": "severity"},
		"unknown target":    {"sev": "nope"},
		"non-canonical":     {"atype": "asset_type"},
		"alias of an alias": {"s": "sev"},
	} {
		_, err := NewEntity(EntityDef{Name: "x", Permission: "p", Registry: reg,
			Paths: map[string]string{"asset.type": "asset_type"}, Aliases: aliases})
		if err == nil {
			t.Errorf("%s: entity accepted", name)
		}
	}
}
