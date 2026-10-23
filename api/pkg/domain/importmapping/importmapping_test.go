package importmapping

import (
	"errors"
	"strings"
	"testing"

	"github.com/openctemio/ctis/importer/mapping"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func findingDoc(identity, sets string) string {
	return `{"apiVersion": "openctem.io/mapping/v1", "source": "csv", "identity": ` + identity + `,
	  "records": [{"kind": "finding", "set": {"title": "/title", "severity": {"const": "low"}, "asset_value": "/host"` + sets + `}}]}`
}

func mustCompile(t *testing.T, doc string) *mapping.Mapping {
	t.Helper()
	m, problems := Compile([]byte(doc))
	if len(problems) > 0 {
		t.Fatalf("problems: %v", problems)
	}
	return m
}

func TestCompilePolicy(t *testing.T) {
	ok := findingDoc(`["title", "asset_value"]`, `, "vulnerability.cve_id": "/cve", "type": {"const": "misconfiguration"}`)
	mustCompile(t, ok)

	refused := map[string]struct{ doc, want string }{
		"reserved fingerprint":  {findingDoc(`["title"]`, `, "fingerprint": "/id"`), `"fingerprint" is reserved`},
		"reserved partial fp":   {findingDoc(`["title"]`, `, "partial_fingerprints.x": "/id"`), "reserved"},
		"reserved baseline":     {findingDoc(`["title"]`, `, "baseline_state": "/s"`), "reserved"},
		"reserved kev":          {findingDoc(`["title"]`, `, "vulnerability.in_cisa_kev": {"const": true}`), "reserved"},
		"reserved branch":       {findingDoc(`["title"]`, `, "location.branch": "/b"`), "reserved"},
		"reserved source extra": {findingDoc(`["title"]`, `, "source_extra.plugin_type": "/p"`), "reserved"},
		"secret type":           {findingDoc(`["title"]`, `, "type": {"const": "secret"}`), "type must be one of"},
		"type from path":        {findingDoc(`["title"]`, `, "type": "/kind"`), "type must be one of"},
		"type map escapes":      {findingDoc(`["title"]`, `, "type": {"path": "/kind", "map": {"a": "vulnerability", "b": "secret"}}`), "type must be one of"},
		"no identity":           {strings.Replace(findingDoc(`["title"]`, ``), `"identity": ["title"],`, ``, 1), "declares its identity"},
		"identity not member":   {findingDoc(`["description"]`, `, "description": "/d"`), "not an identity member"},
		"constant identity":     {findingDoc(`["rule_id"]`, `, "rule_id": {"const": "X"}`), "constant"},
		// A const passes through the map, so the map decides the type.
		"type const remapped":    {findingDoc(`["title"]`, `, "type": {"const": "vulnerability", "map": {"vulnerability": "secret"}}`), "type must be one of"},
		"type const default":     {findingDoc(`["title"]`, `, "type": {"const": "vulnerability", "map": {"x": "misconfiguration"}, "default": "secret"}`), "type must be one of"},
		"type const bad default": {findingDoc(`["title"]`, `, "type": {"const": "vulnerability", "default": "secret"}`), "type must be one of"},
		// Near-constant identities: a default every record without the
		// value shares, or a map with one output.
		"identity default":       {findingDoc(`["title", "rule_id"]`, `, "rule_id": {"path": "/never", "default": "X"}`), "has a default"},
		"identity one-value map": {findingDoc(`["title", "rule_id"]`, `, "rule_id": {"path": "/r", "map": {"a": "X", "b": "X"}}`), "same output"},
		"asset criticality": {`{"apiVersion": "openctem.io/mapping/v1", "source": "csv", "records": [
		  {"kind": "asset", "set": {"type": {"const": "host"}, "value": "/h", "criticality": {"const": "critical"}}}]}`, `"criticality" is reserved`},
		"asset properties": {`{"apiVersion": "openctem.io/mapping/v1", "source": "csv", "records": [
		  {"kind": "asset", "set": {"type": {"const": "host"}, "value": "/h", "properties.owner": "/o"}}]}`, "reserved"},
		"asset identity hints": {`{"apiVersion": "openctem.io/mapping/v1", "source": "csv", "records": [
		  {"kind": "asset", "set": {"type": {"const": "host"}, "value": "/h", "identity_hints.hostname": "/o"}}]}`, ""},
		"dependency": {`{"apiVersion": "openctem.io/mapping/v1", "source": "csv", "records": [
		  {"kind": "dependency", "set": {"name": "/n"}}]}`, "not available for imports"},
		"language error": {`{"apiVersion": "v0"}`, "apiVersion"},
	}
	for name, c := range refused {
		t.Run(name, func(t *testing.T) {
			m, problems := Compile([]byte(c.doc))
			if m != nil || len(problems) == 0 {
				t.Fatal("compiled")
			}
			if !strings.Contains(strings.Join(problems, "|"), c.want) {
				t.Fatalf("problems %v, want %q", problems, c.want)
			}
		})
	}
	// An asset-only mapping needs no identity.
	mustCompile(t, `{"apiVersion": "openctem.io/mapping/v1", "source": "csv", "records": [
	  {"kind": "asset", "set": {"type": {"const": "host"}, "value": "/h", "name": "/n", "tags": "/t"}}]}`)
}

func TestIdentityChanged(t *testing.T) {
	base := mustCompile(t, findingDoc(`["title", "asset_value"]`, `, "description": "/d"`))
	cases := map[string]struct {
		doc     string
		changed bool
	}{
		"same":                   {findingDoc(`["title", "asset_value"]`, `, "description": "/d"`), false},
		"cosmetic member":        {findingDoc(`["title", "asset_value"]`, `, "description": "/other", "remediation.recommendation": "/r"`), false},
		"identity list":          {findingDoc(`["title"]`, `, "description": "/d"`), true},
		"identity member source": {strings.Replace(findingDoc(`["title", "asset_value"]`, `, "description": "/d"`), `"title": "/title"`, `"title": {"path": "/title", "lower": true}`, 1), true},
		"asset source":           {strings.Replace(findingDoc(`["title", "asset_value"]`, `, "description": "/d"`), `"asset_value": "/host"`, `"asset_value": "/ip"`, 1), true},
		"asset type added":       {findingDoc(`["title", "asset_value"]`, `, "description": "/d", "asset_type": {"const": "ip_address"}`), true},
		// Members the server keys findings on change the identity even when
		// the mapping does not declare them.
		"undeclared key member": {findingDoc(`["title", "asset_value"]`, `, "description": "/d", "vulnerability.package": "/pkg"`), true},
		"rule id source":        {findingDoc(`["title", "asset_value"]`, `, "description": "/d", "rule_id": "/rule"`), true},
		"type changed":          {findingDoc(`["title", "asset_value"]`, `, "description": "/d", "type": {"const": "misconfiguration"}`), true},
		"recipe block added":    {findingDoc(`["title", "asset_value"]`, `, "description": "/d", "network.service": "/svc"`), true},
		"cosmetic block member": {findingDoc(`["title", "asset_value"]`, `, "description": "/d", "vulnerability.fixed_version": "/fix"`), false},
	}
	for name, c := range cases {
		if got := IdentityChanged(base, mustCompile(t, c.doc)); got != c.changed {
			t.Errorf("%s: changed = %v, want %v", name, got, c.changed)
		}
	}
}

func TestParseFormat(t *testing.T) {
	id := shared.NewID().String()
	good := map[string]FormatRef{
		"mapping:legacy-vm":     {Ref: "legacy-vm"},
		"mapping:legacy-vm@3":   {Ref: "legacy-vm", Version: 3},
		"mapping:" + id:         {Ref: id},
		"mapping:" + id + "@12": {Ref: id, Version: 12},
	}
	for in, want := range good {
		got, ok, err := ParseFormat(in)
		if !ok || err != nil || got != want {
			t.Errorf("%s: %+v %v %v", in, got, ok, err)
		}
	}
	if _, ok, _ := ParseFormat("nessus"); ok {
		t.Error("nessus is not a mapping format")
	}
	for _, bad := range []string{"mapping:", "mapping:Upper", "mapping:a@0", "mapping:a@-1", "mapping:a@x", "mapping:../x", "mapping:a@1@2", "mapping:a b"} {
		if _, ok, err := ParseFormat(bad); !ok || !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%s: ok=%v err=%v", bad, ok, err)
		}
	}
}

func TestValidateName(t *testing.T) {
	for _, n := range []string{"a", "legacy-vm.export_2", strings.Repeat("a", 64)} {
		if err := ValidateName(n); err != nil {
			t.Errorf("%q: %v", n, err)
		}
	}
	for _, n := range []string{"", "-a", "A", "a/b", strings.Repeat("a", 65), "a b", "mapping:x"} {
		if err := ValidateName(n); err == nil {
			t.Errorf("%q accepted", n)
		}
	}
}
