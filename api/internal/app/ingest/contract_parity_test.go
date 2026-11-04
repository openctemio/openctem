package ingest

import (
	"reflect"
	"strings"
	"testing"

	"github.com/openctemio/contract/capability"
	"github.com/openctemio/ctis/v2"
)

// The contract module names CTIS 2.0 asset types and the JSON paths each
// capability's output must carry without importing CTIS (its README,
// "Relation to CTIS"); this is the parity check it relies on: every asset
// type it names is a CTIS 2.0 type, and every rule path resolves to a member
// of the CTIS 2.0 record it selects.
func TestContractCapabilitiesMatchCTIS2(t *testing.T) {
	for _, at := range capability.AllAssetTypes() {
		if !ctis.AssetType(at).IsValid() {
			t.Errorf("contract asset type %q is not a CTIS 2.0 asset type", at)
		}
	}
	records := map[string]reflect.Type{
		"assets":       reflect.TypeOf(ctis.Asset{}),
		"findings":     reflect.TypeOf(ctis.Finding{}),
		"dependencies": reflect.TypeOf(ctis.Dependency{}),
		"endpoints":    reflect.TypeOf(ctis.Endpoint{}),
	}
	for _, c := range capability.All() {
		for _, r := range c.Outputs {
			sel, filter, _ := strings.Cut(r.Select, "[")
			rt, ok := records[sel]
			if !ok {
				t.Errorf("%s: rule selects %q, not a CTIS 2.0 record list", c.Ref(), r.Select)
				continue
			}
			if filter != "" {
				for _, v := range strings.Split(strings.TrimSuffix(strings.TrimPrefix(filter, "type="), "]"), "|") {
					if sel == "assets" && !ctis.AssetType(v).IsValid() {
						t.Errorf("%s: rule filters assets on %q, not a CTIS 2.0 asset type", c.Ref(), v)
					}
					if sel == "findings" && !ctis.FindingType(v).IsValid() {
						t.Errorf("%s: rule filters findings on %q, not a CTIS 2.0 finding type", c.Ref(), v)
					}
				}
			}
			for _, p := range append(append([]string(nil), r.Paths...), r.AnyOf...) {
				if !jsonPathResolves(rt, p) {
					t.Errorf("%s: rule path %s.%s is not a CTIS 2.0 member", c.Ref(), sel, p)
				}
			}
		}
	}
}

// jsonPathResolves reports whether a dotted path of JSON member names ("[]"
// after a list member) leads through t's fields. A free-form map member
// (extensions, properties, details) accepts any key below it.
func jsonPathResolves(t reflect.Type, path string) bool {
	for _, seg := range strings.Split(path, ".") {
		seg = strings.TrimSuffix(seg, "[]")
		for t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice {
			t = t.Elem()
		}
		if t.Kind() == reflect.Map {
			return true
		}
		if t.Kind() != reflect.Struct {
			return false
		}
		f, ok := fieldByJSONName(t, seg)
		if !ok {
			return false
		}
		t = f.Type
	}
	return true
}

func fieldByJSONName(t reflect.Type, name string) (reflect.StructField, bool) {
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if tag, _, _ := strings.Cut(f.Tag.Get("json"), ","); tag == name {
			return f, true
		}
	}
	return reflect.StructField{}, false
}
