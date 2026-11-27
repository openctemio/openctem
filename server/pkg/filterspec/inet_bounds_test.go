package filterspec

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"
)

// An address range filter is at most a /8 of IPv4 or a /32 of IPv6: a wider
// one (0.0.0.0/0, ::/0) is refused with the bound named, in GET params and in
// a filter document alike. Single addresses and ranges within the bound pass.
func TestInetFilter_RefusesTooWideRanges(t *testing.T) {
	reg := inetRegistry(t)
	for _, bad := range []string{"0.0.0.0/0", "::/0", "10.0.0.0/7", "128.0.0.0/1", "2001:db8::/31", "::ffff:0.0.0.0/96"} {
		_, err := ParseValues(url.Values{"asset_ip": {bad}}, reg, Options{Unknown: UnknownStrict})
		if err == nil || !strings.Contains(err.Error(), "/8 (IPv4) or /32 (IPv6)") {
			t.Errorf("GET asset_ip=%s: err = %v, want the width bound named", bad, err)
		}
		doc := fmt.Sprintf(`{"v":1,"filter":{"field":"asset_ip","op":"in","value":[%q]}}`, bad)
		if _, err := ParseDocument([]byte(doc), reg, Options{Unknown: UnknownStrict}); err == nil || !strings.Contains(err.Error(), "/8 (IPv4) or /32 (IPv6)") {
			t.Errorf("document asset_ip=%s: err = %v, want the width bound named", bad, err)
		}
	}
	for _, ok := range []string{"10.0.0.0/8", "10.1.2.0/24", "10.1.2.3", "2001:db8::/32", "2001:db8::1", "::ffff:10.0.0.0/104"} {
		if _, err := ParseValues(url.Values{"asset_ip": {ok}}, reg, Options{Unknown: UnknownStrict}); err != nil {
			t.Errorf("GET asset_ip=%s: %v, want accepted", ok, err)
		}
	}
}

func TestCheckInetFilterWidth(t *testing.T) {
	for in, wantErr := range map[string]bool{
		"0.0.0.0/0": true, "::/0": true, "10.0.0.0/7": true, "::ffff:0.0.0.0/96": true,
		"10.0.0.0/8": false, " 10.0.0.0/8 ": false, "2001:db8::/32": false, "10.1.2.3": false, "not a range": false,
	} {
		if err := CheckInetFilterWidth(in); (err != nil) != wantErr {
			t.Errorf("CheckInetFilterWidth(%q) = %v, want error %v", in, err, wantErr)
		}
	}
}

// The address values of one filter are capped over all its inet leaves: a
// document of several leaves, each within the per-field cap, cannot bind
// more than MaxInetValues range scans.
func TestInetFilter_CapsValuesAcrossLeaves(t *testing.T) {
	reg := inetRegistry(t)
	leaf := func(base int) map[string]any {
		vals := make([]string, 20)
		for i := range vals {
			vals[i] = fmt.Sprintf("10.%d.%d.0/24", base, i)
		}
		return map[string]any{"field": "asset_ip", "op": "in", "value": vals}
	}
	build := func(n int) []byte {
		kids := make([]any, n)
		for i := range kids {
			kids[i] = leaf(i)
		}
		b, _ := json.Marshal(map[string]any{"v": 1, "filter": map[string]any{"any": kids}})
		return b
	}
	// 40 values: compiles.
	spec, err := ParseDocument(build(2), reg, Options{Unknown: UnknownStrict})
	if err != nil {
		t.Fatalf("parse 2 leaves: %v", err)
	}
	if _, err := Compile(spec, reg, adminActor(t)); err != nil {
		t.Fatalf("compile 40 values: %v", err)
	}
	// 60 values: refused with the limit named.
	spec, err = ParseDocument(build(3), reg, Options{Unknown: UnknownStrict})
	if err != nil {
		t.Fatalf("parse 3 leaves: %v", err)
	}
	_, err = Compile(spec, reg, adminActor(t))
	var fe *Error
	if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("max %d", MaxInetValues)) {
		t.Fatalf("compile 60 values: err = %v, want the cap of %d named", err, MaxInetValues)
	}
	if !errors.As(err, &fe) || fe.APIError().Status != 400 {
		t.Fatalf("compile 60 values: %T %v, want a filterspec 400", err, err)
	}
}
