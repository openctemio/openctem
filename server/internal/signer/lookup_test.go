package signer

import (
	"testing"

	"github.com/openctemio/openctem/server/pkg/jobsign"
)

// SECURITY: a lookup statement is signed only for a platform (instance)
// sensor, for an organization, with the lookup tool and one canonical root
// domain; anything else is refused whatever the API asks.
func TestSign_LookupRules(t *testing.T) {
	s := newService(t, t.TempDir(), newKey(t), nil)
	lookup := func(edit func(m map[string]any)) []byte {
		return statement(func(m map[string]any) {
			m["sensor_scope"] = jobsign.SensorScopeInstance
			m["command_type"] = jobsign.CommandTypeLookup
			m["tool"] = "ctlog"
			m["targets"] = []string{"example.com"}
			if edit != nil {
				edit(m)
			}
		})
	}
	for _, tc := range []struct {
		name   string
		raw    []byte
		reason string
	}{
		{"organization sensor", lookup(func(m map[string]any) { delete(m, "sensor_scope") }), ReasonLookupShape},
		{"platform tenant", lookup(func(m map[string]any) { m["tenant_id"] = jobsign.PlatformTenantID }), ReasonPlatformTenant},
		{"other tool", lookup(func(m map[string]any) { m["tool"] = "nuclei" }), ReasonLookupShape},
		{"empty tool", lookup(func(m map[string]any) { m["tool"] = "" }), ReasonLookupShape},
		{"two targets", lookup(func(m map[string]any) { m["targets"] = []string{"example.com", "example.org"} }), ReasonLookupShape},
		{"wildcard", lookup(func(m map[string]any) { m["targets"] = []string{"*.example.com"} }), ReasonLookupShape},
		{"url", lookup(func(m map[string]any) { m["targets"] = []string{"https://example.com/"} }), ReasonLookupShape},
		{"not canonical", lookup(func(m map[string]any) { m["targets"] = []string{"Example.COM"} }), ReasonLookupShape},
		{"internal name", lookup(func(m map[string]any) { m["targets"] = []string{"corp.internal"} }), ReasonSharedInternal},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env, ref := s.Sign(tc.raw)
			if ref == nil {
				t.Fatalf("signed: %s", env)
			}
			if ref.reason != tc.reason {
				t.Fatalf("refused with %s (%s), want %s", ref.reason, ref.detail, tc.reason)
			}
		})
	}
	env, ref := s.Sign(lookup(nil))
	if ref != nil {
		t.Fatalf("a lookup within the rules was refused: %+v", ref)
	}
	if _, st := decodeEnvelope(t, env); st.CommandType != jobsign.CommandTypeLookup || st.SensorScope != jobsign.SensorScopeInstance {
		t.Fatalf("signed statement %+v", st)
	}
}
