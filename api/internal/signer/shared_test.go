package signer

import (
	"testing"

	"github.com/openctemio/openctem/api/pkg/jobsign"
)

// A statement for a shared sensor is signed only within the shared-job
// rules, whatever the API asks: scan/validate/retest, no custom templates,
// public targets only (the list sensors use, IPv6 forms that carry an
// internal IPv4 included). The signed payload carries the scope, so the
// sensor can tell a shared job from an organization's.
func TestSign_SharedJobRules(t *testing.T) {
	s := newService(t, t.TempDir(), newKey(t), nil)
	shared := func(edit func(m map[string]any)) []byte {
		return statement(func(m map[string]any) {
			m["sensor_scope"] = jobsign.SensorScopeInstance
			if edit != nil {
				edit(m)
			}
		})
	}
	refused := []struct {
		name   string
		raw    []byte
		reason string
	}{
		{"unknown scope", statement(func(m map[string]any) { m["sensor_scope"] = "organization" }), ReasonBadSensorScope},
		{"collect job", shared(func(m map[string]any) { m["command_type"] = "collect" }), ReasonSharedJobType},
		{"connector sync", shared(func(m map[string]any) { m["command_type"] = "connector_sync" }), ReasonSharedJobType},
		{"custom templates", shared(func(m map[string]any) {
			m["templates"] = []string{jobsign.PayloadDigest([]byte("t"))}
		}), ReasonSharedTemplates},
	}
	for _, target := range []string{
		"10.0.0.5", "169.254.169.254", "http://127.0.0.1:8080/x", "[::1]:22", "fd00:ec2::254",
		"64:ff9b::a00:1", "2002:a00:1::1", "8.0.0.0/6", "100.64.0.0/10", "0.0.0.0", "224.0.0.1",
		"intranet.local", "db.internal", "localhost:5432", "router.home.arpa", "https://svc.internal/", "",
	} {
		if target == "" {
			continue
		}
		refused = append(refused, struct {
			name   string
			raw    []byte
			reason string
		}{"target " + target, shared(func(m map[string]any) {
			m["targets"] = []string{"203.0.113.10", target}
		}), ReasonSharedInternal})
	}
	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			env, ref := s.Sign(tc.raw)
			if ref == nil {
				t.Fatalf("signed: %s", env)
			}
			if ref.reason != tc.reason {
				t.Fatalf("refused with %s, want %s", ref.reason, tc.reason)
			}
		})
	}

	// Within the rules: signed, and the payload names the scope.
	env, ref := s.Sign(shared(func(m map[string]any) {
		m["targets"] = []string{"203.0.113.10", "https://app.example.com/login", "198.51.100.0/24", "2606:4700::1"}
	}))
	if ref != nil {
		t.Fatalf("a public shared job was refused: %+v", ref)
	}
	if _, st := decodeEnvelope(t, env); st.SensorScope != jobsign.SensorScopeInstance {
		t.Fatalf("signed statement scope %q, want %q", st.SensorScope, jobsign.SensorScopeInstance)
	}
	// An organization's statement may target internal space as before, and
	// carries no scope.
	env, ref = s.Sign(statement(func(m map[string]any) { m["targets"] = []string{"10.0.0.5"} }))
	if ref != nil {
		t.Fatalf("an organization job was refused: %+v", ref)
	}
	if _, st := decodeEnvelope(t, env); st.SensorScope != "" {
		t.Fatalf("organization statement carries scope %q", st.SensorScope)
	}
}
