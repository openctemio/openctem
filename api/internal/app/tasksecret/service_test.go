package tasksecret

import (
	"testing"

	"github.com/openctemio/contract/secretref"

	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	dom "github.com/openctemio/openctem/api/pkg/domain/tasksecret"
)

// The class gate: a provider secret needs the trusted grant only; a target
// credential (no kind ships yet) also needs the grant's credentials
// dimension and an organization sensor; an unknown class is refused.
func TestClassGate(t *testing.T) {
	tid := shared.NewID()
	org := &sensordom.Sensor{ID: shared.NewID(), TenantID: &tid, Scope: sensordom.ScopeOrganization}
	shr := &sensordom.Sensor{ID: shared.NewID(), Scope: sensordom.ScopeInstance}
	provider := secretref.Ref{Class: secretref.ClassProvider}
	target := secretref.Ref{Class: secretref.ClassTarget}
	creds := sensordom.Grant{TrustLevel: sensordom.TrustTrusted, AllowCredentials: true}
	noCreds := sensordom.Grant{TrustLevel: sensordom.TrustTrusted}
	for _, c := range []struct {
		name string
		ref  secretref.Ref
		sn   *sensordom.Sensor
		g    sensordom.Grant
		want bool
	}{
		{"provider, org", provider, org, noCreds, true},
		{"provider, shared", provider, shr, noCreds, true},
		{"target, org with credentials", target, org, creds, true},
		{"target, org without credentials", target, org, noCreds, false},
		{"target, shared with credentials", target, shr, creds, false},
		{"unknown class", secretref.Ref{Class: "other"}, org, creds, false},
	} {
		if got := classAllowed(c.ref, c.sn, c.g); got != c.want {
			t.Errorf("%s: %v", c.name, got)
		}
	}
}

func TestConfined(t *testing.T) {
	full := &sensordom.ManifestPosture{Sandbox: &sensordom.SandboxPosture{Mode: sensordom.SandboxModeRequired, Sandboxed: true, NetworkEnforced: true}}
	auto := &sensordom.ManifestPosture{Sandbox: &sensordom.SandboxPosture{Mode: sensordom.SandboxModeAuto, Sandboxed: true, NetworkEnforced: true}}
	caps := sensordom.CapabilityReport{Capabilities: []string{sensordom.CapabilityNetConfined}}
	for name, c := range map[string]struct {
		sn   *sensordom.Sensor
		want bool
	}{
		"confined":             {&sensordom.Sensor{Reported: caps, Posture: full}, true},
		"no capability":        {&sensordom.Sensor{Posture: full}, false},
		"no posture":           {&sensordom.Sensor{Reported: caps}, false},
		"sandbox not required": {&sensordom.Sensor{Reported: caps, Posture: auto}, false},
		"nil":                  {nil, false},
	} {
		if got := Confined(c.sn); got != c.want {
			t.Errorf("%s: %v", name, got)
		}
	}
}

func TestMaxFetches(t *testing.T) {
	for tasks, want := range map[int]int{0: 3, 1: 3, 2: 4, 10: 12, 254: 256, 10000: 256} {
		if got := dom.MaxFetches(tasks); got != want {
			t.Errorf("MaxFetches(%d) = %d, want %d", tasks, got, want)
		}
	}
}

// A fetch body is exactly a valid FetchRequest with a reply key of the
// suite's KEM.
func TestDecodeRequest(t *testing.T) {
	for name, body := range map[string]string{
		"empty":          ``,
		"unknown member": `{"lease_epoch":3,"refs":["k1"],"reply_key":"AA","extra":1}`,
		"no epoch":       `{"refs":["k1"],"reply_key":"AA"}`,
		"bad reply key":  `{"lease_epoch":3,"refs":["k1"],"reply_key":"AAAA"}`,
		"no refs":        `{"lease_epoch":3,"refs":[],"reply_key":"AAAA"}`,
		"trailing":       `{"lease_epoch":3,"refs":["k1"],"reply_key":"AAAA"} {}`,
	} {
		if _, _, ok := decodeRequest([]byte(body)); ok {
			t.Errorf("%s: accepted", name)
		}
	}
}
