package sensor

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"
)

// SECURITY: the posture is a claim from an untrusted process. Only the closed
// values are kept; anything else is dropped, never stored.
func TestSanitizeManifestPosture(t *testing.T) {
	if SanitizeManifestPosture(nil) != nil {
		t.Fatal("nil posture")
	}
	got := SanitizeManifestPosture(&ManifestPosture{
		PlatformTLS: &PlatformTLSPosture{Pin: " Fingerprint "},
		Sandbox:     &SandboxPosture{Mode: "AUTO", Sandboxed: true, NetworkEnforced: true},
	})
	if got.PlatformTLS.Pin != PlatformPinFingerprint || got.Sandbox.Mode != SandboxModeAuto || !got.Sandbox.NetworkEnforced || !got.Sandbox.Sandboxed {
		t.Fatalf("valid posture changed: %+v %+v", got.PlatformTLS, got.Sandbox)
	}
	odd := SanitizeManifestPosture(&ManifestPosture{
		PlatformTLS: &PlatformTLSPosture{Pin: "trust-me<script>"},
		Sandbox:     &SandboxPosture{Mode: "maximum", NetworkEnforced: false},
	})
	if odd.PlatformTLS != nil || odd.Sandbox == nil || odd.Sandbox.Mode != "" {
		t.Fatalf("unknown values kept: %+v %+v", odd.PlatformTLS, odd.Sandbox)
	}
	if SanitizeManifestPosture(&ManifestPosture{PlatformTLS: &PlatformTLSPosture{Pin: "other"}}) != nil {
		t.Fatal("a posture with nothing valid is kept")
	}
}

func TestSanitizeLocalPolicyReport_KeepsRequired(t *testing.T) {
	if r := SanitizeLocalPolicyReport(&LocalPolicyReport{State: "absent", Required: true}); r == nil || !r.Required {
		t.Fatalf("required dropped: %+v", r)
	}
	if r := SanitizeLocalPolicyReport(&LocalPolicyReport{State: "absent"}); r == nil || r.Required {
		t.Fatalf("required invented: %+v", r)
	}
	raw, _ := json.Marshal(SanitizeLocalPolicyReport(&LocalPolicyReport{State: "absent"}))
	if !strings.Contains(string(raw), `"required":false`) {
		t.Fatalf("required not serialized: %s", raw)
	}
}

func TestManifest_PostureMemberSanitized(t *testing.T) {
	raw := []byte(`{"schema":1,"tools":[],"local_policy":{"state":"absent","required":true},
		"posture":{"platform_tls":{"pin":"ca_file"},"sandbox":{"mode":"bogus","sandboxed":true,"network_enforced":false},"extra":1}}`)
	m, _, ignored, err := ParseManifest(raw)
	if err != nil {
		t.Fatal(err)
	}
	if slices.ContainsFunc(ignored, func(i ManifestIgnored) bool { return i.Path == "posture" }) {
		t.Fatalf("posture is ignored as unknown: %+v", ignored)
	}
	out, _ := m.Sanitized(CapabilityReport{}, time.Now())
	if out.Posture == nil || out.Posture.PlatformTLS.Pin != PlatformPinCAFile || out.Posture.Sandbox.Mode != "" || out.Posture.Sandbox.NetworkEnforced {
		t.Fatalf("stored posture %+v", out.Posture)
	}
	if out.LocalPolicy == nil || !out.LocalPolicy.Required {
		t.Fatalf("stored local policy %+v", out.LocalPolicy)
	}
	doc, _ := json.Marshal(out)
	if strings.Contains(string(doc), "bogus") || strings.Contains(string(doc), "extra") {
		t.Fatalf("stored document keeps unknown values: %s", doc)
	}
}

func TestDerivePosture(t *testing.T) {
	f, tr := false, true
	confined := &ManifestPosture{PlatformTLS: &PlatformTLSPosture{Pin: PlatformPinFingerprint}, Sandbox: &SandboxPosture{NetworkEnforced: true}}
	weak := &ManifestPosture{PlatformTLS: &PlatformTLSPosture{Pin: PlatformPinNone}, Sandbox: &SandboxPosture{NetworkEnforced: false}}
	cases := []struct {
		name       string
		in         PostureInput
		lp, pin    string
		net        *bool
		unhardened []string
	}{
		{"never connected", PostureInput{}, PostureLocalPolicyUnknown, PlatformPinUnknown, nil, []string{}},
		{"old sdk, seen", PostureInput{Seen: true}, PostureLocalPolicyUnknown, PlatformPinUnknown, nil,
			[]string{UnhardenedPolicyNone, UnhardenedBearerKey}},
		{"legacy", PostureInput{Seen: true, LocalPolicy: &LocalPolicyReport{State: LocalPolicyAbsent}, Posture: weak},
			PostureLocalPolicyAbsentLegacy, PlatformPinNone, &f,
			[]string{UnhardenedPolicyNone, UnhardenedPinNone, UnhardenedNetworkUnenforced, UnhardenedBearerKey}},
		{"fails closed", PostureInput{Seen: true, KeyBound: true, LocalPolicy: &LocalPolicyReport{State: LocalPolicyAbsent, Required: true}},
			PostureLocalPolicyAbsentRequired, PlatformPinUnknown, nil, []string{}},
		{"hardened", PostureInput{Seen: true, KeyBound: true, LocalPolicy: &LocalPolicyReport{State: LocalPolicyEnforced, KillSwitch: true}, Posture: confined},
			PostureLocalPolicyEnforced, PlatformPinFingerprint, &tr, []string{}},
		{"unsanitized input", PostureInput{Seen: true, KeyBound: true, LocalPolicy: &LocalPolicyReport{State: LocalPolicyEnforced},
			Posture: &ManifestPosture{PlatformTLS: &PlatformTLSPosture{Pin: "whatever"}}},
			PostureLocalPolicyEnforced, PlatformPinUnknown, nil, []string{}},
	}
	for _, c := range cases {
		got := DerivePosture(c.in)
		if got.LocalPolicy != c.lp || got.PlatformPin != c.pin || (got.NetworkEnforced == nil) != (c.net == nil) ||
			(c.net != nil && *got.NetworkEnforced != *c.net) || !slices.Equal(got.Unhardened, c.unhardened) || got.Unhardened == nil {
			t.Errorf("%s: %+v (network %v)", c.name, got, got.NetworkEnforced)
		}
	}
	for _, r := range DerivePosture(cases[2].in).Unhardened {
		if !slices.Contains(UnhardenedKinds(), r) {
			t.Errorf("reason %q outside the closed set", r)
		}
	}
}
