package validator

import (
	"strings"
	"testing"
)

// Integration and webhook URLs are judged by the one address guard the
// guarded HTTP client dials through (pkg/httpsec, from the shared address
// scope), for a typed address as for a resolved name. The literal-address
// path used its own, shorter list and let shared address space, the IETF
// protocol range and NAT64/6to4 forms through; documentation ranges stay
// public addresses there (examples and tests use them), as everywhere else.
func TestValidateWebhookURL_LiteralAddressesUseTheSharedGuard(t *testing.T) {
	for _, tc := range []struct {
		url     string
		blocked bool
	}{
		{"https://100.64.0.1/hook", true},           // shared address space (CGNAT)
		{"https://192.0.0.8/hook", true},            // IETF protocol assignments
		{"https://198.18.0.1/hook", true},           // benchmarking
		{"https://[64:ff9b::a9fe:a9fe]/hook", true}, // NAT64 form of the metadata address
		{"https://[2002:a9fe:a9fe::1]/hook", true},  // 6to4 form of the metadata address
		{"https://10.1.2.3/hook", true},
		{"https://169.254.169.254/latest", true},
		{"https://192.0.2.10/hook", false},     // documentation range: public by the shared definition
		{"https://[2001:db8::10]/hook", false}, // documentation range
		{"https://198.51.100.7/hook", false},
	} {
		err := ValidateWebhookURL(tc.url)
		if (err != nil) != tc.blocked {
			t.Errorf("%s: err %v, want blocked=%v", tc.url, err, tc.blocked)
		}
	}
}

// A name that does not resolve says so: it used to be reported as "resolves
// to a blocked address", which sent people looking for an address problem.
func TestValidateWebhookURL_UnresolvableNameSaysSo(t *testing.T) {
	err := ValidateWebhookURL("https://no-such-host.invalid/hook")
	if err == nil || !strings.Contains(err.Error(), "does not resolve") {
		t.Fatalf("err = %v, want \"does not resolve\"", err)
	}
}
