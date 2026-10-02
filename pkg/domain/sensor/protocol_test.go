package sensor

import (
	"strings"
	"testing"
)

func TestSanitizeUserAgent(t *testing.T) {
	for in, want := range map[string]string{
		"openctem-sdk-go/0.9.0 (openctemio-sensor/0.5.0)": "openctem-sdk-go/0.9.0 (openctemio-sensor/0.5.0)",
		"a\r\nX-Injected: 1":                               "aX-Injected: 1",
		"  \tsdké/1 ":                                 "sdk/1",
		"":                                                 "",
	} {
		if got := SanitizeUserAgent(in); got != want {
			t.Errorf("SanitizeUserAgent(%q) = %q, want %q", in, got, want)
		}
	}
	if got := SanitizeUserAgent(strings.Repeat("x", 1000)); len(got) != MaxUserAgentLength {
		t.Errorf("length %d", len(got))
	}
}

func TestProtocolInfoDeprecated(t *testing.T) {
	var none *ProtocolInfo
	if none.Deprecated() {
		t.Error("nil is not deprecated")
	}
	if !(&ProtocolInfo{Version: 1}).Deprecated() || (&ProtocolInfo{Version: 2}).Deprecated() {
		t.Error("v1 deprecated, v2 not")
	}
}
