package tenant

import (
	"strings"
	"testing"
)

// The organization's tool User-Agent is printable ASCII up to 256 bytes;
// forbidding insecure TLS travels as allow_insecure_tls false.
func TestSecuritySettings_ToolHTTPPolicy(t *testing.T) {
	ok := SecuritySettings{ToolHTTPUserAgent: "corp-scan (+soc@corp.example)", ForbidToolInsecureTLS: true}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	if p := ok.ToolHTTPPolicy(); p.UserAgent != "corp-scan (+soc@corp.example)" || p.AllowInsecureTLS == nil || *p.AllowInsecureTLS {
		t.Fatalf("policy %+v", p)
	}
	if p := (&SecuritySettings{}).ToolHTTPPolicy(); p.UserAgent != "" || p.AllowInsecureTLS != nil {
		t.Fatalf("empty policy %+v", p)
	}
	for _, ua := range []string{"a\nb", strings.Repeat("a", 257), "é"} {
		if err := (&SecuritySettings{ToolHTTPUserAgent: ua}).Validate(); err == nil {
			t.Errorf("user agent %q accepted", ua)
		}
	}
}
