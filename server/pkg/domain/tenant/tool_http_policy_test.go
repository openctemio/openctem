package tenant

import (
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scanident"
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

// The organization's scan identification headers: free names within the
// token alphabet, at most six, travel with the tool HTTP layer; transport
// and credential headers, line breaks and duplicates are refused.
func TestSecuritySettings_ToolHTTPHeaders(t *testing.T) {
	ok := SecuritySettings{ToolHTTPHeaders: []scanident.Header{{Name: "ATTT", Value: "is-here"}}}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	if p := ok.ToolHTTPPolicy(); len(p.Headers) != 1 || p.Headers[0].Name != "ATTT" {
		t.Fatalf("policy %+v", p)
	}
	for _, hs := range [][]scanident.Header{
		{{Name: "Cookie", Value: "a=b"}},
		{{Name: "X-A", Value: "x\nY: z"}},
		{{Name: "X-A", Value: "1"}, {Name: "x-A", Value: "2"}},
		{{Name: "X-A", Value: "1", Enforced: true}},
		{{Name: "A", Value: "1"}, {Name: "B", Value: "1"}, {Name: "C", Value: "1"}, {Name: "D", Value: "1"}, {Name: "E", Value: "1"}, {Name: "F", Value: "1"}, {Name: "G", Value: "1"}},
	} {
		if err := (&SecuritySettings{ToolHTTPHeaders: hs}).Validate(); err == nil {
			t.Errorf("%+v accepted", hs)
		}
	}
}

// The organization's rotation list, query parameter and requirement travel
// with the tool HTTP layer; a list and a single User-Agent together, more
// than 200 values, CR/LF and a bad query parameter are refused.
func TestSecuritySettings_ToolHTTPRotationQueryRequired(t *testing.T) {
	ok := SecuritySettings{ToolHTTPUserAgents: []string{"a/1", "b/2"}, ToolHTTPQuery: &scanident.Query{Name: "scan", Value: "corp-1"},
		ToolHTTPIdentificationRequired: true}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	p := ok.ToolHTTPPolicy()
	if len(p.UserAgents) != 2 || p.Query == nil || p.Query.Value != "corp-1" || !p.IdentificationRequired {
		t.Fatalf("policy %+v", p)
	}
	many := make([]string, 201)
	for i := range many {
		many[i] = "ua/" + strings.Repeat("x", i%5) + string(rune('A'+i%26)) + strings.Repeat("y", i/26)
	}
	for name, bad := range map[string]SecuritySettings{
		"both":      {ToolHTTPUserAgent: "one", ToolHTTPUserAgents: []string{"a", "b"}},
		"201":       {ToolHTTPUserAgents: many},
		"CR/LF":     {ToolHTTPUserAgents: []string{"a\r\nX: 1"}},
		"duplicate": {ToolHTTPUserAgents: []string{"a", "a"}},
		"query":     {ToolHTTPQuery: &scanident.Query{Name: "a&b", Value: "v"}},
	} {
		if err := bad.Validate(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
