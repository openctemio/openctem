package scanident

import (
	"errors"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A header name is fully free within the RFC 7230 token alphabet; values
// are printable ASCII; transport and credential names are refused.
func TestCheckHeader(t *testing.T) {
	for _, ok := range [][2]string{{"ATTT", "is-here"}, {"X-Scanner", "corp-42"}, {"a!#$%&'*+-.^_`|~9", ""}, {"Ok", strings.Repeat("v", MaxHeaderValue)}} {
		if err := CheckHeader(ok[0], ok[1]); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	bad := [][2]string{
		{"", "v"}, {"Has Space", "v"}, {"Colon:", "v"}, {strings.Repeat("n", MaxHeaderName+1), "v"}, {"Ünicode", "v"},
		{"X-A", "line\r\nInjected: 1"}, {"X-A", "nul\x00"}, {"X-A", "tab\t"}, {"X-A", "é"}, {"X-A", strings.Repeat("v", MaxHeaderValue+1)},
		{"Host", "x"}, {"content-length", "1"}, {"Transfer-Encoding", "chunked"}, {"Connection", "close"}, {"TE", "x"},
		{"Upgrade", "h2c"}, {"Proxy-Authorization", "x"}, {"proxy-anything", "x"}, {"Cookie", "a=b"}, {"AUTHORIZATION", "Bearer x"},
		{"Keep-Alive", "1"}, {"Trailer", "x"},
	}
	for _, b := range bad {
		if err := CheckHeader(b[0], b[1]); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%q accepted (%v)", b, err)
		}
	}
}

func TestCheckHeaders_DuplicatesCapsEnforced(t *testing.T) {
	if err := CheckHeaders([]Header{{Name: "X-A", Value: "1"}, {Name: "x-a", Value: "2"}}, 6, false); err == nil {
		t.Fatal("case-insensitive duplicate accepted")
	}
	many := make([]Header, MaxOrganizationHeaders+1)
	for i := range many {
		many[i] = Header{Name: "X-" + string(rune('A'+i)), Value: "v"}
	}
	if err := CheckHeaders(many, MaxOrganizationHeaders, false); err == nil {
		t.Fatal("over the cap accepted")
	}
	if err := CheckHeaders([]Header{{Name: "X-A", Value: "1", Enforced: true}}, 6, false); err == nil {
		t.Fatal("an organization enforced a header")
	}
	if err := (PlatformLayer{Headers: []Header{{Name: "X-A", Value: "1", Enforced: true}}}).Validate(); err != nil {
		t.Fatal(err)
	}
	if err := (PlatformLayer{UserAgent: "a\nb"}).Validate(); err == nil {
		t.Fatal("UA with a line break accepted")
	}
}

// The merge keeps every distinct name; the organization wins a clash
// unless the platform enforces the header; the UA follows the same rule.
func TestMerge(t *testing.T) {
	p := PlatformLayer{UserAgent: "openctem-scanner", Headers: []Header{
		{Name: "X-Operator", Value: "saas", Enforced: true},
		{Name: "X-Env", Value: "prod"},
	}}
	org := OrganizationLayer{UserAgent: "corp-scan", Headers: []Header{
		{Name: "x-operator", Value: "mine"}, // enforced: ignored
		{Name: "x-env", Value: "uat"},       // replaces the platform default
		{Name: "ATTT", Value: "is-here"},    // new: kept
	}}
	e := Merge(p, org)
	want := []Marker{
		{Name: "X-Operator", Value: "saas", Source: SourcePlatformEnforced, Locked: true},
		{Name: "x-env", Value: "uat", Source: SourceOrganization},
		{Name: "ATTT", Value: "is-here", Source: SourceOrganization},
	}
	if len(e.Headers) != len(want) {
		t.Fatalf("headers %+v", e.Headers)
	}
	for i := range want {
		if e.Headers[i] != want[i] {
			t.Errorf("header %d: %+v, want %+v", i, e.Headers[i], want[i])
		}
	}
	if e.UserAgent != "corp-scan" || e.UserAgentSource != SourceOrganization || e.UserAgentLocked {
		t.Errorf("ua %q %q %v", e.UserAgent, e.UserAgentSource, e.UserAgentLocked)
	}
	if got := Merge(PlatformLayer{UserAgent: "op", UserAgentEnforced: true}, org); got.UserAgent != "op" || !got.UserAgentLocked {
		t.Errorf("enforced ua lost: %+v", got)
	}
	if got := Merge(PlatformLayer{UserAgent: "op"}, OrganizationLayer{}); got.UserAgent != "op" || got.UserAgentSource != SourcePlatform {
		t.Errorf("platform default ua: %+v", got)
	}
	if got := Merge(PlatformLayer{}, OrganizationLayer{}); len(got.Headers) != 0 || got.UserAgent != "" || got.HeaderMap() != nil {
		t.Errorf("empty merge: %+v", got)
	}
	if names := e.LockedNames(); len(names) != 1 || names[0] != "X-Operator" {
		t.Errorf("locked %v", names)
	}
}

// A program goes over the organization but never over an enforced
// platform header, and the merged set never exceeds MaxHeaders.
func TestOverlay(t *testing.T) {
	e := Merge(PlatformLayer{Headers: []Header{{Name: "X-Operator", Value: "saas", Enforced: true}}},
		OrganizationLayer{UserAgent: "corp", Headers: []Header{{Name: "X-Research", Value: "org"}}})
	got, err := e.Overlay(map[string]string{"x-research": "alice", "X-Operator": "prog"}, "prog-ua", SourceProgram)
	if err != nil {
		t.Fatal(err)
	}
	m := got.HeaderMap()
	if m["X-Operator"] != "saas" || m["x-research"] != "alice" || len(m) != 2 {
		t.Fatalf("overlay %v", m)
	}
	if got.UserAgent != "prog-ua" || got.UserAgentSource != SourceProgram || !got.UserAgentLocked {
		t.Fatalf("ua %+v", got)
	}
	if len(got.LockedNames()) != 2 {
		t.Fatalf("locked %v", got.LockedNames())
	}
	// The receiver is unchanged.
	if e.HeaderMap()["X-Research"] != "org" {
		t.Fatal("overlay changed its receiver")
	}
	big := map[string]string{}
	for i := 0; i < MaxHeaders; i++ {
		big["X-P"+string(rune('a'+i))] = "v"
	}
	if _, err := e.Overlay(big, "", SourceProgram); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("overflow accepted: %v", err)
	}
	if got, _ := Merge(PlatformLayer{UserAgent: "op", UserAgentEnforced: true}, OrganizationLayer{}).Overlay(nil, "prog", SourceProgram); got.UserAgent != "op" {
		t.Fatalf("program replaced an enforced UA: %+v", got)
	}
}
