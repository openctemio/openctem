package mcpoauth

import (
	"errors"
	"reflect"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestReadScopesAreTheFourReadScopes(t *testing.T) {
	want := []Scope{ScopeAssetsRead, ScopeComplianceRead, ScopeFindingsRead, ScopePentestRead}
	if got := ReadScopes(); !reflect.DeepEqual(got, want) {
		t.Fatalf("ReadScopes() = %v, want %v", got, want)
	}
	for _, s := range ReadScopes() {
		if IsWrite(s) {
			t.Errorf("%s is a read scope but marked write", s)
		}
		if Title(s) == "" {
			t.Errorf("%s has no consent title", s)
		}
	}
}

func TestParseScopes(t *testing.T) {
	got, err := ParseScopes("  mcp:findings.read mcp:assets.read mcp:findings.read ")
	if err != nil {
		t.Fatal(err)
	}
	if want := []Scope{ScopeAssetsRead, ScopeFindingsRead}; !reflect.DeepEqual(got, want) {
		t.Fatalf("ParseScopes = %v, want %v (sorted, deduplicated)", got, want)
	}
	if got, err := ParseScopes(""); err != nil || len(got) != 0 {
		t.Fatalf("empty scope = %v, %v; want empty, nil", got, err)
	}
	for _, bad := range []string{"mcp:assets.write", "findings:read", "*", "mcp:findings.read offline_access", "MCP:FINDINGS.READ"} {
		if _, err := ParseScopes(bad); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("ParseScopes(%q) err = %v, want validation error", bad, err)
		}
	}
}

func TestPermissionsOfScopes(t *testing.T) {
	got := Permissions([]Scope{ScopePentestRead, ScopeFindingsRead, ScopeFindingsRead})
	want := []string{
		string(permission.FindingsRead),
		string(permission.PentestCampaignsRead),
		string(permission.PentestFindingsRead),
		string(permission.PentestRetestsRead),
		string(permission.PentestTemplatesRead),
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Permissions = %v, want %v", got, want)
	}
	if got := Permissions([]Scope{"mcp:unknown"}); len(got) != 0 {
		t.Fatalf("unknown scope grants %v, want nothing", got)
	}
}

// Every permission a scope stands for must be a read permission that
// exists: a typo here would silently grant nothing, a write permission
// would turn a read scope into a write scope.
func TestScopePermissionsAreKnownReadPermissions(t *testing.T) {
	known := map[string]bool{}
	for _, p := range permission.AllPermissions() {
		known[string(p)] = true
	}
	for s, info := range catalog {
		for _, p := range info.perms {
			if !known[string(p)] {
				t.Errorf("scope %s: permission %s does not exist", s, p)
			}
			if !info.write && !isReadPermission(string(p)) {
				t.Errorf("read scope %s stands for non-read permission %s", s, p)
			}
		}
	}
}

func isReadPermission(p string) bool {
	return len(p) > 5 && p[len(p)-5:] == ":read"
}

func TestScopesFor(t *testing.T) {
	if got := ScopesFor(string(permission.PentestRetestsRead)); !reflect.DeepEqual(got, []Scope{ScopePentestRead}) {
		t.Fatalf("ScopesFor(pentest retests) = %v", got)
	}
	if got := ScopesFor(string(permission.FindingsWrite)); len(got) != 1 || got[0] != ScopeFindingsWrite {
		t.Fatalf("ScopesFor(findings:write) = %v, want the write scope only", got)
	}
}

func TestNewEndpoints(t *testing.T) {
	e, err := NewEndpoints("https://OpenCTEM.Example/")
	if err != nil {
		t.Fatal(err)
	}
	want := Endpoints{
		Issuer:           "https://openctem.example",
		Resource:         "https://openctem.example/api/v1/mcp",
		ResourceMetadata: "https://openctem.example/.well-known/oauth-protected-resource/api/v1/mcp",
	}
	if e != want {
		t.Fatalf("NewEndpoints = %+v, want %+v", e, want)
	}
	if e, err := NewEndpoints("http://localhost:3000"); err != nil || e.Issuer != "http://localhost:3000" {
		t.Fatalf("loopback http = %+v, %v; want accepted", e, err)
	}
	if _, err := NewEndpoints("http://127.0.0.1:8080"); err != nil {
		t.Fatalf("loopback IP http refused: %v", err)
	}
	for _, bad := range []string{
		"", "openctem.example", "http://openctem.example", "ftp://openctem.example",
		"https://openctem.example/app", "https://openctem.example?x=1", "https://openctem.example#f",
		"https://user:pw@openctem.example",
	} {
		if _, err := NewEndpoints(bad); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("NewEndpoints(%q) err = %v, want validation error", bad, err)
		}
	}
}
