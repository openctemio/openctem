package sensor

import (
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func scopeTarget(tenant shared.ID, kind scope.TargetType, pattern string, status scope.Status) *scope.Target {
	now := time.Now()
	return scope.ReconstituteTarget(shared.NewID(), tenant, kind, pattern, "", 0, status, nil, "u", now, now)
}

func scopeExclusion(tenant shared.ID, kind scope.ExclusionType, pattern string, approved bool, expires *time.Time) *scope.Exclusion {
	now := time.Now()
	var by string
	var at *time.Time
	if approved {
		by, at = "u", &now
	}
	return scope.ReconstituteExclusion(shared.NewID(), tenant, kind, pattern, "r", scope.StatusActive, expires, by, at, "u", now, now)
}

func TestPolicyFromScope(t *testing.T) {
	tn := shared.NewID()
	past := time.Now().Add(-time.Hour)
	targets := []*scope.Target{
		scopeTarget(tn, scope.TargetTypeCIDR, "10.20.0.0/16", scope.StatusActive),
		scopeTarget(tn, scope.TargetTypeIPRange, "203.0.113.0/24", scope.StatusActive),
		scopeTarget(tn, scope.TargetTypeIPAddress, "198.51.100.7", scope.StatusActive),
		scopeTarget(tn, scope.TargetTypeDomain, "*.Example.com", scope.StatusActive),
		scopeTarget(tn, scope.TargetTypeSubdomain, "app.example.org", scope.StatusActive),
		scopeTarget(tn, scope.TargetTypeURL, "https://portal.example.net:8443/login", scope.StatusActive),
		scopeTarget(tn, scope.TargetTypeHost, "192.0.2.10", scope.StatusActive),
		// Duplicates collapse.
		scopeTarget(tn, scope.TargetTypeSubdomain, "APP.example.org", scope.StatusActive),
		// Not in effect: never suggested.
		scopeTarget(tn, scope.TargetTypeCIDR, "100.100.0.0/16", scope.StatusInactive),
		// The sensor refuses these in an allow list: left out and counted.
		scopeTarget(tn, scope.TargetTypeCIDR, "127.0.0.0/8", scope.StatusActive),
		scopeTarget(tn, scope.TargetTypeIPAddress, "169.254.169.254", scope.StatusActive),
		scopeTarget(tn, scope.TargetTypeCIDR, "0.0.0.0/0", scope.StatusActive),
		// Types with no network meaning are ignored without counting.
		scopeTarget(tn, scope.TargetTypeRepository, "github.com/acme/*", scope.StatusActive),
		nil,
	}
	exclusions := []*scope.Exclusion{
		scopeExclusion(tn, scope.ExclusionTypeCIDR, "10.20.5.0/24", true, nil),
		scopeExclusion(tn, scope.ExclusionTypeDomain, "secret.example.com", true, nil),
		scopeExclusion(tn, scope.ExclusionTypePath, "/admin", true, nil),            // not a target
		scopeExclusion(tn, scope.ExclusionTypeIPAddress, "10.20.9.9", false, nil),   // not approved
		scopeExclusion(tn, scope.ExclusionTypeIPAddress, "10.20.9.10", true, &past), // expired
	}
	p := PolicyFromScope(targets, exclusions)
	if p.Source != PolicySourceScope || !p.AllowPrivate || p.Open {
		t.Fatalf("policy %+v", p)
	}
	if got := strings.Join(p.Ranges, ","); got != "10.20.0.0/16,192.0.2.10/32,198.51.100.7/32,203.0.113.0/24" {
		t.Fatalf("ranges %s", got)
	}
	if got := strings.Join(p.Domains, ","); got != "*.example.com,app.example.org,example.com,portal.example.net" {
		t.Fatalf("domains %s", got)
	}
	if got := strings.Join(p.Deny, ","); got != "10.20.5.0/24,secret.example.com" {
		t.Fatalf("deny %s", got)
	}
	if p.Skipped != 3 {
		t.Fatalf("skipped %d, want 3 (loopback, metadata, 0.0.0.0/0)", p.Skipped)
	}

	// Public scope only: private targets stay off.
	if p := PolicyFromScope([]*scope.Target{scopeTarget(tn, scope.TargetTypeCIDR, "203.0.113.0/24", scope.StatusActive)}, nil); p.AllowPrivate {
		t.Fatal("a public scope must not turn private targets on")
	}
	// Nothing in scope: nothing to allow.
	if p := PolicyFromScope(nil, nil); p.HasAllow() || p.AllowPrivate {
		t.Fatalf("empty scope %+v", p)
	}
}

func TestPolicyFromScope_Caps(t *testing.T) {
	tn := shared.NewID()
	var targets []*scope.Target
	for i := 0; i < MaxPolicyPrefillEntries+5; i++ {
		targets = append(targets, scopeTarget(tn, scope.TargetTypeSubdomain, "h"+shared.NewID().String()[24:]+".example.com", scope.StatusActive))
	}
	p := PolicyFromScope(targets, nil)
	if len(p.Domains) != MaxPolicyPrefillEntries || p.Truncated != 5 {
		t.Fatalf("domains %d truncated %d", len(p.Domains), p.Truncated)
	}
}

// The rendered policy from a scope is a document the sensor accepts, lists
// the scope and the exclusions, and the daemon snippets turn the private
// switch on for a private range.
func TestTemplates_PolicyFromScope(t *testing.T) {
	tn := shared.NewID()
	scoped := PolicyFromScope(
		[]*scope.Target{
			scopeTarget(tn, scope.TargetTypeCIDR, "10.20.0.0/16", scope.StatusActive),
			scopeTarget(tn, scope.TargetTypeDomain, "*.example.com", scope.StatusActive),
			scopeTarget(tn, scope.TargetTypeCIDR, "127.0.0.0/8", scope.StatusActive),
		},
		[]*scope.Exclusion{scopeExclusion(tn, scope.ExclusionTypeDomain, "secret.example.com", true, nil)},
	)
	for _, dir := range templateSources {
		data := fullData(t)
		data.Policy = scoped
		r := render(t, dir, data)
		d := parsePolicyDoc(t, r.Policy)
		if got := strings.Join(d.Targets.Allow, ","); got != "10.20.0.0/16,*.example.com,example.com" {
			t.Errorf("[%s] allow %s\n%s", dir, got, r.Policy)
		}
		if got := strings.Join(d.Targets.Deny, ","); got != "secret.example.com" {
			t.Errorf("[%s] deny %s", dir, got)
		}
		if !d.Targets.AllowPrivate || !strings.Contains(r.Docker, "SENSOR_ALLOW_PRIVATE_TARGETS") {
			t.Errorf("[%s] private range without the private switch", dir)
		}
		for _, want := range []string{"Your organization's scope", "1 scope entries are left out", "docker kill -s HUP"} {
			if !strings.Contains(r.Policy, want) {
				t.Errorf("[%s] policy lacks %q", dir, want)
			}
		}
		// Plain text: no internal design ids, no note about releases that
		// are no longer supported.
		for _, bad := range []string{"RFC-0", "v0.8.0"} {
			if strings.Contains(r.Policy, bad) {
				t.Errorf("[%s] policy still says %q", dir, bad)
			}
		}
	}
}
