package scan

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// tenantNamePorts answers only for its own tenant, like the tenant-scoped
// query.
type tenantNamePorts struct {
	tenant shared.ID
	ports  map[string][]int
	err    error
	asked  []string
}

func (r *tenantNamePorts) OpenPortsOfNames(_ context.Context, tenantID shared.ID, names []string) (map[string][]int, error) {
	r.asked = append(r.asked, names...)
	if r.err != nil {
		return nil, r.err
	}
	out := map[string][]int{}
	if tenantID != r.tenant {
		return out, nil
	}
	for _, n := range names {
		if p, ok := r.ports[n]; ok {
			out[n] = p
		}
	}
	return out, nil
}

func namedPortsService(reader NamePortReader, excl map[string]bool, blocked map[string]attribution.State) *Service {
	s := &Service{scopeExclusions: &stubExclusions{values: excl}, attributionGate: &stubGate{blockedTyped: blocked}, logger: logger.NewNop()}
	s.SetNamePorts(reader)
	return s
}

func TestNamedPortCandidates(t *testing.T) {
	ctx, tenant := context.Background(), shared.NewID()
	r := &tenantNamePorts{tenant: tenant, ports: map[string][]int{
		"www.example.com": {8443, 443, 80, 2083, 8443},
		"api.example.com": {9443},
	}}
	s := namedPortsService(r, nil, nil)
	kept := []string{"WWW.example.com", "api.example.com", "203.0.113.5", "203.0.113.5:8080", "https://x.example.com", "www.example.com"}

	got := s.namedPortCandidates(ctx, tenant, "probe.http", kept, 100)
	if strings.Join(got, ",") != "api.example.com:9443,www.example.com:2083,www.example.com:8443" {
		t.Fatalf("candidates = %v", got)
	}
	// Only names were asked about, once each.
	if strings.Join(r.asked, ",") != "www.example.com,api.example.com" {
		t.Fatalf("asked = %v", r.asked)
	}
	// Room caps the total.
	if got := s.namedPortCandidates(ctx, tenant, "probe.http", kept, 1); len(got) != 1 {
		t.Fatalf("room 1 = %v", got)
	}
	// Only the HTTP probe takes them.
	if got := s.namedPortCandidates(ctx, tenant, "vuln.templates", kept, 100); got != nil {
		t.Fatalf("other capability = %v", got)
	}
	// Another tenant's batch gets nothing from this tenant's inventory.
	if got := s.namedPortCandidates(ctx, shared.NewID(), "probe.http", kept, 100); len(got) != 0 {
		t.Fatalf("cross-tenant = %v", got)
	}
}

func TestNamedPortCandidates_PerNameCap(t *testing.T) {
	ctx, tenant := context.Background(), shared.NewID()
	var many []int
	for p := 10000; p < 10000+3*maxNamedPortsPerName; p++ {
		many = append(many, p)
	}
	s := namedPortsService(&tenantNamePorts{tenant: tenant, ports: map[string][]int{"a.example.com": many}}, nil, nil)
	if got := s.namedPortCandidates(ctx, tenant, "probe.http", []string{"a.example.com"}, 500); len(got) != maxNamedPortsPerName {
		t.Fatalf("per-name cap: %d", len(got))
	}
}

// Every named port passes the batch's gate: a host:port exclusion and a
// rejected name refuse it, the rest is added after the batch's own targets.
func TestWithNamedPorts_Gated(t *testing.T) {
	ctx, tenant := context.Background(), shared.NewID()
	r := &tenantNamePorts{tenant: tenant, ports: map[string][]int{
		"www.example.com": {8443, 9443},
		"bad.example.com": {8443},
	}}
	s := namedPortsService(r,
		map[string]bool{"www.example.com:9443": true},
		map[string]attribution.State{"bad.example.com:8443": attribution.StateRejected})
	tier := scopedom.TierActive
	in := CoverageInput{TenantID: tenant, Capability: "probe.http"}
	gateIn := DispatchTargetsInput{TenantID: tenant, Tier: &tier, SkipZoneRouting: true}

	got := s.withNamedPorts(ctx, in, gateIn, []string{"www.example.com", "bad.example.com"})
	if strings.Join(got, ",") != "www.example.com,bad.example.com,www.example.com:8443" {
		t.Fatalf("kept = %v", got)
	}
}

// A failed lookup, or a gate failure on the derived set, leaves the batch
// exactly as it was.
func TestWithNamedPorts_FallsBack(t *testing.T) {
	ctx, tenant := context.Background(), shared.NewID()
	tier := scopedom.TierActive
	in := CoverageInput{TenantID: tenant, Capability: "probe.http"}
	gateIn := DispatchTargetsInput{TenantID: tenant, Tier: &tier, SkipZoneRouting: true}
	batch := []string{"www.example.com"}

	s := namedPortsService(&tenantNamePorts{tenant: tenant, err: errors.New("db down")}, nil, nil)
	if got := s.withNamedPorts(ctx, in, gateIn, batch); strings.Join(got, ",") != "www.example.com" {
		t.Fatalf("lookup failure: %v", got)
	}

	s = namedPortsService(&tenantNamePorts{tenant: tenant, ports: map[string][]int{"www.example.com": {8443}}}, nil, nil)
	s.scopeExclusions = &stubExclusions{err: errors.New("exclusions unavailable")}
	if got := s.withNamedPorts(ctx, in, gateIn, batch); strings.Join(got, ",") != "www.example.com" {
		t.Fatalf("gate failure: %v", got)
	}

	// Without the lookup wired, nothing changes.
	plain := &Service{logger: logger.NewNop()}
	if got := plain.withNamedPorts(ctx, in, gateIn, batch); strings.Join(got, ",") != "www.example.com" {
		t.Fatalf("unwired: %v", got)
	}
}
