package handler

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	sensorapp "github.com/openctemio/openctem/api/internal/app/sensor"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/scanzone"
	"github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// fakeScope answers only for its own tenant, like the tenant-scoped
// repositories; any other tenant gets nothing.
type fakeScope struct {
	tenant  shared.ID
	targets []*scope.Target
	excl    []*scope.Exclusion
	zones   []*scanzone.Zone
	err     error
	asked   []shared.ID
}

func (f *fakeScope) List(_ context.Context, tenantID shared.ID) ([]*scanzone.Zone, error) {
	f.asked = append(f.asked, tenantID)
	if tenantID != f.tenant {
		return nil, nil
	}
	return f.zones, nil
}

type fakeTargets struct{ *fakeScope }

func (f fakeTargets) ListActive(_ context.Context, tenantID shared.ID) ([]*scope.Target, error) {
	f.asked = append(f.asked, tenantID)
	if f.err != nil {
		return nil, f.err
	}
	if tenantID != f.tenant {
		return nil, nil
	}
	return f.targets, nil
}

type fakeExclusions struct{ *fakeScope }

func (f fakeExclusions) ListActive(_ context.Context, tenantID shared.ID) ([]*scope.Exclusion, error) {
	if tenantID != f.tenant {
		return nil, nil
	}
	return f.excl, nil
}

func TestSensorPolicyPrefill(t *testing.T) {
	tenant, other, sensorID := shared.NewID(), shared.NewID(), shared.NewID()
	now := time.Now()
	f := &fakeScope{
		tenant: tenant,
		targets: []*scope.Target{
			scope.ReconstituteTarget(shared.NewID(), tenant, scope.TargetTypeCIDR, "203.0.113.0/24", "", 0, scope.StatusActive, nil, "u", now, now),
			scope.ReconstituteTarget(shared.NewID(), tenant, scope.TargetTypeDomain, "*.example.com", "", 0, scope.StatusActive, nil, "u", now, now),
		},
		excl: []*scope.Exclusion{
			scope.ReconstituteExclusion(shared.NewID(), tenant, scope.ExclusionTypeDomain, "secret.example.com", "r", scope.StatusActive, nil, "u", &now, "u", now, now),
		},
	}
	p := &SensorPolicyPrefill{Zones: f, Targets: fakeTargets{f}, Exclusions: fakeExclusions{f}}
	canScope := context.WithValue(context.Background(), middleware.FetchedPermissionsKey,
		[]string{permission.SensorsRead.String(), permission.ScopeRead.String()})
	sensorsOnly := context.WithValue(context.Background(), middleware.FetchedPermissionsKey,
		[]string{permission.SensorsRead.String()})

	// No zone: the organization's scope, exclusions as deny.
	got := p.For(canScope, tenant, sensorID)
	if got.Source != sensorapp.PolicySourceScope || strings.Join(got.Ranges, ",") != "203.0.113.0/24" ||
		strings.Join(got.Domains, ",") != "*.example.com,example.com" || strings.Join(got.Deny, ",") != "secret.example.com" {
		t.Fatalf("scope prefill %+v", got)
	}

	// A member who cannot read the scope never sees it through the policy.
	if got := p.For(sensorsOnly, tenant, sensorID); got.HasAllow() || len(got.Deny) != 0 || got.Source != "" {
		t.Fatalf("scope leaked to a member without scope read: %+v", got)
	}

	// Another tenant's caller gets that tenant's (empty) scope, never this one.
	if got := p.For(canScope, other, sensorID); got.HasAllow() || len(got.Deny) != 0 {
		t.Fatalf("cross-tenant prefill %+v", got)
	}

	// The sensor's zones win over the scope; the exclusions still deny.
	f.zones = []*scanzone.Zone{{Name: "dc", Ranges: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")}, SensorIDs: []shared.ID{sensorID}}}
	got = p.For(canScope, tenant, sensorID)
	if got.Source != sensorapp.PolicySourceZones || strings.Join(got.Ranges, ",") != "10.20.0.0/16" || len(got.Domains) != 0 ||
		strings.Join(got.Deny, ",") != "secret.example.com" || !got.AllowPrivate {
		t.Fatalf("zone prefill %+v", got)
	}
	// Zones are not scope: a member without scope read still gets them.
	if got := p.For(sensorsOnly, tenant, sensorID); strings.Join(got.Ranges, ",") != "10.20.0.0/16" || len(got.Deny) != 0 {
		t.Fatalf("zones for a sensors-only member %+v", got)
	}
	// A sensor that does not exist yet (install before pairing) has no zone.
	if got := p.For(canScope, tenant, shared.ID{}); got.Source != sensorapp.PolicySourceScope {
		t.Fatalf("pre-pairing prefill %+v", got)
	}

	// A read error leaves the scope out instead of failing the commands.
	f.zones, f.err = nil, errors.New("db down")
	if got := p.For(canScope, tenant, sensorID); got.HasAllow() || strings.Join(got.Deny, ",") != "secret.example.com" {
		t.Fatalf("read error prefill %+v", got)
	}

	// Nil prefill and zero tenant: nothing.
	var none *SensorPolicyPrefill
	if got := none.For(canScope, tenant, sensorID); got.HasAllow() {
		t.Fatal("nil prefill")
	}
	if got := p.For(canScope, shared.ID{}, sensorID); got.HasAllow() {
		t.Fatal("zero tenant")
	}
}
