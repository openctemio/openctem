package validation

// The active-probe gate on the validate-command dispatcher: every job runs
// through the scan target gate (exclusions, private-range policy,
// attribution, scan zones) before a command exists, and the gate fails
// closed.

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	scanapp "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/scanzone"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// allowAllGate allows every target, unzoned.
type allowAllGate struct{}

func (allowAllGate) ResolveDispatchTargets(_ context.Context, in scanapp.DispatchTargetsInput) (*scanapp.DispatchTargets, error) {
	return &scanapp.DispatchTargets{Allowed: in.Targets}, nil
}

// recordingGate records its input and answers with a fixed result or error.
type recordingGate struct {
	got []scanapp.DispatchTargetsInput
	out *scanapp.DispatchTargets
	err error
}

func (g *recordingGate) ResolveDispatchTargets(_ context.Context, in scanapp.DispatchTargetsInput) (*scanapp.DispatchTargets, error) {
	g.got = append(g.got, in)
	return g.out, g.err
}

// tenantExclusions excludes values per tenant.
type tenantExclusions map[string]map[string]bool

func (e tenantExclusions) ExcludedTargets(_ context.Context, tenantID string, cands []scope.ExclusionCandidate) (map[shared.ID]bool, error) {
	out := map[shared.ID]bool{}
	for _, c := range cands {
		for _, v := range c.Values {
			if e[tenantID][strings.ToLower(v)] {
				out[c.ID] = true
			}
		}
	}
	return out, nil
}

// tenantAttribution blocks asset ids per tenant.
type tenantAttribution map[shared.ID]map[string]attribution.State

func (a tenantAttribution) ActiveCheckBlocked(_ context.Context, tenantID shared.ID, ids []string) (map[string]attribution.State, error) {
	out := map[string]attribution.State{}
	for _, id := range ids {
		if st, ok := a[tenantID][id]; ok {
			out[id] = st
		}
	}
	return out, nil
}

// BlockedTargets: typed targets without an asset are not refused here.
func (a tenantAttribution) BlockedTargets(context.Context, shared.ID, []string) (map[string]attribution.State, error) {
	return map[string]attribution.State{}, nil
}

type failingAttribution struct{}

func (tenantAttribution) TierExceeded(context.Context, shared.ID, []string, scopedom.Tier) (map[string]*scopedom.RuleRef, error) {
	return nil, nil
}

func (failingAttribution) TierExceeded(context.Context, shared.ID, []string, scopedom.Tier) (map[string]*scopedom.RuleRef, error) {
	return nil, errors.New("db down")
}

func (failingAttribution) BlockedTargets(context.Context, shared.ID, []string) (map[string]attribution.State, error) {
	return nil, errors.New("db down")
}

func (failingAttribution) ActiveCheckBlocked(context.Context, shared.ID, []string) (map[string]attribution.State, error) {
	return nil, errors.New("db down")
}

// tenantZones lists zones per tenant.
type tenantZones map[shared.ID][]*scanzone.Zone

func (z tenantZones) List(_ context.Context, tenantID shared.ID) ([]*scanzone.Zone, error) {
	return z[tenantID], nil
}

func (tenantZones) RoutableSensors(context.Context, shared.ID, []shared.ID, string) (map[shared.ID][]scanzone.SensorCandidate, error) {
	return nil, nil
}

// publicResolver resolves every hostname to a public documentation address.
type publicResolver struct{}

func (publicResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("203.0.113.7")}, nil
}

func validateJob(tenant shared.ID, asset shared.ID, address, name string) ValidationJob {
	return ValidationJob{
		JobID: shared.NewID(), TenantID: tenant, FindingID: shared.NewID(),
		ExecutorKind: KindSafeCheck, Technique: "T1046", TimeoutSeconds: 60,
		Target: Target{AssetID: asset, Type: "domain", Address: address, AssetName: name},
	}
}

// The real scan gate behind the dispatcher: an excluded target (by its
// address or by the asset's inventory name), a private address outside every
// zone, and an asset whose ownership is not confirmed are all refused, and no
// command is created. Tenant B's exclusions, attribution and zones never
// apply to tenant A, and the other way round.
func TestCommandDispatcher_GateRefusesAndCreatesNothing(t *testing.T) {
	tenantA, tenantB := shared.NewID(), shared.NewID()
	unconfirmed, confirmedA := shared.NewID(), shared.NewID()
	sensorA := shared.NewID()
	zoneA, err := scanzone.NewZone(tenantA, "dc-a", "", false, []string{"10.1.0.0/16"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	zoneA.SensorIDs = []shared.ID{sensorA}

	gate := scanapp.NewTargetGate(
		tenantExclusions{
			tenantA.String(): {"excluded.example.com": true, "legacy.example.com": true},
			tenantB.String(): {"b-only.example.com": true},
		},
		tenantAttribution{
			tenantA: {unconfirmed.String(): attribution.StateNeedsReview},
			tenantB: {confirmedA.String(): attribution.StateRejected},
		},
		tenantZones{tenantA: {zoneA}},
		publicResolver{}, logger.NewNop(),
	)

	refused := []struct {
		name string
		job  ValidationJob
		want string
	}{
		{"excluded address", validateJob(tenantA, shared.NewID(), "excluded.example.com", "excluded.example.com"), "scope exclusion"},
		{"URL on an excluded asset", validateJob(tenantA, shared.NewID(), "https://www.legacy.example.com/login", "legacy.example.com"), "scope exclusion"},
		{"private address outside every zone", validateJob(tenantA, shared.NewID(), "10.9.0.5", "10.9.0.5"), "zone"},
		{"loopback", validateJob(tenantA, shared.NewID(), "127.0.0.1", "127.0.0.1"), ""},
		{"ownership not confirmed", validateJob(tenantA, unconfirmed, "shadow.example.com", "shadow.example.com"), "ownership is not confirmed"},
		{"no address", validateJob(tenantA, shared.NewID(), "  ", "x"), "no address"},
	}
	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			cc := &fakeCommandCreator{}
			d := NewCommandDispatcher(cc, gate, logger.NewNop())
			_, err := d.Dispatch(context.Background(), tc.job)
			if !errors.Is(err, ErrTargetRefused) || !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("err = %v, want ErrTargetRefused (a validation error)", err)
			}
			if tc.want != "" && !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %q, want the reason to mention %q", err, tc.want)
			}
			if cc.created != nil {
				t.Fatal("a refused target must not create a command")
			}
		})
	}

	allowed := []struct {
		name string
		job  ValidationJob
		zone *shared.ID
	}{
		// B's exclusion and B's attribution row do not touch A.
		{"tenant B exclusion does not apply to A", validateJob(tenantA, confirmedA, "b-only.example.com", "b-only.example.com"), nil},
		// A's exclusion and A's zone do not touch B: B has no zones, so a
		// public target goes unzoned and A's private range is not B's.
		{"tenant A exclusion does not apply to B", validateJob(tenantB, shared.NewID(), "excluded.example.com", "excluded.example.com"), nil},
		{"private address in the zone, pinned to it", validateJob(tenantA, shared.NewID(), "10.1.2.3", "10.1.2.3"), &zoneA.ID},
	}
	for _, tc := range allowed {
		t.Run(tc.name, func(t *testing.T) {
			cc := &fakeCommandCreator{}
			d := NewCommandDispatcher(cc, gate, logger.NewNop())
			if _, err := d.Dispatch(context.Background(), tc.job); err != nil {
				t.Fatalf("Dispatch: %v", err)
			}
			if cc.created == nil {
				t.Fatal("no command created")
			}
			got := cc.created.ScanZoneID
			switch {
			case tc.zone == nil && got != nil:
				t.Fatalf("scan_zone_id = %v, want unzoned", got)
			case tc.zone != nil && (got == nil || !got.Equals(*tc.zone)):
				t.Fatalf("scan_zone_id = %v, want %v: only the zone's sensors may claim the probe", got, tc.zone)
			}
		})
	}

	// Tenant B's private range is not covered by A's zone.
	cc := &fakeCommandCreator{}
	if _, err := NewCommandDispatcher(cc, gate, logger.NewNop()).Dispatch(context.Background(),
		validateJob(tenantB, shared.NewID(), "10.1.2.3", "10.1.2.3")); !errors.Is(err, ErrTargetRefused) || cc.created != nil {
		t.Fatalf("tenant B probing 10.1.2.3 through tenant A's zone: err = %v, created = %v", err, cc.created != nil)
	}
}

// The gate fails closed: unwired, erroring, or unable to check attribution,
// nothing is dispatched.
func TestCommandDispatcher_GateFailsClosed(t *testing.T) {
	tenant := shared.NewID()
	job := validateJob(tenant, shared.NewID(), "app.example.com", "app.example.com")
	cases := []struct {
		name string
		gate TargetGate
	}{
		{"nil gate", nil},
		{"gate error", &recordingGate{err: errors.New("db down")}},
		{"no exclusion filter", scanapp.NewTargetGate(nil, tenantAttribution{}, nil, nil, logger.NewNop())},
		{"no attribution check", scanapp.NewTargetGate(tenantExclusions{}, nil, nil, nil, logger.NewNop())},
		{"attribution lookup fails", scanapp.NewTargetGate(tenantExclusions{}, failingAttribution{}, nil, nil, logger.NewNop())},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cc := &fakeCommandCreator{}
			d := NewCommandDispatcher(cc, tc.gate, logger.NewNop())
			if _, err := d.Dispatch(context.Background(), job); err == nil {
				t.Fatal("dispatch must fail when the gate cannot decide")
			}
			if err := d.Preflight(context.Background(), tenant, job.Target); err == nil {
				t.Fatal("preflight must fail when the gate cannot decide")
			}
			if cc.created != nil {
				t.Fatal("nothing may be dispatched when the gate cannot decide")
			}
		})
	}
}

// The dispatcher hands the gate the asset id (attribution) and the asset's
// inventory name (exclusions) along with the probed address.
func TestCheckTarget_PassesAssetToGate(t *testing.T) {
	tenant, asset := shared.NewID(), shared.NewID()
	g := &recordingGate{out: &scanapp.DispatchTargets{Allowed: []string{"https://app.example.com/x"}}}
	if _, err := CheckTarget(context.Background(), g, tenant, Target{AssetID: asset, Address: " https://app.example.com/x ", AssetName: "app.example.com"}); err != nil {
		t.Fatal(err)
	}
	if len(g.got) != 1 {
		t.Fatalf("gate called %d times, want 1", len(g.got))
	}
	in := g.got[0]
	if !in.TenantID.Equals(tenant) || len(in.Targets) != 1 || in.Targets[0] != "https://app.example.com/x" {
		t.Fatalf("gate input = %+v", in)
	}
	a, ok := in.Assets["https://app.example.com/x"]
	if !ok || len(a.IDs) != 1 || a.IDs[0] != asset.String() || len(a.AlsoMatch) != 1 || a.AlsoMatch[0] != "app.example.com" {
		t.Fatalf("gate asset = %+v, %v", a, ok)
	}
}

func (tenantAttribution) UncoveredTargets(context.Context, shared.ID, []string) ([]string, error) {
	return nil, nil
}

func (failingAttribution) UncoveredTargets(context.Context, shared.ID, []string) ([]string, error) {
	return nil, nil
}
