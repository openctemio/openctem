package scan

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/instancezone"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// stubZones assigns zones to organizations the way the instancezone service
// answers: only the asking organization's zones are considered.
type stubZones struct {
	byTenant map[shared.ID][]*instancezone.Zone
	err      error
}

func (z stubZones) ZoneFor(_ context.Context, tenantID shared.ID, internal []string) (*instancezone.Zone, error) {
	if z.err != nil {
		return nil, z.err
	}
	ps := make([]netip.Prefix, 0, len(internal))
	for _, t := range internal {
		p, ok := instancezone.TargetPrefix(t)
		if !ok {
			return nil, nil
		}
		ps = append(ps, p)
	}
	return instancezone.Covering(z.byTenant[tenantID], ps), nil
}

func mustInstanceZone(t *testing.T, ranges ...string) *instancezone.Zone {
	t.Helper()
	z, err := instancezone.New("zone", "", ranges)
	if err != nil {
		t.Fatal(err)
	}
	return z
}

// A single scan's internal targets pass the shared check only inside an
// instance scan zone assigned to the organization; organization B's zone
// over the same range never serves organization A; workflow steps keep
// the public-only rule; a failed lookup is an error.
func TestSharedTargetRefusal_InstanceZones(t *testing.T) {
	ctx := context.Background()
	orgA, orgB := shared.NewID(), shared.NewID()
	zones := stubZones{byTenant: map[shared.ID][]*instancezone.Zone{orgB: {mustInstanceZone(t, "10.20.0.0/16")}}}
	svc := &Service{logger: logger.NewNop(), attributionGate: sharedCheckGate{}, proofPolicy: StaticProofPolicy(false),
		zoneResolver: publicResolver{}, instanceZones: zones}

	refused := func(err error) bool {
		var de *shared.DomainError
		return errors.As(err, &de) && de.Code == codePlatformRefused
	}
	// A has no zone: refused, even though B's zone covers the address.
	if r, err := svc.sharedTargetRefusal(ctx, orgA, []string{"10.20.1.5"}, false, true); err != nil || !refused(r) {
		t.Fatalf("A without a zone: refusal=%v err=%v", r, err)
	}
	// B inside its zone: allowed.
	if r, err := svc.sharedTargetRefusal(ctx, orgB, []string{"10.20.1.5", "203.0.113.4"}, false, true); err != nil || r != nil {
		t.Fatalf("B inside its zone: refusal=%v err=%v", r, err)
	}
	// B outside its zone, or an internal name: refused.
	for _, target := range []string{"10.21.0.1", "10.0.0.0/8", "db.internal", "169.254.169.254"} {
		if r, _ := svc.sharedTargetRefusal(ctx, orgB, []string{target}, false, true); !refused(r) {
			t.Fatalf("B target %s outside its zone was not refused: %v", target, r)
		}
	}
	// Workflow steps (and every caller of PlatformTargetRefusal): public only.
	if err := svc.PlatformTargetRefusal(ctx, orgB, []string{"10.20.1.5"}, false); !refused(err) {
		t.Fatalf("a workflow step reached a zone: %v", err)
	}
	// Asset groups never.
	if r, _ := svc.sharedTargetRefusal(ctx, orgB, []string{"10.20.1.5"}, true, true); !refused(r) {
		t.Fatal("an asset group passed")
	}
	// A failed zone lookup is an error (callers refuse).
	svc.instanceZones = stubZones{err: errors.New("db down")}
	if _, err := svc.sharedTargetRefusal(ctx, orgB, []string{"10.20.1.5"}, false, true); err == nil {
		t.Fatal("a failed lookup was not reported")
	}
	// Without the lookup wired: refused.
	svc.instanceZones = nil
	if r, _ := svc.sharedTargetRefusal(ctx, orgB, []string{"10.20.1.5"}, false, true); !refused(r) {
		t.Fatal("internal target passed without instance zones")
	}
}

// The shared job of an internal target is stamped with the organization's
// zone; a shared job whose internal target lies in no assigned zone is
// refused; public and organization jobs are not stamped.
func TestStampInstanceZone(t *testing.T) {
	ctx := context.Background()
	orgA, orgB := shared.NewID(), shared.NewID()
	zb := mustInstanceZone(t, "10.20.0.0/16")
	svc := &Service{logger: logger.NewNop(), instanceZones: stubZones{byTenant: map[shared.ID][]*instancezone.Zone{orgB: {zb}}}}
	newCmd := func(tenant shared.ID, platform bool) *command.Command {
		c, err := command.NewCommand(tenant, command.CommandTypeScan, command.CommandPriorityNormal, json.RawMessage(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		if platform {
			if err := c.SetPlatformJob(1); err != nil {
				t.Fatal(err)
			}
		}
		return c
	}
	c := newCmd(orgB, true)
	if err := svc.stampInstanceZone(ctx, c, []string{"10.20.3.3"}); err != nil || c.InstanceScanZoneID == nil || *c.InstanceScanZoneID != zb.ID {
		t.Fatalf("B's job: zone=%v err=%v", c.InstanceScanZoneID, err)
	}
	c = newCmd(orgA, true)
	if err := svc.stampInstanceZone(ctx, c, []string{"10.20.3.3"}); err == nil || c.InstanceScanZoneID != nil {
		t.Fatalf("A's job used B's zone: zone=%v err=%v", c.InstanceScanZoneID, err)
	}
	for _, tc := range []struct {
		platform bool
		targets  []string
	}{{true, []string{"203.0.113.9"}}, {false, []string{"10.20.3.3"}}} {
		c = newCmd(orgB, tc.platform)
		if err := svc.stampInstanceZone(ctx, c, tc.targets); err != nil || c.InstanceScanZoneID != nil {
			t.Fatalf("platform=%v targets=%v stamped %v (%v)", tc.platform, tc.targets, c.InstanceScanZoneID, err)
		}
	}
	if !slices.Equal(internalTargets([]string{"a.example", "10.0.0.1", "192.168.0.0/24"}), []string{"10.0.0.1", "192.168.0.0/24"}) {
		t.Fatal("internalTargets")
	}
}
