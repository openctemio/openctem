package tenablesc

import (
	"context"
	"errors"
	"testing"

	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The claim's grant gate withholds a connector command the sensor's grant
// does not allow, and before this pre-check the command then sat pending
// until it expired (found on a scratch end-to-end run: the default profile
// of a paired scanning sensor allows neither connector type, and a sensor
// at trust "new" never receives a T1 scan). Now the request is refused at
// once with what to widen.

type fakeGrants struct {
	byTenant map[shared.ID]map[shared.ID]*sensordom.Grant
	err      error
}

func (f *fakeGrants) Get(_ context.Context, tenantID, sensorID shared.ID) (*sensordom.Grant, error) {
	if f.err != nil {
		return nil, f.err
	}
	g, ok := f.byTenant[tenantID][sensorID]
	if !ok {
		return nil, shared.ErrNotFound
	}
	return g, nil
}

func grantEnv(t *testing.T, g *sensordom.Grant) (*env, *fakeGrants) {
	t.Helper()
	e := newEnv(t)
	fg := &fakeGrants{byTenant: map[shared.ID]map[shared.ID]*sensordom.Grant{e.tenant: {e.sensorID: g}}}
	e.svc.SetGrantReader(fg)
	return e, fg
}

func profileGrant(t *testing.T, e *env, profile string) *sensordom.Grant {
	t.Helper()
	g, err := sensordom.NewGrantFromProfile(e.tenant, e.sensorID, profile, nil)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func connectorGrant(trust sensordom.TrustLevel, cidrs ...string) *sensordom.Grant {
	return &sensordom.Grant{Profile: sensordom.ProfileCustom, TrustLevel: trust, TierCeiling: sensordom.TierActive,
		JobTypes: []string{"connector_sync", "connector_scan"}, Tools: []string{ToolName},
		TargetNetwork: sensordom.TargetNetworkAny, TargetCIDRs: cidrs, RemoteActions: []string{}}
}

func TestGrantPrecheck_Sync(t *testing.T) {
	ctx := context.Background()

	e := newEnv(t)
	e.svc.SetGrantReader(&fakeGrants{})
	scanner := profileGrant(t, e, sensordom.ProfileInternalScanner)
	e.svc.SetGrantReader(&fakeGrants{byTenant: map[shared.ID]map[shared.ID]*sensordom.Grant{e.tenant: {e.sensorID: scanner}}})
	if _, err := e.svc.RequestSync(ctx, e.tenant, e.intg.ID(), TriggerManual, nil); !IsGrantRefusal(err) || !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("default scanner profile: err %v, want the grant refusal", err)
	}
	if len(e.cmds.rows) != 0 {
		t.Fatal("a refused sync queued a command")
	}

	e2 := newEnv(t)
	collector := profileGrant(t, e2, sensordom.ProfileCollector)
	e2.svc.SetGrantReader(&fakeGrants{byTenant: map[shared.ID]map[shared.ID]*sensordom.Grant{e2.tenant: {e2.sensorID: collector}}})
	if _, err := e2.svc.RequestSync(ctx, e2.tenant, e2.intg.ID(), TriggerManual, nil); err != nil {
		t.Fatalf("collector profile allows connector_sync: %v", err)
	}

	// A grant that cannot be read is left to the claim (which fails closed).
	e3 := newEnv(t)
	e3.svc.SetGrantReader(&fakeGrants{err: errors.New("db down")})
	if _, err := e3.svc.RequestSync(ctx, e3.tenant, e3.intg.ID(), TriggerManual, nil); err != nil {
		t.Fatalf("unreadable grant: %v", err)
	}
}

func TestGrantPrecheck_Scan(t *testing.T) {
	ctx := context.Background()
	targets := []string{"10.0.0.0/28", "10.0.1.5"}
	for name, tc := range map[string]struct {
		grant   *sensordom.Grant
		refused bool
	}{
		"trusted connector grant":       {connectorGrant(sensordom.TrustTrusted, "10.0.0.0/16"), false},
		"trust new: passive work only":  {connectorGrant(sensordom.TrustNew, "10.0.0.0/16"), true},
		"targets outside the grant":     {connectorGrant(sensordom.TrustTrusted, "192.168.0.0/16"), true},
		"sync only (collector profile)": {&sensordom.Grant{TrustLevel: sensordom.TrustTrusted, TierCeiling: sensordom.TierPassive, JobTypes: []string{"collect", "connector_sync"}, TargetNetwork: sensordom.TargetNetworkNone}, true},
		"another tool only": {func() *sensordom.Grant {
			g := connectorGrant(sensordom.TrustTrusted)
			g.Tools = []string{"nuclei"}
			return g
		}(), true},
	} {
		t.Run(name, func(t *testing.T) {
			e, _ := grantEnv(t, tc.grant)
			cmd, err := e.svc.NewScanCommand(ctx, e.tenant, scanCfg(e.intg, nil), targets, nil)
			if tc.refused != IsGrantRefusal(err) {
				t.Fatalf("err %v, refused want %v", err, tc.refused)
			}
			if !tc.refused && (err != nil || cmd == nil) {
				t.Fatalf("err %v cmd %v", err, cmd)
			}
		})
	}
}

// Another tenant's grant of the same sensor id is never read.
func TestGrantPrecheck_TenantScoped(t *testing.T) {
	e := newEnv(t)
	other := shared.NewID()
	e.svc.SetGrantReader(&fakeGrants{byTenant: map[shared.ID]map[shared.ID]*sensordom.Grant{
		other:    {e.sensorID: connectorGrant(sensordom.TrustTrusted, "10.0.0.0/8")},
		e.tenant: {e.sensorID: profileGrant(t, e, sensordom.ProfileInternalScanner)},
	}})
	if _, err := e.svc.NewScanCommand(context.Background(), e.tenant, scanCfg(e.intg, nil), []string{"10.0.0.1"}, nil); !IsGrantRefusal(err) {
		t.Fatalf("err %v: the tenant's own grant must decide", err)
	}
}
