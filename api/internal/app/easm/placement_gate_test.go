package easm

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Ownership confirmation applies only to a job on platform sensors of the
// hosted service. A job on the organization's own sensors, and every job of
// a self-hosted install, treats discovered and unclassified assets as fully
// authorized; a rejection, the deny list and the guardrails hold everywhere.
func TestActiveGate_ConfirmationOnlyOnManagedPlatformSensors(t *testing.T) {
	type deployment struct {
		name      string
		managed   bool
		placement attribution.Placement
		required  bool // ownership confirmation applies
	}
	deployments := []deployment{
		{"managed, platform sensor", true, attribution.PlacementPlatform, true},
		{"managed, sensor not known yet", true, attribution.PlacementUnknown, true},
		{"managed, tenant sensor", true, attribution.PlacementTenant, false},
		{"self-hosted, tenant sensor", false, attribution.PlacementTenant, false},
		{"self-hosted, platform sensor", false, attribution.PlacementPlatform, false},
		{"self-hosted, sensor not known yet", false, attribution.PlacementUnknown, false},
	}
	for _, d := range deployments {
		t.Run(d.name, func(t *testing.T) {
			f := newGateFixture(t)
			g := NewActiveGate(f, f, f, f)
			g.SetManagedService(d.managed)
			ctx := attribution.WithPlacement(context.Background(), d.placement)

			// Under a verified domain, no scope entry covers them: unclassified.
			discovered := f.add(t, "found.verified.com", asset.AssetTypeSubdomain)
			f.record(discovered, attribution.StateDiscovered, false)
			unrecorded := f.add(t, "new.verified.com", asset.AssetTypeSubdomain)
			// Under no domain of the organization: a guardrail holds it.
			foreign := f.add(t, "cdn.thirdparty.example", asset.AssetTypeDomain)
			f.record(foreign, attribution.StateDiscovered, false)
			// The tenant said "not ours", or kept it out of the scans.
			rejected := f.add(t, "no.verified.com", asset.AssetTypeSubdomain)
			f.record(rejected, attribution.StateRejected, true)
			monitor := f.add(t, "watch.verified.com", asset.AssetTypeSubdomain)
			f.record(monitor, attribution.StateMonitorOnly, true)
			// Covered by an active scope entry: allowed everywhere.
			covered := f.add(t, "app.scoped.com", asset.AssetTypeSubdomain)
			f.record(covered, attribution.StateDiscovered, false)

			ids := []string{}
			for _, a := range []*asset.Asset{discovered, unrecorded, foreign, rejected, monitor, covered} {
				ids = append(ids, a.ID().String())
			}
			got, err := g.ActiveCheckBlocked(ctx, f.tenant, ids)
			if err != nil {
				t.Fatal(err)
			}
			state := func(a *asset.Asset) attribution.State { return got[a.ID().String()] }

			if d.required {
				if state(discovered) != attribution.StateDiscovered || state(unrecorded) != attribution.StateUnattributed {
					t.Errorf("unconfirmed assets must be refused: %v", got)
				}
			} else if state(discovered) != "" || state(unrecorded) != "" {
				t.Errorf("unconfirmed assets must be authorized: discovered=%q unrecorded=%q", state(discovered), state(unrecorded))
			}
			// Never relaxed.
			if state(rejected) != attribution.StateRejected {
				t.Errorf("rejected asset: %q", state(rejected))
			}
			if state(monitor) != attribution.StateMonitorOnly {
				t.Errorf("monitor-only asset: %q", state(monitor))
			}
			if state(foreign) == "" {
				t.Errorf("an asset under none of the organization's domains must stay refused (guardrail)")
			}
			if state(covered) != "" {
				t.Errorf("covered asset: %q", state(covered))
			}

			// Typed text decides the same way, and a rejected parent refuses.
			typed, err := g.BlockedTargets(ctx, f.tenant, []string{"found.verified.com", "x.no.verified.com"})
			if err != nil {
				t.Fatal(err)
			}
			if (typed["found.verified.com"] != "") != d.required {
				t.Errorf("typed discovered asset: %q (required=%v)", typed["found.verified.com"], d.required)
			}
			if typed["x.no.verified.com"] != attribution.StateRejected {
				t.Errorf("typed name under a rejected name: %q", typed["x.no.verified.com"])
			}
		})
	}
}

// A name that resolves only through a wildcard record is scanned on the
// organization's own sensors when an active scope entry covers it; on a
// platform sensor of the hosted service it stays passive. A name no entry
// covers stays passive everywhere.
func TestActiveGate_WildcardOnlyByPlacement(t *testing.T) {
	cases := []struct {
		name      string
		managed   bool
		placement attribution.Placement
		coveredOK bool
	}{
		{"managed, platform sensor", true, attribution.PlacementPlatform, false},
		{"managed, tenant sensor", true, attribution.PlacementTenant, true},
		{"self-hosted, tenant sensor", false, attribution.PlacementTenant, true},
		{"self-hosted, platform sensor", false, attribution.PlacementPlatform, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newGateFixture(t)
			g := NewActiveGate(f, f, f, f)
			g.SetManagedService(c.managed)
			marks := &wildcardMarks{tenant: f.tenant, marked: map[shared.ID]bool{}}
			g.SetWildcardDNS(marks)
			ctx := attribution.WithPlacement(context.Background(), c.placement)

			covered := f.add(t, "guess.scoped.com", asset.AssetTypeSubdomain)
			f.record(covered, attribution.StateConfirmed, false)
			marks.marked[covered.ID()] = true
			svc := f.add(t, "guess.scoped.com:443:tcp", asset.AssetTypeService)
			uncovered := f.add(t, "guess.verified.com", asset.AssetTypeSubdomain)
			marks.marked[uncovered.ID()] = true

			got, err := g.ActiveCheckBlocked(ctx, f.tenant, []string{covered.ID().String(), svc.ID().String(), uncovered.ID().String()})
			if err != nil {
				t.Fatal(err)
			}
			for name, a := range map[string]*asset.Asset{"covered": covered, "service on the covered host": svc} {
				refused := got[a.ID().String()] == attribution.StateWildcardOnly
				if refused == c.coveredOK {
					t.Errorf("%s: state %q, scanned want %v", name, got[a.ID().String()], c.coveredOK)
				}
			}
			if got[uncovered.ID().String()] != attribution.StateWildcardOnly {
				t.Errorf("wildcard-only name no entry covers: %q, want wildcard_only", got[uncovered.ID().String()])
			}

			typed, err := g.BlockedTargets(ctx, f.tenant, []string{"guess.scoped.com"})
			if err != nil {
				t.Fatal(err)
			}
			if (typed["guess.scoped.com"] == attribution.StateWildcardOnly) == c.coveredOK {
				t.Errorf("typed covered name: %q", typed["guess.scoped.com"])
			}
		})
	}
}

// The deny list applies on every placement.
func TestActiveGate_DenyListHoldsOnEveryPlacement(t *testing.T) {
	for _, p := range []attribution.Placement{attribution.PlacementTenant, attribution.PlacementPlatform, attribution.PlacementUnknown} {
		f := newGateFixture(t)
		gr, _ := scopedom.NewGuardrails(0, 0, []string{"198.51.100.200/32"})
		g := NewActiveGate(f, f, f, f).WithPlatformPolicy(gr)
		g.SetManagedService(true)
		ctx := attribution.WithPlacement(context.Background(), p)
		got, err := g.BlockedTargets(ctx, f.tenant, []string{"198.51.100.200"})
		if err != nil {
			t.Fatal(err)
		}
		if len(got) == 0 {
			t.Errorf("placement %d: the denied address must stay refused", p)
		}
	}
}
