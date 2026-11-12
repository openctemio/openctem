package unit

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/actscope"
	scanservice "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/pkg/domain/assetgroup"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Editing a scan's targets: the Edit wizard let people change them, and the
// API dropped the change while answering 200. An edit's targets now pass
// the checks a new scan's targets pass, as the editor.

func strs(v ...string) *[]string { return &v }

// actRefuses refuses the given targets for the editor (outside their act
// scope) and allows everything else.
type actRefuses map[string]bool

func (a actRefuses) Check(_ context.Context, in actscope.Input) (*actscope.Decision, error) {
	d := &actscope.Decision{RefusedTargets: map[string]string{}, RefusedAssets: map[shared.ID]bool{}}
	for _, t := range in.Targets {
		if a[t] {
			d.RefusedTargets[t] = actscope.ReasonNoScopeTarget
		}
	}
	return d, nil
}

// unownedGate reports the given targets as not authorized for active scanning.
type unownedGate struct {
	allOwned
	blocked map[string]bool
}

func (g unownedGate) BlockedTargets(_ context.Context, _ shared.ID, targets []string) (map[string]attribution.State, error) {
	out := map[string]attribution.State{}
	for _, t := range targets {
		if g.blocked[t] {
			out[t] = attribution.StateUnattributed
		}
	}
	return out, nil
}

func (g unownedGate) TierExceeded(context.Context, shared.ID, []string, scopedom.Tier) (map[string]*scopedom.RuleRef, error) {
	return map[string]*scopedom.RuleRef{}, nil
}

func editTargets(t *testing.T, svc *scanservice.Service, s *scan.Scan, in scanservice.UpdateScanInput) (*scan.Scan, error) {
	t.Helper()
	in.TenantID, in.ScanID = s.TenantID.String(), s.ID.String()
	return svc.UpdateScan(context.Background(), in)
}

func TestUpdateScan_ReplacesDirectTargets(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()
	s := createTestScanInRepo(deps, tenantID, "edit targets", scan.ScanTypeSingle)
	s.Targets = []string{"old.example.com"}

	got, err := editTargets(t, svc, s, scanservice.UpdateScanInput{Targets: strs("new.example.com", "api.example.com")})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Targets) != 2 || got.Targets[0] != "new.example.com" || got.Targets[1] != "api.example.com" {
		t.Fatalf("targets = %v, want the edited list", got.Targets)
	}
	stored, _ := deps.scanRepo.GetByTenantAndID(context.Background(), tenantID, s.ID)
	if len(stored.Targets) != 2 {
		t.Fatalf("stored targets = %v, want the edited list saved", stored.Targets)
	}
}

func TestUpdateScan_OmittedTargetsAreUnchanged(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()
	s := createTestScanInRepo(deps, tenantID, "keep targets", scan.ScanTypeSingle)
	s.Targets = []string{"keep.example.com"}
	groups := append([]shared.ID(nil), s.GetAllAssetGroupIDs()...)

	got, err := editTargets(t, svc, s, scanservice.UpdateScanInput{Name: "renamed"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Targets) != 1 || got.Targets[0] != "keep.example.com" {
		t.Fatalf("targets = %v, want unchanged", got.Targets)
	}
	if len(got.GetAllAssetGroupIDs()) != len(groups) {
		t.Fatalf("groups = %v, want unchanged %v", got.GetAllAssetGroupIDs(), groups)
	}
}

func TestUpdateScan_ReplacesAssetGroups(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()
	s := createTestScanInRepo(deps, tenantID, "edit groups", scan.ScanTypeSingle)
	other, _ := assetgroup.NewAssetGroupWithTenant(tenantID, "other group", assetgroup.EnvironmentProduction, assetgroup.CriticalityHigh)
	deps.assetGroupRepo.groups[other.ID().String()] = other

	got, err := editTargets(t, svc, s, scanservice.UpdateScanInput{AssetGroupIDs: strs(other.ID().String())})
	if err != nil {
		t.Fatal(err)
	}
	ids := got.GetAllAssetGroupIDs()
	if len(ids) != 1 || ids[0] != other.ID() {
		t.Fatalf("groups = %v, want only %s", ids, other.ID())
	}
	if got.AssetGroupID != other.ID() {
		t.Fatalf("primary group = %s, want %s", got.AssetGroupID, other.ID())
	}
}

func TestUpdateScan_RefusesAnotherTenantsAssetGroup(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()
	s := createTestScanInRepo(deps, tenantID, "foreign group", scan.ScanTypeSingle)
	foreign, _ := assetgroup.NewAssetGroupWithTenant(shared.NewID(), "foreign", assetgroup.EnvironmentProduction, assetgroup.CriticalityHigh)
	deps.assetGroupRepo.groups[foreign.ID().String()] = foreign
	before := append([]shared.ID(nil), s.GetAllAssetGroupIDs()...)

	_, err := editTargets(t, svc, s, scanservice.UpdateScanInput{AssetGroupIDs: strs(foreign.ID().String())})
	if !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("err = %v, want not found for another tenant's group", err)
	}
	stored, _ := deps.scanRepo.GetByTenantAndID(context.Background(), tenantID, s.ID)
	if len(stored.GetAllAssetGroupIDs()) != len(before) || stored.GetAllAssetGroupIDs()[0] != before[0] {
		t.Fatalf("groups changed to %v after a refused edit", stored.GetAllAssetGroupIDs())
	}
}

func TestUpdateScan_RefusesInvalidAndInternalTargets(t *testing.T) {
	for _, target := range []string{"127.0.0.1", "10.0.0.0/8", "localhost", "not a target"} {
		t.Run(target, func(t *testing.T) {
			svc, deps := newTestScanService()
			tenantID := shared.NewID()
			s := createTestScanInRepo(deps, tenantID, "bad "+target, scan.ScanTypeSingle)
			s.Targets = []string{"keep.example.com"}
			_, err := editTargets(t, svc, s, scanservice.UpdateScanInput{Targets: strs(target)})
			if !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("err = %v, want a validation refusal", err)
			}
			if s.Targets[0] != "keep.example.com" {
				t.Fatalf("targets changed to %v after a refused edit", s.Targets)
			}
		})
	}
}

func TestUpdateScan_RefusesTargetsOutsideTheEditorsActScope(t *testing.T) {
	svc, deps := newTestScanService(scanservice.WithActScope(actRefuses{"evil.example.org": true}))
	tenantID := shared.NewID()
	s := createTestScanInRepo(deps, tenantID, "act scope", scan.ScanTypeSingle)
	s.Targets = []string{"keep.example.com"}

	_, err := editTargets(t, svc, s, scanservice.UpdateScanInput{
		Targets: strs("keep.example.com", "evil.example.org"), ActorID: shared.NewID().String(),
	})
	if err == nil {
		t.Fatal("a target outside the editor's act scope must be refused")
	}
	stored, _ := deps.scanRepo.GetByTenantAndID(context.Background(), tenantID, s.ID)
	if len(stored.Targets) != 1 {
		t.Fatalf("stored targets = %v after a refused edit", stored.Targets)
	}
}

func TestUpdateScan_RefusesTargetsNotAuthorizedForActiveScanning(t *testing.T) {
	svc, deps := newTestScanService(scanservice.WithAttributionGate(unownedGate{blocked: map[string]bool{"unowned.example.net": true}}))
	tenantID := shared.NewID()
	s := createTestScanInRepo(deps, tenantID, "unowned", scan.ScanTypeSingle)
	s.Targets = []string{"keep.example.com"}

	if _, err := editTargets(t, svc, s, scanservice.UpdateScanInput{Targets: strs("unowned.example.net")}); err == nil {
		t.Fatal("a target the tenant has not authorized for active scanning must be refused")
	}
}

func TestUpdateScan_RefusesLeavingTheScanWithNothingToScan(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()
	s := createTestScanInRepo(deps, tenantID, "empty", scan.ScanTypeSingle)

	_, err := editTargets(t, svc, s, scanservice.UpdateScanInput{Targets: strs(), AssetGroupIDs: strs()})
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("err = %v, want a validation refusal for a scan with no target or group", err)
	}
}

func TestUpdateScan_ClearingGroupsKeepsDirectTargets(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()
	s := createTestScanInRepo(deps, tenantID, "drop groups", scan.ScanTypeSingle)

	got, err := editTargets(t, svc, s, scanservice.UpdateScanInput{Targets: strs("only.example.com"), AssetGroupIDs: strs()})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.GetAllAssetGroupIDs()) != 0 || !got.AssetGroupID.IsZero() {
		t.Fatalf("groups = %v, want none", got.GetAllAssetGroupIDs())
	}
	if len(got.Targets) != 1 {
		t.Fatalf("targets = %v", got.Targets)
	}
}
