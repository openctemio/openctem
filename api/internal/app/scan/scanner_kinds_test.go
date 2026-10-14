package scan

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/assetgroup"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// A single-scanner run hands every target to one tool. A typed-in network
// range used to reach nuclei or httpx as written (nuclei then ran every
// template on every address); it is now left out for them and counted as
// incompatible. A port scanner still takes it.
func TestResolveScanTargets_ScannerKinds(t *testing.T) {
	ctx := context.Background()
	svc := allowAllChecks(&Service{tools: testTools, logger: logger.NewNop()})

	got, err := svc.resolveScanTargets(ctx, testScan("nuclei", "203.0.113.0/24", "app.example.com", "203.0.113.9"))
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"app.example.com", "203.0.113.9"}; !reflect.DeepEqual(got.Targets, want) {
		t.Fatalf("nuclei targets = %v, want %v", got.Targets, want)
	}
	if got.Incompatible != 1 || got.IncompatibleReason == "" {
		t.Fatalf("incompatible = %d (%q), want 1 with a reason", got.Incompatible, got.IncompatibleReason)
	}

	got, err = svc.resolveScanTargets(ctx, testScan("naabu", "203.0.113.0/24", "app.example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"203.0.113.0/24", "app.example.com"}; !reflect.DeepEqual(got.Targets, want) || got.Incompatible != 0 {
		t.Fatalf("naabu targets = %v (incompatible %d), want %v", got.Targets, got.Incompatible, want)
	}

	// Only ranges: the run is refused before anything is dispatched.
	sc := testScan("httpx", "203.0.113.0/24")
	got, err = svc.resolveScanTargets(ctx, sc)
	if err != nil {
		t.Fatal(err)
	}
	err = recordResolvedTargets(sc, got, map[string]any{})
	var de *shared.DomainError
	if !errors.As(err, &de) || de.Code != codeNoCompatibleTargets {
		t.Fatalf("err = %v, want %s", err, codeNoCompatibleTargets)
	}
}

// An inventory range (an asset-group member of type network) is refused for
// a template scanner too, whatever the registry says about its type; a
// typed name the registry cannot decide is still left to the type gate.
func TestResolveScanTargets_InventoryRangeNeverReachesTemplates(t *testing.T) {
	svc := allowAllChecks(&Service{tools: testTools,
		assetGroupRepo: &typedMembersRepo{members: []*assetgroup.ScanMember{
			member("203.0.113.0/24", asset.AssetTypeNetwork, ""),
			member("mystery", asset.AssetTypeUnclassified, ""),
		}},
		logger: logger.NewNop(),
	})
	sc := testScan("nuclei")
	sc.AssetGroupID = shared.NewID()
	got, err := svc.resolveScanTargets(context.Background(), sc)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"mystery"}; !reflect.DeepEqual(got.Targets, want) || got.Incompatible != 1 {
		t.Fatalf("targets = %v (incompatible %d), want %v", got.Targets, got.Incompatible, want)
	}
	if _, typed := got.TargetTypes["203.0.113.0/24"]; typed {
		t.Fatal("a refused range must not be typed in the run")
	}
}
