package scan

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// POST /scans asset_ids: the server names each asset; an id the creator may
// not scan (outside their act scope, another tenant's, unknown) refuses the
// request with one answer that does not say which or why.
func TestResolveAssetTargets(t *testing.T) {
	tenant, other, creator := shared.NewID(), shared.NewID(), shared.NewID()
	mine, mine2, hidden, foreign := shared.NewID(), shared.NewID(), shared.NewID(), shared.NewID()
	gate := &assetGate{tenant: tenant, names: map[shared.ID][]string{
		mine:   {"app.example.com", "10.0.0.5"},
		mine2:  {"APP.example.com"}, // same name, other spelling
		hidden: {"secret.example.com"},
	}}
	act := &stubActScope{assets: map[shared.ID]bool{hidden: true}}
	svc := &Service{actScope: act, attributionGate: gate, logger: logger.NewNop()}
	ctx := context.Background()

	got, err := svc.resolveAssetTargets(ctx, tenant, &creator, []string{mine.String(), mine2.String(), mine.String()})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, []string{"app.example.com"}) {
		t.Fatalf("targets = %v, want the asset name once", got)
	}
	if in := act.got[len(act.got)-1]; in.FallbackUser == nil || *in.FallbackUser != creator {
		t.Fatalf("act scope checked for %v, want the creator", in.FallbackUser)
	}

	for name, ids := range map[string][]string{
		"outside the creator's scope": {mine.String(), hidden.String()},
		"another tenant's":            {foreign.String()},
		"unknown":                     {shared.NewID().String()},
	} {
		_, err := svc.resolveAssetTargets(ctx, tenant, &creator, ids)
		if !errors.Is(err, errScanAssetsUnavailable) {
			t.Fatalf("%s: err = %v, want the one unavailable answer", name, err)
		}
		if strings.Contains(err.Error(), "secret") {
			t.Fatalf("%s: the error names a hidden asset: %v", name, err)
		}
	}
	// The other tenant's view of its own asset id is the same answer.
	if _, err := svc.resolveAssetTargets(ctx, other, &creator, []string{mine.String()}); !errors.Is(err, errScanAssetsUnavailable) {
		t.Fatalf("cross-tenant: err = %v", err)
	}

	if _, err := svc.resolveAssetTargets(ctx, tenant, &creator, []string{"not-a-uuid"}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("bad id: err = %v", err)
	}
	act.err = errors.New("db down")
	if _, err := svc.resolveAssetTargets(ctx, tenant, &creator, []string{mine.String()}); err == nil {
		t.Fatal("an act-scope failure must refuse (fail closed)")
	}
}

func TestMergeDirectTargets(t *testing.T) {
	got, err := mergeDirectTargets([]string{"a.example.com", "b.example.com"}, []string{"B.example.com", "c.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, []string{"a.example.com", "b.example.com", "c.example.com"}) {
		t.Fatalf("merged = %v", got)
	}
	typed := make([]string, 0, MaxDirectTargets)
	for i := range MaxDirectTargets {
		typed = append(typed, fmt.Sprintf("h%d.example.com", i))
	}
	if _, err := mergeDirectTargets(typed, []string{"extra.example.com"}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("over the limit: err = %v", err)
	}
	if got, _ := mergeDirectTargets(typed, nil); len(got) != MaxDirectTargets {
		t.Fatal("no assets: the typed targets unchanged")
	}
}
