package ingest

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/assettech"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type fakeTechRepo struct {
	upserted []assettech.Technology
	shown    map[shared.ID]map[string]bool
}

func (f *fakeTechRepo) Upsert(_ context.Context, _ shared.ID, techs []assettech.Technology) error {
	f.upserted = append(f.upserted, techs...)
	return nil
}

func (f *fakeTechRepo) ListByAsset(context.Context, shared.ID, shared.ID) ([]assettech.Technology, error) {
	return nil, nil
}

func (f *fakeTechRepo) ShownKeys(_ context.Context, _ shared.ID, ids []shared.ID) (map[shared.ID]map[string]bool, error) {
	out := map[shared.ID]map[string]bool{}
	for _, id := range ids {
		out[id] = f.shown[id]
	}
	return out, nil
}

type fakeSetReconciler struct{}

func (fakeSetReconciler) ReconcileSets(context.Context, shared.ID, []asset.SetObservation) ([]asset.SetChange, error) {
	return nil, nil
}

// Every detection becomes a categorized technology; only assets the report
// may write get any; names are sanitized and capped.
func TestRecordTechnologies_CategoriesAndScope(t *testing.T) {
	repo := &fakeTechRepo{}
	s := &Service{logger: logger.NewNop()}
	s.SetTechnologyRepository(repo)

	allowed, denied := shared.NewID(), shared.NewID()
	report := &ctis.Report{
		Tool: &ctis.Tool{Name: "httpx"},
		Assets: []ctis.Asset{
			{ID: "a", Properties: ctis.Properties{"technologies": []any{"HSTS", "Vercel", "Next.js:13.4.1", "bad\x1bname"}},
				Technologies: []ctis.Technology{{Name: "Acme Edge", Categories: []string{"CDN"}, Confidence: 75}}},
			{ID: "b", Properties: ctis.Properties{"technologies": []any{"nginx:1.20.0"}}},
		},
	}
	scope := &alterScope{allowed: map[shared.ID]bool{allowed: true}}
	s.recordTechnologies(context.Background(), shared.NewID(), scope, attributeSource{name: "fallback"},
		time.Now(), report, map[string]shared.ID{"a": allowed, "b": denied})

	got := map[string]assettech.Technology{}
	for _, tc := range repo.upserted {
		if tc.AssetID != allowed {
			t.Fatalf("wrote an asset outside the report's scope: %+v", tc)
		}
		got[tc.Key] = tc
	}
	want := map[string]assettech.Category{
		"hsts": assettech.CategorySecurityHeader, "vercel": assettech.CategoryHosting,
		"next.js": assettech.CategoryFramework, "acme edge": assettech.CategoryCDN,
	}
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for k, c := range want {
		if got[k].Category != c || got[k].Source != "httpx" {
			t.Errorf("%s: %+v", k, got[k])
		}
	}
	if got["next.js"].Version != "13.4.1" || got["acme edge"].Confidence != 75 {
		t.Errorf("version/confidence lost: %+v", got)
	}
}

// With set reconciliation, a technology the asset does not show (an
// untrusted source) is not recorded.
func TestRecordTechnologies_OnlyShown(t *testing.T) {
	id := shared.NewID()
	repo := &fakeTechRepo{shown: map[shared.ID]map[string]bool{id: {"nginx": true}}}
	s := &Service{logger: logger.NewNop(), sets: fakeSetReconciler{}}
	s.SetTechnologyRepository(repo)
	report := &ctis.Report{Assets: []ctis.Asset{
		{ID: "a", Properties: ctis.Properties{"technologies": []any{"nginx:1.25.0", "PHP:8.1"}}},
	}}
	s.recordTechnologies(context.Background(), shared.NewID(), &alterScope{all: true}, attributeSource{},
		time.Now(), report, map[string]shared.ID{"a": id})
	if len(repo.upserted) != 1 || repo.upserted[0].Key != "nginx" {
		t.Fatalf("got %+v", repo.upserted)
	}
}

func TestRecordTechnologies_Caps(t *testing.T) {
	repo := &fakeTechRepo{}
	s := &Service{logger: logger.NewNop()}
	s.SetTechnologyRepository(repo)
	techs := make([]any, 0, 300)
	for i := 0; i < 300; i++ {
		techs = append(techs, "product"+strings.Repeat("x", i%7)+string(rune('a'+i%26))+string(rune('a'+i/26)))
	}
	report := &ctis.Report{}
	assetMap := map[string]shared.ID{}
	for i := 0; i < 80; i++ {
		ref := "asset" + string(rune('a'+i%26)) + string(rune('a'+i/26))
		report.Assets = append(report.Assets, ctis.Asset{ID: ref, Properties: ctis.Properties{"technologies": techs}})
		assetMap[ref] = shared.NewID()
	}
	s.recordTechnologies(context.Background(), shared.NewID(), &alterScope{all: true}, attributeSource{},
		time.Now(), report, assetMap)
	per := map[shared.ID]int{}
	for _, tc := range repo.upserted {
		per[tc.AssetID]++
	}
	for _, n := range per {
		if n > assettech.MaxPerAsset {
			t.Fatalf("per-asset cap: %d", n)
		}
	}
	if len(repo.upserted) > assettech.MaxPerReport {
		t.Fatalf("per-report cap: %d", len(repo.upserted))
	}
}

// The typed technologies join the reconciled set as "Name:version".
func TestTechnologiesOf_Typed(t *testing.T) {
	a := &ctis.Asset{Technologies: []ctis.Technology{{Name: "nginx", Version: "1.25.3"}, {Name: "HSTS"}, {Name: " "}}}
	got, ok := technologiesOf(a)
	if !ok || len(got) != 2 || got[0] != "nginx:1.25.3" || got[1] != "HSTS" {
		t.Fatalf("got %v %v", got, ok)
	}
}
