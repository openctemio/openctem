package ingest

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/openctemio/ctis/v2"
	"github.com/openctemio/ctis/v2/importer"

	"github.com/openctemio/openctem/api/pkg/domain/exposure"
	"github.com/openctemio/openctem/api/pkg/domain/ingestreceipt"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type settingsTenantRepo struct {
	tenant.Repository
	t *tenant.Tenant
}

func (r settingsTenantRepo) GetByID(context.Context, shared.ID) (*tenant.Tenant, error) {
	return r.t, nil
}

// An organization that files info matches as findings keeps them as
// findings.
func TestInfoMatchesAsFindingsSetting(t *testing.T) {
	tn, err := tenant.NewTenant("Org", "org", "u")
	if err != nil {
		t.Fatal(err)
	}
	st := tn.TypedSettings()
	st.EASM.InfoMatchesAsFindings = true
	if err := tn.UpdateSettings(st); err != nil {
		t.Fatal(err)
	}
	report, assetMap, _ := infoReport(t)
	proj := &fakeTemplateMatches{}
	s := &Service{logger: logger.NewNop(), templateMatches: proj, tenantRepo: settingsTenantRepo{t: tn}}
	out := &Output{}
	s.routeInfoMatches(context.Background(), shared.NewID(), report, assetMap, out, Binding{}, nil, nil)
	if len(report.Findings) != 14 || len(proj.got) != 0 {
		t.Fatalf("findings %d, filed %d", len(report.Findings), len(proj.got))
	}
}

type fakeTemplateMatches struct {
	got []exposure.TemplateMatch
	err error
}

func (f *fakeTemplateMatches) ProjectTemplateMatches(_ context.Context, _ shared.ID, m []exposure.TemplateMatch) (int, error) {
	if f.err != nil {
		return 0, f.err
	}
	f.got = append(f.got, m...)
	return len(m), nil
}

type fakeStepInfo struct {
	tenant, step shared.ID
	n            int
}

func (f *fakeStepInfo) AddStepInfoObservations(_ context.Context, tenantID, stepRunID shared.ID, n int) error {
	f.tenant, f.step, f.n = tenantID, stepRunID, f.n+n
	return nil
}

// infoReport is a real nuclei v3.11.1 run (templates v10.5.1, the sensor's
// default arguments) against a local origin serving /.env and /.git/config:
// 12 info matches (2 tech-detect, 10 http-missing-security-headers), one
// medium (git-config) and one high (generic-env), on one asset.
func infoReport(t *testing.T) (*ctis.Report, map[string]shared.ID, shared.ID) {
	t.Helper()
	f, err := os.Open("testdata/nuclei_info_matches.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	res, err := importer.Parse(context.Background(), f, importer.Options{Format: importer.FormatNuclei})
	if err != nil {
		t.Fatal(err)
	}
	asset := shared.NewID()
	assetMap := map[string]shared.ID{}
	for _, a := range res.Report.Assets {
		assetMap[a.ID] = asset
	}
	return res.Report, assetMap, asset
}

func TestInfoMatchesBecomeExposuresNotFindings(t *testing.T) {
	report, assetMap, asset := infoReport(t)
	if len(report.Findings) != 14 {
		t.Fatalf("fixture findings = %d, want 14", len(report.Findings))
	}
	proj, rec := &fakeTemplateMatches{}, &fakeStepInfo{}
	s := &Service{logger: logger.NewNop(), templateMatches: proj, stepInfo: rec}
	tenant, step := shared.NewID(), shared.NewID()
	out := &Output{}
	s.routeInfoMatches(context.Background(), tenant, report, assetMap, out, Binding{Kind: BindingCommand, StepRunID: &step}, nil, nil)

	if len(report.Findings) != 2 {
		t.Fatalf("findings left = %d, want the medium and the high", len(report.Findings))
	}
	// The receipt still accounts for them (research 436).
	if out.Outcomes[ingestreceipt.OutcomeExposure] != 12 {
		t.Fatalf("exposure outcome = %d, want 12", out.Outcomes[ingestreceipt.OutcomeExposure])
	}
	for _, f := range report.Findings {
		if f.Severity == ctis.SeverityInfo {
			t.Fatalf("an info match stayed a finding: %s", f.RuleID)
		}
	}
	if len(proj.got) != 12 || out.InfoObservations != 12 {
		t.Fatalf("filed %d, counted %d, want 12", len(proj.got), out.InfoObservations)
	}
	matchers := map[string]bool{}
	for _, m := range proj.got {
		if m.AssetID != asset || m.Tool != "nuclei" || m.URL == "" || m.StepRunID == nil || *m.StepRunID != step {
			t.Fatalf("match %+v", m)
		}
		if m.RuleID == "http-missing-security-headers" {
			matchers[m.Matcher] = true
		}
	}
	if len(matchers) != 10 {
		t.Fatalf("header matchers %v, want 10 distinct", matchers)
	}
	if rec.tenant != tenant || rec.step != step || rec.n != 12 {
		t.Fatalf("step run count %+v", rec)
	}
}

// Matches the finding pipeline would refuse (asset excluded, refused over
// the outside-targets cap, outside the uploader's scope, or not resolved)
// stay findings, refused there
// with their receipt item; a scanner that does not run templates keeps its
// info findings.
func TestInfoMatchesOnlyFromAcceptedAssetsOfTemplateScanners(t *testing.T) {
	for name, mutate := range map[string]func(*ctis.Report, *Output, map[string]shared.ID){
		"excluded":     func(r *ctis.Report, o *Output, _ map[string]shared.ID) { o.ExcludedAssetRefs = refs(r) },
		"over cap":     func(r *ctis.Report, o *Output, _ map[string]shared.ID) { o.OverCapAssetRefs = refs(r) },
		"out of scope": func(r *ctis.Report, o *Output, _ map[string]shared.ID) { o.OutOfScopeAssetRefs = refs(r) },
		"unresolved":   func(r *ctis.Report, _ *Output, m map[string]shared.ID) { clear(m) },
		"other tool":   func(r *ctis.Report, _ *Output, _ map[string]shared.ID) { r.Tool.Name = "trivy" },
	} {
		t.Run(name, func(t *testing.T) {
			report, assetMap, _ := infoReport(t)
			out := &Output{}
			mutate(report, out, assetMap)
			proj := &fakeTemplateMatches{}
			s := &Service{logger: logger.NewNop(), templateMatches: proj}
			s.routeInfoMatches(context.Background(), shared.NewID(), report, assetMap, out, Binding{}, nil, nil)
			if len(report.Findings) != 14 || len(proj.got) != 0 {
				t.Fatalf("findings %d, filed %d", len(report.Findings), len(proj.got))
			}
		})
	}
}

// When the exposures cannot be stored the matches stay findings rather
// than vanish.
func TestInfoMatchesKeptWhenNotFiled(t *testing.T) {
	report, assetMap, _ := infoReport(t)
	s := &Service{logger: logger.NewNop(), templateMatches: &fakeTemplateMatches{err: errors.New("down")}}
	out := &Output{}
	s.routeInfoMatches(context.Background(), shared.NewID(), report, assetMap, out, Binding{}, nil, nil)
	if len(report.Findings) != 14 || out.InfoObservations != 0 {
		t.Fatalf("findings %d, counted %d", len(report.Findings), out.InfoObservations)
	}
}

func refs(r *ctis.Report) map[string]bool {
	m := map[string]bool{}
	for _, f := range r.Findings {
		m[f.AssetRef] = true
	}
	return m
}
