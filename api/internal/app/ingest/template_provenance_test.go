package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/ingestreport"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

func toolWithRelease(digest string) *ctis.Tool {
	return &ctis.Tool{Name: "nuclei", Properties: ctis.Properties{"content": []any{
		map[string]any{"name": "trivy-db", "digest": "sha256:" + strings.Repeat("0", 64)},
		map[string]any{"name": "nuclei-templates", "version": "v10.4.9", "digest": digest},
	}}}
}

func TestFindingTemplateProvenance(t *testing.T) {
	d := "sha256:" + strings.Repeat("c", 64)
	rel := "sha256:" + strings.Repeat("d", 64)
	got := findingTemplateProvenance(&ctis.Finding{Properties: ctis.Properties{"template_digest": d, "template_path": "http/x.yaml"}}, toolWithRelease(rel))
	if got.TemplateDigest != d || got.TemplatePath != "http/x.yaml" || got.TemplatesVersion != "v10.4.9" || got.TemplatesDigest != rel {
		t.Fatalf("provenance %+v", got)
	}
	if !findingTemplateProvenance(&ctis.Finding{}, toolWithRelease(rel)).Empty() {
		t.Error("a finding without a digest has provenance")
	}
	if v, dg := reportTemplateRelease(&ctis.Tool{Name: "nuclei", Properties: ctis.Properties{"content": "garbage"}}); v != "" || dg != "" {
		t.Error("malformed content read")
	}
}

// The run's template release is one value across its reports, else unknown.
func TestDecideRunCoverage_TemplatesDigest(t *testing.T) {
	rel1 := "sha256:" + strings.Repeat("1", 64)
	rel2 := "sha256:" + strings.Repeat("2", 64)
	report := func(rel string) ingestreport.CoverageReport {
		h, _ := json.Marshal(V2Header{Tool: toolWithRelease(rel), Metadata: ctis.ReportMetadata{CoverageType: "full"}})
		return ingestreport.CoverageReport{ReportID: shared.NewID().String(), State: protov2.StateCompleted, ToolName: "nuclei",
			Header: h, TouchedAssetIDs: []shared.ID{shared.NewID()}}
	}
	cov := func(rs ...ingestreport.CoverageReport) *ingestreport.CommandCoverage {
		return &ingestreport.CommandCoverage{CommandType: "scan", CommandStatus: "completed", Reports: rs}
	}
	if d := decideCoverage(cov(report(rel1), report(rel1))); !d.eligible() || d.query.TemplatesDigest != rel1 {
		t.Fatalf("agreeing reports: %+v", d)
	}
	if d := decideCoverage(cov(report(rel1), report(rel2))); d.query.TemplatesDigest != "" {
		t.Fatalf("disagreeing reports gave %q", d.query.TemplatesDigest)
	}
	if d := decideCoverage(cov(report("not-a-digest"))); d.query.TemplatesDigest != "" {
		t.Fatalf("malformed release digest kept: %q", d.query.TemplatesDigest)
	}
}

// driftRepo adds the template-drift queries to the coverage fake.
type driftRepo struct {
	*coverageFindingRepo
	drifted     map[shared.ID]bool
	runDigest   string
	notObserved []shared.ID
	err         error
}

func (r *driftRepo) TemplateDriftedFindings(_ context.Context, _ shared.ID, ids []shared.ID, runDigest string) ([]shared.ID, error) {
	r.runDigest = runDigest
	if r.err != nil {
		return nil, r.err
	}
	var out []shared.ID
	for _, id := range ids {
		if r.drifted[id] {
			out = append(out, id)
		}
	}
	return out, nil
}

func (r *driftRepo) MarkCoverageNotObserved(_ context.Context, _ shared.ID, ids []shared.ID) ([]shared.ID, error) {
	r.notObserved = append(r.notObserved, ids...)
	return ids, nil
}

// A covered run that ran other template content does not close a finding
// last seen with another release: it becomes not_observed; the others
// close as before. A failed drift lookup closes nothing.
func TestEvaluateCommandCoverage_TemplateDriftIsNotObserved(t *testing.T) {
	svc, base := coverageService(t, CoverageAutoResolveEnforce, []string{"nuclei"})
	same, drifted := shared.NewID(), shared.NewID()
	base.stale = []shared.ID{same, drifted}
	repo := &driftRepo{coverageFindingRepo: base, drifted: map[shared.ID]bool{drifted: true}}
	svc.findingRepo = repo
	out := svc.EvaluateCommandCoverage(context.Background(), shared.NewID(), shared.NewID())
	if len(base.resolved) != 1 || base.resolved[0] != same {
		t.Fatalf("resolved %v, want only the finding without drift", base.resolved)
	}
	if len(repo.notObserved) != 1 || repo.notObserved[0] != drifted || len(out.NotObserved) != 1 || len(out.TemplateDrift) != 1 {
		t.Fatalf("not_observed %v outcome %+v", repo.notObserved, out)
	}

	// Dry run: neither resolves nor marks.
	svc2, base2 := coverageService(t, CoverageAutoResolveDryRun, []string{"nuclei"})
	base2.stale = []shared.ID{drifted}
	repo2 := &driftRepo{coverageFindingRepo: base2, drifted: map[shared.ID]bool{drifted: true}}
	svc2.findingRepo = repo2
	if out := svc2.EvaluateCommandCoverage(context.Background(), shared.NewID(), shared.NewID()); len(repo2.notObserved) != 0 || len(base2.resolved) != 0 || len(out.TemplateDrift) != 1 {
		t.Fatalf("dry run changed state: %+v", out)
	}

	// Lookup error: fail closed.
	svc3, base3 := coverageService(t, CoverageAutoResolveEnforce, []string{"nuclei"})
	svc3.findingRepo = &driftRepo{coverageFindingRepo: base3, err: errors.New("db down")}
	if out := svc3.EvaluateCommandCoverage(context.Background(), shared.NewID(), shared.NewID()); len(base3.resolved) != 0 || out.Reason != "error" {
		t.Fatalf("drift lookup error: %+v resolved %v", out, base3.resolved)
	}
}
