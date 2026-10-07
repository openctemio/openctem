package pipeline

import (
	"context"
	"errors"
	"testing"
	"time"

	pipelinedom "github.com/openctemio/openctem/api/pkg/domain/pipeline"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
)

type fakeEndpoints struct {
	urls  map[shared.ID][]string
	err   error
	mode  string
	since time.Time
}

func (f *fakeEndpoints) SelectEndpointURLs(_ context.Context, _ shared.ID, _ []shared.ID, mode string, since time.Time, _ int) (map[shared.ID][]string, error) {
	f.mode, f.since = mode, since
	return f.urls, f.err
}

func TestExpandEndpoints(t *testing.T) {
	a, b := shared.NewID(), shared.NewID()
	started := time.Now().Add(-time.Hour)
	run := &pipelinedom.Run{TenantID: shared.NewID(), StartedAt: &started}
	vuln, _ := stage.Lookup(stage.VulnTemplates)
	cands := candidates{gate: []hopCandidate{{key: "https://a.example.com", assetID: a}, {key: "https://b.example.com", assetID: b}}}
	f := &fakeEndpoints{urls: map[shared.ID][]string{a: {"https://a.example.com/orders/1", "https://a.example.com/login", "https://a.example.com/login"}}}
	s := &Service{endpoints: f}
	step := &pipelinedom.Step{StepKey: "vuln", Config: map[string]any{pipelinedom.StepKeyEndpointSelector: "changed"}}

	skipped := map[string]int{}
	out, err := s.expandEndpoints(context.Background(), run, vuln, step, cands, skipped)
	if err != nil {
		t.Fatal(err)
	}
	if f.mode != "changed" || !f.since.Equal(started) {
		t.Fatalf("asked mode %q since %v", f.mode, f.since)
	}
	if len(out.gate) != 2 || out.gate[0].key != "https://a.example.com/orders/1" || out.gate[0].assetID != a {
		t.Fatalf("gate = %+v", out.gate)
	}
	if skipped[pipelinedom.ReasonUnchanged] != 1 || len(out.dropped) != 1 || out.dropped[0].assetID != b {
		t.Fatalf("an origin without new endpoints must be skipped as unchanged: %v %+v", skipped, out.dropped)
	}

	// "all" (or unset) keeps the origins; a non-template stage too.
	same, _ := s.expandEndpoints(context.Background(), run, vuln, &pipelinedom.Step{}, cands, map[string]int{})
	if len(same.gate) != 2 || same.gate[0].key != "https://a.example.com" {
		t.Fatal("default must keep the origins")
	}
	crawl, _ := stage.Lookup(stage.CrawlWeb)
	same, _ = s.expandEndpoints(context.Background(), run, crawl, step, cands, map[string]int{})
	if len(same.gate) != 2 {
		t.Fatal("a crawl step is never narrowed to endpoints")
	}

	// Fail closed: unwired or a failed lookup refuses the plan.
	if _, err := (&Service{}).expandEndpoints(context.Background(), run, vuln, step, cands, map[string]int{}); err == nil {
		t.Fatal("unwired selector planned the step")
	}
	f.err = errors.New("db down")
	if _, err := s.expandEndpoints(context.Background(), run, vuln, step, cands, map[string]int{}); err == nil {
		t.Fatal("a failed lookup planned the step")
	}
}

func TestEndpointSelectorSetting(t *testing.T) {
	out, err := pipelinedom.NormalizeStepConfig("nuclei", map[string]any{pipelinedom.StepKeyEndpointSelector: "new", "severity": []any{"high"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, sent := out[pipelinedom.StepKeyEndpointSelector]; sent {
		t.Fatal("the platform-only setting reached the sensor payload")
	}
	if _, err := pipelinedom.NormalizeStepConfig("nuclei", map[string]any{pipelinedom.StepKeyEndpointSelector: "everything"}); err == nil {
		t.Fatal("an invalid selector was accepted")
	}
	if pipelinedom.EndpointSelectorOf(map[string]any{}) != pipelinedom.EndpointSelectorAll {
		t.Fatal("default")
	}
}
