package stage

import (
	"slices"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
)

// check.takeover is routed to nuclei with only its takeover templates: a
// capability step resolves it, a step that pins nuclei alone still runs
// vulnerability templates, the job runs as a nuclei job every sensor
// version accepts, and the step's own tags cannot widen the template set.
func TestCheckTakeover_RoutedToNucleiTakeoverTemplates(t *testing.T) {
	if IsPlanned(CheckTakeover) {
		t.Fatal("check.takeover is still planned")
	}
	st, ok := Lookup(CheckTakeover)
	if !ok || !st.Available() || st.Tier != TierActive || !st.Findings || len(st.Outputs) != 0 {
		t.Fatalf("stage: %+v", st)
	}
	if !st.Accepts(asset.TypeRef{Type: asset.AssetTypeSubdomain}) || !st.Accepts(asset.TypeRef{Type: asset.AssetTypeDomain}) ||
		st.Accepts(asset.TypeRef{Type: asset.AssetTypeIPAddress}) {
		t.Fatal("takeover check takes DNS names only")
	}
	if got, err := ForCapabilities([]string{"check.takeover"}); err != nil || got.Key != CheckTakeover || got.Tools()[0] != "nuclei" {
		t.Fatalf("capability step: %+v %v", got, err)
	}
	if got, ok := ForStep("nuclei", nil); !ok || got.Key != VulnTemplates {
		t.Fatalf("pinned nuclei without a capability: %+v", got)
	}
	if got, ok := ForStep("nuclei", []string{"check.takeover"}); !ok || got.Key != CheckTakeover {
		t.Fatalf("pinned nuclei naming the capability: %+v", got)
	}
	if TakesCapabilityJobs(st, "nuclei") {
		t.Fatal("a takeover job must not name a capability the sensor's nuclei does not declare")
	}
	vt, _ := Lookup(VulnTemplates)
	if !TakesCapabilityJobs(vt, "nuclei") {
		t.Fatal("vulnerability templates keep their capability jobs")
	}

	step := map[string]any{"tags": []any{"cve", "default-login"}, "severity": []any{"high"}}
	got := st.WithStageToolConfig("NUCLEI", step)
	if tags, _ := got["tags"].([]string); !slices.Equal(tags, []string{"takeover"}) || got["severity"] == nil {
		t.Fatalf("forced config: %v", got)
	}
	if tags, _ := step["tags"].([]any); len(tags) != 2 {
		t.Fatal("the step's config was changed in place")
	}
	got["tags"].([]string)[0] = "x"
	if again := st.WithStageToolConfig("nuclei", nil); again["tags"].([]string)[0] != "takeover" {
		t.Fatal("the fixed config is shared with callers")
	}
	if c := vt.WithStageToolConfig("nuclei", step); c["tags"].([]any)[0] != "cve" {
		t.Fatal("vulnerability templates keep the step's tags")
	}
}
