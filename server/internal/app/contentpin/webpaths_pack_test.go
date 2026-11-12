package contentpin

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/openctemio/openctem/server/internal/app/command"
	covdom "github.com/openctemio/openctem/server/pkg/domain/coverage"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/stage"
)

type fakeOrigins struct {
	facts map[string]covdom.PathOriginFacts
}

func (f fakeOrigins) PathOriginFacts(_ context.Context, _ shared.ID, origins []string) (map[string]covdom.PathOriginFacts, error) {
	out := map[string]covdom.PathOriginFacts{}
	for _, o := range origins {
		if v, ok := f.facts[o]; ok {
			out[o] = v
		}
	}
	return out, nil
}

// SECURITY: a wordlist pack is the platform's list, not the organization's
// inventory, so a path discovery job that asks for one runs only on origins
// an active scope entry names; without the check wired, or for an origin
// without an entry or no origin of the organization, the job is refused. A
// job that asks only for the derived list is not subject to it here (the
// dispatch gate decides it).
func TestPin_WebPathPackNeedsAnOriginScopeEntry(t *testing.T) {
	ctx := context.Background()
	reqs := stage.ToolWordlists("webguess")
	job := func(depth string, lists ...string) command.PinRequest {
		raw, err := json.Marshal(map[string]any{
			"scanner": "webguess", "capability": "enumerate.web_paths@1",
			"targets":           []string{"https://app.example.com"},
			"context":           map[string]any{"depth": depth},
			"scanner_config":    map[string]any{"lists": lists},
			PayloadKeyWordlists: reqs,
		})
		if err != nil {
			t.Fatal(err)
		}
		return command.PinRequest{TenantID: shared.NewID(), Payload: raw}
	}
	named := fakeOrigins{facts: map[string]covdom.PathOriginFacts{"https://app.example.com": {ScopeEntry: true}}}
	unnamed := fakeOrigins{facts: map[string]covdom.PathOriginFacts{"https://app.example.com": {ScopeEntry: false}}}

	p := New(newDelivery(), nil, quiet())
	if _, _, err := p.PinJobContent(ctx, job("standard", "common")); err == nil {
		t.Fatal("a pack was pinned with no origin scope check wired")
	}
	p.SetPackOrigins(unnamed)
	if _, _, err := p.PinJobContent(ctx, job("standard", "common")); err == nil {
		t.Fatal("a pack was pinned on an origin no scope entry names")
	} else {
		refusedWith(t, err, "active scope entry")
	}
	p.SetPackOrigins(fakeOrigins{})
	if _, _, err := p.PinJobContent(ctx, job("standard", "common")); err == nil {
		t.Fatal("a pack was pinned on an origin the organization does not have")
	}
	p.SetPackOrigins(named)
	content, _, err := p.PinJobContent(ctx, job("standard", "common"))
	if err != nil || len(content) != 1 || content[0].Pack != "wordlists-s" {
		t.Fatalf("standard depth on a named origin: %+v %v, want the small pack", content, err)
	}
	// The medium class needs the Deep depth; a standard run never gets it.
	content, _, err = p.PinJobContent(ctx, job("deep", "common"))
	if err != nil || len(content) != 1 || content[0].Pack != "wordlists-m" {
		t.Fatalf("deep depth: %+v %v, want the medium pack", content, err)
	}
	if _, _, err := p.PinJobContent(ctx, job("passive", "common")); err == nil {
		t.Fatal("a passive run got a pack")
	}
}
