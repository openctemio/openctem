package contentpin

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/command"
	contentpackapp "github.com/openctemio/openctem/api/internal/app/contentpack"
	scanapp "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
)

// The request a subdomain enumeration job carries (the scan service builds
// it from stage.ToolWordlists at standard depth) pins the small platform pack
// and the labels learned from the organization's own names under the root.
func TestPin_EnumerationJobGetsPackAndLearnedLabels(t *testing.T) {
	if scanapp.PayloadKeyWordlists != PayloadKeyWordlists {
		t.Fatalf("the scan service writes %q, the planner reads %q", scanapp.PayloadKeyWordlists, PayloadKeyWordlists)
	}
	for _, r := range stage.ToolWordlists("dnsx-enum") {
		if _, ok := purposeDir[r.Purpose]; !ok || !slotRE.MatchString(r.Slot) {
			t.Fatalf("dnsx-enum asks for a request the planner refuses: %+v", r)
		}
	}
	raw, err := json.Marshal(map[string]any{
		"scanner":           "dnsx-enum",
		"targets":           []string{"example.vn"},
		"context":           map[string]any{"depth": "standard"},
		PayloadKeyWordlists: stage.ToolWordlists("dnsx-enum"),
	})
	if err != nil {
		t.Fatal(err)
	}
	a, b := shared.NewID(), shared.NewID()
	names := namesByTenant{
		a.String(): {"charts-uat.example.vn", "dchart-api.example.vn", "hocviendgo5.example.vn", "www.example.vn"},
		b.String(): {"payroll-uat2.example.vn"},
	}
	p := New(newDelivery(), names, quiet())
	content, inputs, err := p.PinJobContent(context.Background(), command.PinRequest{TenantID: a, Payload: raw})
	if err != nil {
		t.Fatal(err)
	}
	if len(content) != 1 || content[0].Pack != "wordlists-s" || content[0].Slot != "labels" {
		t.Fatalf("content %+v, want the small pack in slot labels", content)
	}
	if len(inputs) != 1 {
		t.Fatalf("%d inputs, want the learned list", len(inputs))
	}
	lines := strings.Split(strings.TrimSpace(string(gunzip(t, inputs[0].Data))), "\n")
	for _, want := range []string{"charts-uat", "charts", "uat", "hocviendgo", "dchart", "charts-uat2"} {
		if !slices.Contains(lines, want) {
			t.Errorf("%q missing from the learned labels %v", want, lines)
		}
	}
	// Tenant isolation: another organization's names never reach the job.
	for _, l := range lines {
		if strings.Contains(l, "payroll") || l == "uat2" {
			t.Errorf("label %q is another organization's", l)
		}
	}
	// Without a stable platform pack the job is refused, not sent without a list.
	empty := &fakeDelivery{}
	if _, _, err := New(empty, names, quiet()).PinJobContent(context.Background(), command.PinRequest{TenantID: a, Payload: raw}); err == nil {
		t.Fatal("a job was pinned with no platform pack")
	} else {
		refusedWith(t, err, "no stable wordlists-s pack")
	}
}

// Coverage readiness: the small pack with a DNS list makes enumeration
// ready; no pack, or a pack without the purpose's lists, does not.
func TestCoverageContentReady(t *testing.T) {
	ctx := context.Background()
	reqs := stage.ToolWordlists("dnsx-enum")
	if ok, err := New(newDelivery(), nil, quiet()).CoverageContentReady(ctx, reqs); !ok || err != nil {
		t.Fatalf("with the pack: %v %v", ok, err)
	}
	if ok, err := New(&fakeDelivery{}, nil, quiet()).CoverageContentReady(ctx, reqs); ok || err != nil {
		t.Fatalf("without a pack: %v %v", ok, err)
	}
	noDNS := newDelivery()
	noDNS.index[digS] = []contentpackapp.IndexEntry{{Path: "paths/common.txt"}}
	if ok, err := New(noDNS, nil, quiet()).CoverageContentReady(ctx, reqs); ok || err != nil {
		t.Fatalf("pack without DNS lists: %v %v", ok, err)
	}
	if ok, _ := New(newDelivery(), nil, quiet()).CoverageContentReady(ctx, []stage.WordlistRequest{{Slot: "x", Purpose: "nope"}}); ok {
		t.Fatal("an unknown purpose is ready")
	}
}
