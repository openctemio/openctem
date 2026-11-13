package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	assetapp "github.com/openctemio/openctem/server/internal/app/asset"
	"github.com/openctemio/openctem/server/internal/infra/http/middleware"
	assetdom "github.com/openctemio/openctem/server/pkg/domain/asset"
	covdom "github.com/openctemio/openctem/server/pkg/domain/coverage"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/filterspec"
	"github.com/openctemio/openctem/server/pkg/logger"
	"github.com/openctemio/openctem/server/pkg/pagination"
)

// fakeAssetList records the asset list input and answers the given assets.
type fakeAssetList struct {
	got    []assetapp.ListAssetsInput
	where  []assetapp.ListQuery
	caller []assetapp.ListCaller
	assets []*assetdom.Asset
}

func (f *fakeAssetList) ListAssetsWhere(_ context.Context, c assetapp.ListCaller, q assetapp.ListQuery) (assetdom.WhereResult, error) {
	f.where = append(f.where, q)
	f.caller = append(f.caller, c)
	return assetdom.WhereResult{Data: f.assets, Total: int64(len(f.assets)), Page: 1, PerPage: 25}, nil
}

func (f *fakeAssetList) ListAssets(_ context.Context, in assetapp.ListAssetsInput) (pagination.Result[*assetdom.Asset], error) {
	f.got = append(f.got, in)
	return pagination.NewResult(f.assets, int64(len(f.assets)), pagination.Pagination{Page: 1, PerPage: 25}), nil
}
func (f *fakeAssetList) GetAsset(context.Context, string, string) (*assetdom.Asset, error) {
	return nil, shared.ErrNotFound
}

// fakeAssetCtx answers the asset page reads; an asset not in inScope is
// not found, like the service for an asset outside the caller's scope.
type fakeAssetCtx struct {
	inScope  map[string]*assetdom.Asset
	coverErr error
	tenants  []string
}

func (f *fakeAssetCtx) GetAssetInCallerScope(_ context.Context, tenantID, id string) (*assetdom.Asset, error) {
	f.tenants = append(f.tenants, tenantID)
	if a, ok := f.inScope[id]; ok {
		return a, nil
	}
	return nil, shared.ErrNotFound
}
func (f *fakeAssetCtx) GetCoverage(_ context.Context, _, id string) (*covdom.AssetView, error) {
	if f.coverErr != nil {
		return nil, f.coverErr
	}
	return &covdom.AssetView{AssetID: id}, nil
}
func (f *fakeAssetCtx) ListAssetChanges(context.Context, string, string, assetdom.ChangeQuery) ([]assetdom.ChangeEvent, bool, error) {
	return nil, false, nil
}
func (f *fakeAssetCtx) GetResolvedPorts(context.Context, string, string) (*assetdom.ResolvedPorts, error) {
	return &assetdom.ResolvedPorts{}, nil
}
func (f *fakeAssetCtx) GetLineage(context.Context, string, string) (*assetdom.Lineage, error) {
	return &assetdom.Lineage{}, nil
}

func newAsset(t *testing.T, name string) *assetdom.Asset {
	t.Helper()
	a, err := assetdom.NewAsset(name, assetdom.AssetTypeSubdomain, assetdom.CriticalityHigh)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// leafText renders a spec's leaves as field:op:values, sorted, for checks.
func leafText(spec *filterspec.Spec) string {
	var out []string
	for _, l := range spec.Leaves() {
		vals := make([]string, 0, len(l.Values))
		for _, v := range l.Values {
			vals = append(vals, fmt.Sprint(v))
		}
		out = append(out, l.Field+":"+string(l.Op)+":"+strings.Join(vals, ","))
	}
	sort.Strings(out)
	return strings.Join(out, " ")
}

func TestMCP_SearchAssets(t *testing.T) {
	for _, c := range []struct {
		args, leaves, q string
	}{
		{`{"query":"10.0.0.5"}`, "ip:in:10.0.0.5", ""},
		{`{"query":"10.0.0.0/24"}`, "ip:in:10.0.0.0/24", ""},
		{`{"query":"api.example.com"}`, "", "api.example.com"},
		{`{"query":"tên miền 漢字"}`, "", "tên miền 漢字"},
		{`{"type":"Service, ip_address","exposure":"public","internet_facing":true,"page":2,"limit":10}`,
			"exposure:in:public internet_facing:eq:true type:in:service,ip_address", ""},
		// The filter param: the search box syntax, ANDed with the params.
		{`{"type":"subdomain","filter":"criticality:high,critical -tag:lab"}`,
			"criticality:in:high,critical tag:not_in:lab type:in:subdomain", ""},
	} {
		al := &fakeAssetList{}
		h := NewMCPHandler(&fakeFindingReader{}, nil, nil, nil, nil, al, nil, logger.NewNop())
		if _, refused := toolPayload(t, h, "search_assets", c.args); refused != "" {
			t.Fatalf("%s: refused %s", c.args, refused)
		}
		q, caller := al.where[0], al.caller[0]
		if caller.IsAdmin || caller.UserID == "" || caller.TenantID == "" {
			t.Errorf("%s: caller %+v", c.args, caller)
		}
		if len(q.Spec.Sort) != 1 || q.Spec.Sort[0].Field != "risk_score" || !q.Spec.Sort[0].Desc {
			t.Errorf("%s: sort %+v", c.args, q.Spec.Sort)
		}
		if got := leafText(q.Spec); got != c.leaves || q.Spec.Q != c.q {
			t.Errorf("%s: leaves %q q %q", c.args, got, q.Spec.Q)
		}
	}
	// A CVE no open finding in scope names: no asset, no asset read.
	al := &fakeAssetList{}
	h := NewMCPHandler(&fakeFindingReader{}, nil, nil, nil, nil, al, nil, logger.NewNop())
	out, refused := toolPayload(t, h, "search_assets", `{"cve":"CVE-2010-0738"}`)
	if refused != "" || out["total"] != float64(0) {
		t.Fatalf("cve search: %v %s", out, refused)
	}
	if len(al.where) != 0 {
		t.Errorf("asset list read for a CVE with no finding: %+v", al.where)
	}
	if _, refused := toolPayload(t, h, "search_assets", `{"owner_id":"x"}`); refused == "" {
		t.Error("a bad owner_id must be refused")
	}
	// A filter naming a field that does not exist, or one the caller may
	// not read, is refused with the same message, without the values.
	for _, f := range []string{`nosuchfield=zzsecretzz`, `tenant_id=zzsecretzz`, `deleted=true`} {
		_, refused := toolPayload(t, h, "search_assets", `{"filter":"`+f+`"}`)
		if refused == "" || strings.Contains(refused, "zzsecretzz") {
			t.Errorf("filter %q: refused %q", f, refused)
		}
	}
}

func TestMCP_GetAsset(t *testing.T) {
	a := newAsset(t, "app.example.com")
	id := a.ID().String()
	newH := func(ctx *fakeAssetCtx, list *fakeAssetList) *MCPHandler {
		h := NewMCPHandler(&fakeFindingReader{}, nil, nil, nil, nil, list, nil, logger.NewNop())
		h.SetAssetContext(ctx, "https://console.example.test/")
		return h
	}

	// Out of the caller's scope (or another tenant's): not found, nothing else.
	_, refused := toolPayload(t, newH(&fakeAssetCtx{}, &fakeAssetList{}), "get_asset", `{"asset_id":"`+shared.NewID().String()+`"}`)
	if !strings.Contains(refused, "not_found") {
		t.Fatalf("out of scope: %q", refused)
	}

	// The asset page's sections; one the caller may not read says so.
	fc := &fakeAssetCtx{inScope: map[string]*assetdom.Asset{id: a}, coverErr: shared.ErrForbidden}
	out, refused := toolPayload(t, newH(fc, &fakeAssetList{}), "get_asset", `{"asset_id":"`+id+`"}`)
	if refused != "" {
		t.Fatal(refused)
	}
	data := out["untrusted_data"].(map[string]any)
	for _, s := range assetSections {
		if _, ok := data[s]; !ok {
			t.Errorf("section %s missing", s)
		}
	}
	if cov := data["coverage"].(map[string]any); cov["error"] != "forbidden" {
		t.Errorf("coverage section %v: want the error code only", cov)
	}
	// The overview is the REST asset response for the same asset.
	wantRaw, _ := json.Marshal(toAssetResponse(a))
	var want map[string]any
	_ = json.Unmarshal(wantRaw, &want)
	if !reflect.DeepEqual(want, data["overview"]) {
		t.Errorf("overview differs from GET /assets/{id}:\n%v\n%v", data["overview"], want)
	}
	if out["console_url"] != "https://console.example.test/assets/"+id+"?org=018f5a1e-0000-7000-8000-000000000001" {
		t.Errorf("console_url %v", out["console_url"])
	}
	if fc.tenants[0] != "018f5a1e-0000-7000-8000-000000000001" {
		t.Errorf("tenant %v: must be the credential's", fc.tenants)
	}

	// Fewer sections on request; an unknown one is refused.
	out, _ = toolPayload(t, newH(fc, &fakeAssetList{}), "get_asset", `{"asset_id":"`+id+`","sections":["overview"]}`)
	if d := out["untrusted_data"].(map[string]any); len(d) != 1 {
		t.Errorf("sections: %v", d)
	}
	if _, refused := toolPayload(t, newH(fc, &fakeAssetList{}), "get_asset", `{"asset_id":"`+id+`","sections":["secrets"]}`); refused == "" {
		t.Error("an unknown section must be refused")
	}

	// By name: one exact match reads it; several return candidates.
	out, refused = toolPayload(t, newH(fc, &fakeAssetList{assets: []*assetdom.Asset{a}}), "get_asset", `{"name":"APP.example.com"}`)
	if refused != "" || out["asset_id"] != id {
		t.Errorf("by name: %v %s", out["asset_id"], refused)
	}
	twin := newAsset(t, "app.example.com")
	out, _ = toolPayload(t, newH(fc, &fakeAssetList{assets: []*assetdom.Asset{a, twin}}), "get_asset", `{"name":"app.example.com"}`)
	if c, _ := out["untrusted_data"].(map[string]any)["candidates"].([]any); len(c) != 2 {
		t.Errorf("candidates: %v", out)
	}
	if _, refused := toolPayload(t, newH(fc, &fakeAssetList{}), "get_asset", `{"name":"nope.example.com"}`); !strings.Contains(refused, "not_found") {
		t.Errorf("unknown name: %q", refused)
	}
	_ = middleware.AuthProviderAPIKey
}
