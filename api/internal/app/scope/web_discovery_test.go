package scope

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/openctemio/contract/webpath"

	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// SECURITY: the web scope of a path discovery job is strict: GET and HEAD
// only, the per-host request cap, and every exclusion on the target hosts
// denied unless its testing mode is allowed (read_only included).
func TestBuildDiscoveryWebScope_Strict(t *testing.T) {
	tenantID := shared.NewID()
	future := time.Now().Add(time.Hour)
	svc := newFilterService(&fakeExclusionRepo{active: []*scopedom.Exclusion{
		pathExclusion(t, tenantID, "*", "/admin", nil, scopedom.TestingReadOnly, nil),
		pathExclusion(t, tenantID, "*.example.com", "/orders", []string{"POST"}, scopedom.TestingBlocked, nil),
		pathExclusion(t, tenantID, "*", "/staging", nil, scopedom.TestingAllowed, &future),
		pathExclusion(t, tenantID, "other.example.net", "/x", nil, scopedom.TestingBlocked, nil),
	}})
	ws, err := svc.BuildDiscoveryWebScope(context.Background(), tenantID, []string{"https://app.example.com"}, 300)
	if err != nil || ws == nil {
		t.Fatalf("scope %+v, %v", ws, err)
	}
	if !slices.Equal(ws.Methods, []string{"GET", "HEAD"}) || ws.MaxRequestsPerHost != 300 {
		t.Fatalf("methods %v cap %d", ws.Methods, ws.MaxRequestsPerHost)
	}
	if !slices.Equal(ws.DenyPaths, []string{"/admin", "/orders"}) {
		t.Fatalf("deny %v, want the read_only and the method-scoped rule, not the allowed or other-host one", ws.DenyPaths)
	}
	raw, _ := json.Marshal(ws)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	if m["max_requests_per_host"] != float64(300) {
		t.Fatalf("wire form %s", raw)
	}
	// Every spelling of the excluded path is denied with the sensor's reading.
	for _, p := range []string{"/Admin", "/%61dmin", "/x/../admin", "/admin;x", "/admin/users"} {
		clean, err := webpath.CleanPath(p)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if _, denied := webpath.Denied(clean, ws.DenyPaths); !denied {
			t.Errorf("%s is not denied by %v", p, ws.DenyPaths)
		}
	}
	// Bounds of the cap; never nil without exclusions.
	svc = newFilterService(&fakeExclusionRepo{})
	ws, err = svc.BuildDiscoveryWebScope(context.Background(), tenantID, []string{"https://app.example.com"}, 10)
	if err != nil || ws == nil || ws.MaxRequestsPerHost != MinDiscoveryRequestsPerHost || len(ws.DenyPaths) != 0 {
		t.Fatalf("no exclusions: %+v, %v", ws, err)
	}
	svc = newFilterService(&fakeExclusionRepo{err: errors.New("db down")})
	if _, err := svc.BuildDiscoveryWebScope(context.Background(), tenantID, []string{"https://app.example.com"}, 300); err == nil {
		t.Fatal("a failed lookup built a discovery scope")
	}
}

// SECURITY: a path discovery job always gets the strict scope, with the cap
// its config names, even when nothing else would attach one; a scope the
// caller wrote is replaced.
func TestWebJobGuard_DiscoveryJobStrict(t *testing.T) {
	tenantID := shared.NewID()
	svc := newFilterService(&fakeExclusionRepo{active: []*scopedom.Exclusion{
		pathExclusion(t, tenantID, "*", "/admin", nil, scopedom.TestingReadOnly, nil),
	}})
	g := NewWebJobGuard(svc, nil)
	cmd := newCmd(t, commanddom.CommandTypeScan, map[string]any{
		"scanner": "webguess", "capability": "enumerate.web_paths@1", "targets": []string{"https://app.example.com"},
		"scanner_config": map[string]any{"max_requests": 250},
		"web_scope":      map[string]any{"methods": []string{"POST"}},
	})
	cmd.TenantID = tenantID
	if err := g.GuardCreate(context.Background(), cmd); err != nil {
		t.Fatal(err)
	}
	ws, _ := payloadOf(t, cmd)[commanddom.PayloadKeyWebScope].(map[string]any)
	if ws == nil || ws["max_requests_per_host"] != float64(250) || len(ws["methods"].([]any)) != 2 {
		t.Fatalf("web scope %v", ws)
	}
	if got := denyPaths(payloadOf(t, cmd)); !slices.Equal(got, []string{"/admin"}) {
		t.Fatalf("deny %v", got)
	}
	// No cap in the config: the default.
	cmd = newCmd(t, commanddom.CommandTypeScan, map[string]any{
		"scanner": "webguess", "targets": []string{"https://app.example.com"}})
	cmd.TenantID = tenantID
	if err := g.GuardCreate(context.Background(), cmd); err != nil {
		t.Fatal(err)
	}
	ws, _ = payloadOf(t, cmd)[commanddom.PayloadKeyWebScope].(map[string]any)
	if ws == nil || ws["max_requests_per_host"] != float64(DefaultDiscoveryRequestsPerHost) {
		t.Fatalf("default cap: %v", ws)
	}
}
