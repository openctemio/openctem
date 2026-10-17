package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// trustScopeFake lists trusts and their scope links, counting the reads.
type trustScopeFake struct {
	CIAdminService
	configs   []cirun.TrustConfig
	links     map[string][]scopedom.CITrustLink
	reads     int
	lastTrust *shared.ID
	lastScope *shared.DataScope
}

func (f *trustScopeFake) ListTrustConfigs(context.Context, shared.ID) ([]cirun.TrustConfig, error) {
	return f.configs, nil
}

func (f *trustScopeFake) TrustScopes(_ context.Context, _ shared.ID, trustID *shared.ID, scope *shared.DataScope) (map[string][]scopedom.CITrustLink, error) {
	f.reads++
	f.lastTrust, f.lastScope = trustID, scope
	return f.links, nil
}

// The trust list reads every trust's scope entries in one call, with the
// caller's data scope, and attaches them to the right trust.
func TestCITrustList_ScopeEntriesOneReadWithDataScope(t *testing.T) {
	tenant := shared.NewID()
	a, b, c := shared.NewID(), shared.NewID(), shared.NewID()
	f := &trustScopeFake{
		configs: []cirun.TrustConfig{{ID: a, Name: "a"}, {ID: b, Name: "b"}, {ID: c, Name: "c"}},
		links: map[string][]scopedom.CITrustLink{
			a.String(): {{TrustConfigID: a, Pattern: "gitlab.com/acme/*"}},
			b.String(): {{TrustConfigID: b, Pattern: "gitlab.com/beta/*"}, {TrustConfigID: b, Pattern: "gitlab.com/gamma/*"}},
		},
	}
	h := NewCIAdminHandler(f, assetScope{}, logger.NewNop()) // a restricted caller
	w := httptest.NewRecorder()
	h.ListTrustConfigs(w, tenantRequest(http.MethodGet, "/api/v1/ci/trust-configs", "", tenant))
	var out CITrustConfigListResponse
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	if f.reads != 1 || f.lastTrust != nil {
		t.Fatalf("scope reads %d (trust %v), want one tenant-wide read", f.reads, f.lastTrust)
	}
	if f.lastScope == nil || !f.lastScope.Restricted() {
		t.Fatalf("the caller's data scope was not passed: %+v", f.lastScope)
	}
	got := map[string]int{}
	for _, d := range out.Data {
		got[d.ID] = len(d.ScopeEntries)
	}
	if got[a.String()] != 1 || got[b.String()] != 2 || got[c.String()] != 0 {
		t.Fatalf("entries per trust: %v", got)
	}
}
