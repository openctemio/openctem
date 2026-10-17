package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	cirunapp "github.com/openctemio/openctem/api/internal/app/cirun"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// policyFake is a CI admin service holding gate policies.
type policyFake struct {
	CIAdminService
	policies map[shared.ID]*cirun.GatePolicy
	changed  []string
	err      error
}

func (f *policyFake) ListGatePolicies(context.Context, shared.ID) ([]cirun.GatePolicy, error) {
	out := []cirun.GatePolicy{}
	for _, p := range f.policies {
		out = append(out, *p)
	}
	return out, nil
}

func (f *policyFake) GetGatePolicy(_ context.Context, _, id shared.ID) (*cirun.GatePolicy, error) {
	if p, ok := f.policies[id]; ok {
		return p, nil
	}
	return nil, shared.ErrNotFound
}

func (f *policyFake) CreateGatePolicy(context.Context, shared.ID, cirunapp.GatePolicyInput, cirunapp.Actor) (*cirun.GatePolicy, error) {
	f.changed = append(f.changed, "create")
	if f.err != nil {
		return nil, f.err
	}
	return &cirun.GatePolicy{ID: shared.NewID()}, nil
}

func (f *policyFake) UpdateGatePolicy(_ context.Context, _, id shared.ID, _ cirunapp.GatePolicyInput, _ cirunapp.Actor) (*cirun.GatePolicy, error) {
	f.changed = append(f.changed, "update")
	if f.err != nil {
		return nil, f.err
	}
	return f.policies[id], nil
}

func (f *policyFake) DeleteGatePolicy(context.Context, shared.ID, shared.ID, string, cirunapp.Actor) error {
	f.changed = append(f.changed, "delete")
	return f.err
}

// assetScope sees only the listed assets; restricted unless all is set.
type assetScope struct {
	visible map[shared.ID]bool
	all     bool
}

func (s assetScope) Resolve(context.Context, shared.ID) (*shared.DataScope, error) {
	return &shared.DataScope{Unrestricted: s.all}, nil
}

func (s assetScope) AssertAsset(_ context.Context, _, id shared.ID) error {
	if s.all || s.visible[id] {
		return nil
	}
	return shared.ErrNotFound
}

func TestCIGatePolicies_DataScope(t *testing.T) {
	tenant := shared.NewID()
	inScope, outScope, unit := shared.NewID(), shared.NewID(), shared.NewID()
	org := &cirun.GatePolicy{ID: shared.NewID(), ScopeType: cirun.ScopeTenant}
	bu := &cirun.GatePolicy{ID: shared.NewID(), ScopeType: cirun.ScopeBusinessUnit, ScopeID: &unit}
	mine := &cirun.GatePolicy{ID: shared.NewID(), ScopeType: cirun.ScopeRepository, ScopeID: &inScope}
	theirs := &cirun.GatePolicy{ID: shared.NewID(), ScopeType: cirun.ScopeRepository, ScopeID: &outScope}
	newFake := func() *policyFake {
		return &policyFake{policies: map[shared.ID]*cirun.GatePolicy{org.ID: org, bu.ID: bu, mine.ID: mine, theirs.ID: theirs}}
	}
	restricted := assetScope{visible: map[shared.ID]bool{inScope: true}}

	t.Run("list hides repository policies outside the scope", func(t *testing.T) {
		h := NewCIAdminHandler(newFake(), restricted, logger.NewNop())
		w := httptest.NewRecorder()
		h.ListGatePolicies(w, tenantRequest(http.MethodGet, "/api/v1/ci/gate-policies", "", tenant))
		var out CIGatePolicyListResponse
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || w.Code != http.StatusOK {
			t.Fatalf("%d %s", w.Code, w.Body.String())
		}
		seen := map[string]bool{}
		for _, p := range out.Data {
			seen[p.ID] = true
		}
		if !seen[org.ID.String()] || !seen[bu.ID.String()] || !seen[mine.ID.String()] || seen[theirs.ID.String()] {
			t.Fatalf("listed %v", seen)
		}
	})

	call := func(h *CIAdminHandler, method, id, body string) int {
		r := tenantRequest(method, "/api/v1/ci/gate-policies", body, tenant)
		if id != "" {
			r.SetPathValue("id", id)
		}
		w := httptest.NewRecorder()
		switch method {
		case http.MethodPost:
			h.CreateGatePolicy(w, r)
		case http.MethodPatch:
			h.UpdateGatePolicy(w, r)
		case http.MethodDelete:
			h.DeleteGatePolicy(w, r)
		}
		return w.Code
	}
	cases := []struct {
		name   string
		scope  DataScopeEnforcer
		method string
		id     string
		body   string
		want   int
	}{
		{"create for a repository outside the scope", restricted, http.MethodPost, "",
			`{"scope_type":"repository","scope_id":"` + outScope.String() + `","mode":"warn"}`, http.StatusNotFound},
		{"create for a repository in the scope", restricted, http.MethodPost, "",
			`{"scope_type":"repository","scope_id":"` + inScope.String() + `"}`, http.StatusCreated},
		{"create an organization policy with a restricted scope", restricted, http.MethodPost, "",
			`{"scope_type":"tenant","mode":"warn"}`, http.StatusForbidden},
		{"create a business unit policy with a restricted scope", restricted, http.MethodPost, "",
			`{"scope_type":"business_unit","scope_id":"` + unit.String() + `"}`, http.StatusForbidden},
		{"create an organization policy with full data", assetScope{all: true}, http.MethodPost, "",
			`{"scope_type":"tenant"}`, http.StatusCreated},
		{"update a policy outside the scope", restricted, http.MethodPatch, theirs.ID.String(), `{"mode":"warn"}`, http.StatusNotFound},
		{"delete a policy outside the scope", restricted, http.MethodDelete, theirs.ID.String(), ``, http.StatusNotFound},
		{"update the organization policy with a restricted scope", restricted, http.MethodPatch, org.ID.String(), `{"mode":"warn"}`, http.StatusForbidden},
		{"delete the business unit policy with a restricted scope", restricted, http.MethodDelete, bu.ID.String(), ``, http.StatusForbidden},
		{"update a policy in the scope", restricted, http.MethodPatch, mine.ID.String(), `{"fail_on_severity":"medium"}`, http.StatusOK},
		{"delete a policy in the scope", restricted, http.MethodDelete, mine.ID.String(), ``, http.StatusNoContent},
		{"another tenant's policy id", restricted, http.MethodPatch, shared.NewID().String(), `{"mode":"warn"}`, http.StatusNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			h := NewCIAdminHandler(f, tc.scope, logger.NewNop())
			if got := call(h, tc.method, tc.id, tc.body); got != tc.want {
				t.Fatalf("status %d, want %d", got, tc.want)
			}
			if refused := tc.want == http.StatusNotFound || tc.want == http.StatusForbidden; refused && len(f.changed) > 0 {
				t.Fatalf("the service was called: %v", f.changed)
			}
		})
	}
}

// A change that loosens the gate without a recent sign-in answers the
// step-up error the console handles, never a 500.
func TestCIGatePolicies_LooseningAsksForStepUp(t *testing.T) {
	tenant := shared.NewID()
	for name, svcErr := range map[string]error{
		"step-up required":    middleware.ErrStepUpRequired,
		"step-up not wired":   cirunapp.ErrStepUpUnavailable,
		"step-up unavailable": middleware.ErrStepUpUnavailable,
	} {
		t.Run(name, func(t *testing.T) {
			h := NewCIAdminHandler(&policyFake{err: svcErr}, assetScope{all: true}, logger.NewNop())
			w := httptest.NewRecorder()
			h.CreateGatePolicy(w, tenantRequest(http.MethodPost, "/api/v1/ci/gate-policies", `{"scope_type":"tenant","mode":"warn"}`, tenant))
			if w.Code != http.StatusForbidden {
				t.Fatalf("status %d: %s", w.Code, w.Body.String())
			}
			var body map[string]any
			_ = json.Unmarshal(w.Body.Bytes(), &body)
			if code, _ := body["code"].(string); code != string(middleware.CodeStepUpRequired) && code != string(middleware.CodeStepUpUnavailable) {
				t.Fatalf("body %s", w.Body.String())
			}
		})
	}
}
