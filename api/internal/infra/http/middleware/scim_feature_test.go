package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type scimUsage struct {
	usable map[shared.ID]bool
	err    error
	asked  []shared.ID
}

func (s *scimUsage) Usable(_ context.Context, tenantID shared.ID, feature string) (bool, error) {
	s.asked = append(s.asked, tenantID)
	if feature != "scim" {
		return false, errors.New("unexpected feature " + feature)
	}
	return s.usable[tenantID], s.err
}

func runSCIMGate(t *testing.T, gate SCIMFeatureUsage, tenant *shared.ID) int {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
	if tenant != nil {
		r = r.WithContext(context.WithValue(r.Context(), scimTenantCtxKey, *tenant))
	}
	w := httptest.NewRecorder()
	SCIMFeatureGate(gate)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(w, r)
	return w.Code
}

// The SCIM API of an organization whose plan lost SCIM (grace over) is
// refused; the check is for the token's own organization; a read error
// refuses.
func TestSCIMFeatureGate(t *testing.T) {
	paid, free := shared.NewID(), shared.NewID()
	u := &scimUsage{usable: map[shared.ID]bool{paid: true}}
	if code := runSCIMGate(t, u, &paid); code != http.StatusNoContent {
		t.Fatalf("usable: %d", code)
	}
	if code := runSCIMGate(t, u, &free); code != http.StatusForbidden {
		t.Fatalf("not usable: %d", code)
	}
	if u.asked[len(u.asked)-1] != free {
		t.Fatal("the gate must check the token's own organization")
	}
	if code := runSCIMGate(t, &scimUsage{err: errors.New("db down")}, &paid); code != http.StatusServiceUnavailable {
		t.Fatalf("read error must refuse: %d", code)
	}
	if code := runSCIMGate(t, u, nil); code != http.StatusUnauthorized {
		t.Fatalf("no authenticated tenant: %d", code)
	}
	if code := runSCIMGate(t, nil, &free); code != http.StatusNoContent {
		t.Fatalf("unwired gate must pass: %d", code)
	}
}

// Deprovisioning is never gated: a user DELETE, PUT or PATCH passes (marked
// leave-only) when the feature is off or the limits cannot be read; reads,
// creates and group requests stay refused.
func TestSCIMFeatureGateLetsLeaversThrough(t *testing.T) {
	tenant := shared.NewID()
	run := func(gate SCIMFeatureUsage, method, target string) (int, bool) {
		r := httptest.NewRequestWithContext(context.WithValue(context.Background(), scimTenantCtxKey, tenant), method, target, nil)
		w := httptest.NewRecorder()
		leave := false
		SCIMFeatureGate(gate)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			leave = SCIMLeaveOnly(r.Context())
			w.WriteHeader(http.StatusNoContent)
		})).ServeHTTP(w, r)
		return w.Code, leave
	}
	off := &scimUsage{}
	broken := &scimUsage{err: errors.New("db down")}
	id := shared.NewID().String()
	for _, gate := range []SCIMFeatureUsage{off, broken} {
		for _, m := range []string{http.MethodDelete, http.MethodPut, http.MethodPatch} {
			if code, leave := run(gate, m, "/scim/v2/Users/"+id); code != http.StatusNoContent || !leave {
				t.Fatalf("%s user must pass leave-only: %d %v", m, code, leave)
			}
		}
		for _, c := range []struct{ m, p string }{
			{http.MethodPost, "/scim/v2/Users"},
			{http.MethodGet, "/scim/v2/Users/" + id},
			{http.MethodDelete, "/scim/v2/Groups/" + id},
			{http.MethodPatch, "/scim/v2/Groups/" + id},
		} {
			if code, _ := run(gate, c.m, c.p); code != http.StatusForbidden && code != http.StatusServiceUnavailable {
				t.Fatalf("%s %s must stay refused: %d", c.m, c.p, code)
			}
		}
	}
	// A usable organization is not marked leave-only.
	if _, leave := run(&scimUsage{usable: map[shared.ID]bool{tenant: true}}, http.MethodDelete, "/scim/v2/Users/"+id); leave {
		t.Fatal("usable organization must not be leave-only")
	}
}
