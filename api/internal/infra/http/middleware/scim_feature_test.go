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
