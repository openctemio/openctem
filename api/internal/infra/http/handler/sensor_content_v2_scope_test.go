package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	contentpackapp "github.com/openctemio/openctem/api/internal/app/contentpack"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// scopeRecorder is a ContentDelivery that records the scope each call asked
// for and serves nothing else.
type scopeRecorder struct{ scopes []string }

func (s *scopeRecorder) Desired(_ context.Context, scope string) (*contentpackapp.Desired, string, error) {
	s.scopes = append(s.scopes, scope)
	return &contentpackapp.Desired{}, `"v"`, nil
}

func (s *scopeRecorder) Version(_ context.Context, scope string) (string, error) {
	s.scopes = append(s.scopes, scope)
	return `"v1"`, nil
}

func (s *scopeRecorder) Archive(_ context.Context, scope, _ string) ([]byte, error) {
	s.scopes = append(s.scopes, scope)
	return nil, shared.ErrNotFound
}

func (s *scopeRecorder) Index(_ context.Context, scope, _ string) ([]contentpackapp.IndexEntry, error) {
	s.scopes = append(s.scopes, scope)
	return nil, shared.ErrNotFound
}

func (s *scopeRecorder) File(_ context.Context, scope, _, _ string) ([]byte, error) {
	s.scopes = append(s.scopes, scope)
	return nil, shared.ErrNotFound
}

func contentRequest(h http.HandlerFunc, path string, agt *sensor.Sensor) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, path, nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("digest", "sha256:"+string(make([]byte, 0)))
	rctx.URLParams.Add("sha256", "0000000000000000000000000000000000000000000000000000000000000000")
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
	if agt != nil {
		r = r.WithContext(context.WithValue(r.Context(), sensorContextKey, agt))
	}
	w := httptest.NewRecorder()
	h(w, r)
	return w
}

// A shared sensor reads the content routes in the instance scope (platform
// packs only); an organization's sensor in its own tenant's scope; a sensor
// that is neither, or none, is turned away.
func TestContentRoutesScopeBySensorKind(t *testing.T) {
	tenant := shared.NewID()
	own := &sensor.Sensor{ID: shared.NewID(), TenantID: &tenant}
	instance := &sensor.Sensor{ID: shared.NewID(), Scope: sensor.ScopeInstance}
	odd := &sensor.Sensor{ID: shared.NewID(), Scope: sensor.ScopeInstance, TenantID: &tenant} // a shared sensor with a tenant

	for name, route := range map[string]func(*SensorContentV2Handler) http.HandlerFunc{
		"desired": func(h *SensorContentV2Handler) http.HandlerFunc { return h.Desired },
		"pack":    func(h *SensorContentV2Handler) http.HandlerFunc { return h.Pack },
		"index":   func(h *SensorContentV2Handler) http.HandlerFunc { return h.Index },
		"file":    func(h *SensorContentV2Handler) http.HandlerFunc { return h.File },
	} {
		rec := &scopeRecorder{}
		h := NewSensorContentV2Handler(rec, logger.NewNop())
		contentRequest(route(h), "/x", instance)
		contentRequest(route(h), "/x", own)
		if len(rec.scopes) != 2 || rec.scopes[0] != contentpackapp.InstanceScope || rec.scopes[1] != tenant.String() {
			t.Errorf("%s: scopes = %v, want [instance, %s]", name, rec.scopes, tenant)
		}
		rec.scopes = nil
		if w := contentRequest(route(h), "/x", odd); w.Code != http.StatusForbidden || len(rec.scopes) != 0 {
			t.Errorf("%s: an inconsistent sensor got %d and reached the store %v", name, w.Code, rec.scopes)
		}
		if w := contentRequest(route(h), "/x", nil); w.Code != http.StatusUnauthorized || len(rec.scopes) != 0 {
			t.Errorf("%s: an unauthenticated request got %d", name, w.Code)
		}
	}
}

// The heartbeat answer's content_version is the sensor's own scope's version.
func TestContentVersionIsPerScope(t *testing.T) {
	rec := &scopeRecorder{}
	h := NewSensorContentV2Handler(rec, logger.NewNop())
	tenant := shared.NewID()
	if v := h.Version(context.Background(), &sensor.Sensor{ID: shared.NewID(), Scope: sensor.ScopeInstance}); v != `"v1"` {
		t.Errorf("version = %q", v)
	}
	h.Version(context.Background(), &sensor.Sensor{ID: shared.NewID(), TenantID: &tenant})
	if len(rec.scopes) != 2 || rec.scopes[0] != contentpackapp.InstanceScope || rec.scopes[1] != tenant.String() {
		t.Errorf("scopes = %v", rec.scopes)
	}
}
