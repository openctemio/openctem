package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/adminconsole"
	"github.com/openctemio/openctem/api/internal/app/signup"
	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	signupdom "github.com/openctemio/openctem/api/pkg/domain/signup"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type signupMemRepo struct {
	mu sync.Mutex
	st *signupdom.State
}

func (m *signupMemRepo) Get(context.Context) (signupdom.State, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.st == nil {
		return signupdom.State{}, signupdom.ErrNotFound
	}
	return *m.st, nil
}

func (m *signupMemRepo) CreateIfAbsent(_ context.Context, s signupdom.State) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.st != nil {
		return false, nil
	}
	s.Version = 1
	m.st = &s
	return true, nil
}

func (m *signupMemRepo) Update(_ context.Context, p signupdom.Policy, v int, by shared.ID, at time.Time) (signupdom.State, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.st == nil || m.st.Version != v {
		return signupdom.State{}, signupdom.ErrVersionConflict
	}
	m.st = &signupdom.State{Policy: p, Version: v + 1, Source: signupdom.SourceConsole, UpdatedBy: &by, UpdatedAt: at}
	return *m.st, nil
}

type fakeStepUp struct{ err error }

func (f fakeStepUp) StepUp(context.Context, *admin.AdminUser, string, string, adminconsole.ClientInfo) error {
	return f.err
}

func signupRequest(t *testing.T, method string, body any) *http.Request {
	t.Helper()
	a, err := admin.NewAdminUser("super@op.example", "Super", admin.AdminRoleSuperAdmin, nil)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	r := httptest.NewRequest(method, "/api/v1/admin/settings/signup", &buf)
	return r.WithContext(context.WithValue(r.Context(), middleware.AdminUserKey, a))
}

func TestAdminSignupHandler(t *testing.T) {
	newHandler := func(stepErr error) (*AdminSignupHandler, *signup.Service) {
		svc := signup.NewService(&signupMemRepo{}, nil, nil, nil, logger.NewNop())
		_ = svc.Seed(context.Background(), "admin_only")
		return NewAdminSignupHandler(svc, fakeStepUp{err: stepErr}, logger.NewNop()), svc
	}

	t.Run("get", func(t *testing.T) {
		h, _ := newHandler(nil)
		rec := httptest.NewRecorder()
		h.Get(rec, signupRequest(t, http.MethodGet, nil))
		var resp SignupPolicyResponse
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		if rec.Code != http.StatusOK || resp.Mode != "admin_only" || resp.Version != 1 || resp.Source != "environment" {
			t.Fatalf("got %d %s", rec.Code, rec.Body.String())
		}
	})

	refusals := []struct {
		name   string
		stepUp error
		body   map[string]any
		want   int
	}{
		{"no authenticator code", nil, map[string]any{"mode": "self_service", "version": 1}, http.StatusUnauthorized},
		{"wrong authenticator code", admin.ErrInvalidMFACode, map[string]any{"mode": "self_service", "version": 1, "totp_code": "000000"}, http.StatusUnauthorized},
		{"console authenticator not enrolled", admin.ErrStepUpUnavailable, map[string]any{"mode": "self_service", "version": 1, "totp_code": "123456"}, http.StatusForbidden},
		{"unknown mode", nil, map[string]any{"mode": "everyone", "version": 1, "totp_code": "123456"}, http.StatusBadRequest},
		{"stale version", nil, map[string]any{"mode": "self_service", "version": 9, "totp_code": "123456"}, http.StatusConflict},
	}
	for _, tc := range refusals {
		t.Run(tc.name, func(t *testing.T) {
			h, svc := newHandler(tc.stepUp)
			rec := httptest.NewRecorder()
			h.Update(rec, signupRequest(t, http.MethodPut, tc.body))
			if rec.Code != tc.want {
				t.Fatalf("expected %d, got %d %s", tc.want, rec.Code, rec.Body.String())
			}
			if svc.Current(context.Background()).AllowsSelfService() {
				t.Fatal("a refused change must not change the policy")
			}
		})
	}

	t.Run("saved", func(t *testing.T) {
		h, svc := newHandler(nil)
		rec := httptest.NewRecorder()
		h.Update(rec, signupRequest(t, http.MethodPut, map[string]any{"mode": "self_service", "request_access": true, "version": 1, "totp_code": "123456"}))
		var resp SignupPolicyResponse
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		if rec.Code != http.StatusOK || resp.Mode != "self_service" || !resp.RequestAccess || resp.Version != 2 || resp.Source != "console" {
			t.Fatalf("got %d %s", rec.Code, rec.Body.String())
		}
		if !svc.Current(context.Background()).AllowsSelfService() {
			t.Fatal("the policy must change")
		}
	})

	t.Run("no administrator in context", func(t *testing.T) {
		h, _ := newHandler(nil)
		rec := httptest.NewRecorder()
		h.Update(rec, httptest.NewRequest(http.MethodPut, "/api/v1/admin/settings/signup", bytes.NewBufferString(`{}`)))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", rec.Code)
		}
	})
}

// Public and tenant endpoints follow the console policy, read per request.
func TestSignupPolicyDrivesProvidersAndTenantCreation(t *testing.T) {
	src := &switchable{p: signupdom.Policy{Mode: signupdom.ModeAdminOnly}}
	tenants := &TenantHandler{logger: logger.NewNop()}
	tenants.SetSelfServiceTenantCreation(true) // the console value wins over the env flag
	tenants.SetSignupPolicy(src)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants", bytes.NewBufferString(`{}`))
	rec := httptest.NewRecorder()
	tenants.Create(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("admin_only must refuse POST /tenants, got %d", rec.Code)
	}

	providers := NewAuthProvidersHandler(config.OAuthConfig{}, config.EntraSSOConfig{}, false, logger.NewNop()).
		WithTenantCreationMode("self_service").WithSignupPolicy(src)
	rec = httptest.NewRecorder()
	providers.GetProviders(rec, httptest.NewRequest(http.MethodGet, "/api/v1/auth/providers", nil))
	var body AuthProvidersResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body.TenantCreationMode != "admin_only" {
		t.Fatalf("providers must report the console policy, got %q", body.TenantCreationMode)
	}

	src.set(signupdom.Policy{Mode: signupdom.ModeSelfService})
	rec = httptest.NewRecorder()
	providers.GetProviders(rec, httptest.NewRequest(http.MethodGet, "/api/v1/auth/providers", nil))
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body.TenantCreationMode != "self_service" {
		t.Fatalf("a policy change must show at once, got %q", body.TenantCreationMode)
	}
}

type switchable struct {
	mu sync.Mutex
	p  signupdom.Policy
}

func (s *switchable) Current(context.Context) signupdom.Policy {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.p
}

func (s *switchable) set(p signupdom.Policy) {
	s.mu.Lock()
	s.p = p
	s.mu.Unlock()
}
