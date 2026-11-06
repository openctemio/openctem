package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	signupeventapp "github.com/openctemio/openctem/api/internal/app/signupevent"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/signupevent"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type signupEventMem struct {
	records []signupevent.Record
	t       *signupevent.BurstThresholds
	ver     int
}

func (m *signupEventMem) Insert(_ context.Context, r signupevent.Record) error {
	m.records = append(m.records, r)
	return nil
}

func (m *signupEventMem) List(_ context.Context, f signupevent.Filter) ([]signupevent.Record, int64, error) {
	out := []signupevent.Record{}
	for _, r := range m.records {
		if f.Kind == "" || r.Kind == f.Kind {
			out = append(out, r)
		}
	}
	return out, int64(len(out)), nil
}

func (m *signupEventMem) Daily(context.Context, time.Time) ([]signupevent.DailyCount, error) {
	return []signupevent.DailyCount{{Day: time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC), Kind: signupevent.KindAccountCreated, Count: 3}}, nil
}

func (m *signupEventMem) Purge(context.Context, time.Time) (int64, error) { return 0, nil }

func (m *signupEventMem) GetBurstThresholds(context.Context) (signupevent.BurstThresholds, int, error) {
	if m.t == nil {
		return signupevent.BurstThresholds{}, 0, signupevent.ErrThresholdsNotFound
	}
	return *m.t, m.ver, nil
}

func (m *signupEventMem) SetBurstThresholds(_ context.Context, t signupevent.BurstThresholds, expected int, _ string, _ time.Time) (int, error) {
	if expected != m.ver {
		return 0, signupevent.ErrVersionConflict
	}
	m.t, m.ver = &t, m.ver+1
	return m.ver, nil
}

func signupEventRequest(t *testing.T, method, target string, body any, withAdmin bool) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	r := httptest.NewRequest(method, target, &buf)
	if !withAdmin {
		return r
	}
	a, err := admin.NewAdminUser("super@op.example", "Super", admin.AdminRoleSuperAdmin, nil)
	if err != nil {
		t.Fatal(err)
	}
	return r.WithContext(context.WithValue(r.Context(), middleware.AdminUserKey, a))
}

func TestAdminSignupEventHandler(t *testing.T) {
	newHandler := func(step StepUpVerifier) (*AdminSignupEventHandler, *signupEventMem, *countingStepUp) {
		mem := &signupEventMem{}
		tid := shared.NewID()
		mem.records = []signupevent.Record{
			{ID: 1, Kind: signupevent.KindAccountCreated, Source: signupevent.SourcePassword, EmailDomain: "example.com",
				IPPrefix: "198.51.100.0/24", OccurredAt: time.Now()},
			{ID: 2, Kind: signupevent.KindOrganizationCreated, Source: signupevent.SourceSelfService, EmailDomain: "example.com",
				TenantID: &tid, OccurredAt: time.Now()},
		}
		svc := signupeventapp.NewService(mem, mem, nil, logger.NewNop())
		c := &countingStepUp{}
		if step == nil {
			step = c
		}
		return NewAdminSignupEventHandler(svc, step, logger.NewNop()), mem, c
	}

	t.Run("list filters by kind and returns no person", func(t *testing.T) {
		h, _, _ := newHandler(nil)
		rec := httptest.NewRecorder()
		h.List(rec, signupEventRequest(t, http.MethodGet, "/api/v1/admin/signup-events?kind=organization_created", nil, true))
		var resp SignupEventListResponse
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		if rec.Code != http.StatusOK || len(resp.Data) != 1 || resp.Data[0].TenantID == nil || resp.Data[0].EmailDomain != "example.com" {
			t.Fatalf("got %d %s", rec.Code, rec.Body.String())
		}
		if bytes.Contains(rec.Body.Bytes(), []byte("user_id")) {
			t.Fatal("the feed must not expose account ids")
		}
	})
	t.Run("list refuses an unknown kind", func(t *testing.T) {
		h, _, _ := newHandler(nil)
		rec := httptest.NewRecorder()
		h.List(rec, signupEventRequest(t, http.MethodGet, "/api/v1/admin/signup-events?kind=everything", nil, true))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("got %d", rec.Code)
		}
	})
	t.Run("daily bounds days", func(t *testing.T) {
		h, _, _ := newHandler(nil)
		for target, want := range map[string]int{
			"/api/v1/admin/signup-events/daily":         http.StatusOK,
			"/api/v1/admin/signup-events/daily?days=7":  http.StatusOK,
			"/api/v1/admin/signup-events/daily?days=0":  http.StatusBadRequest,
			"/api/v1/admin/signup-events/daily?days=91": http.StatusBadRequest,
			"/api/v1/admin/signup-events/daily?days=x":  http.StatusBadRequest,
		} {
			rec := httptest.NewRecorder()
			h.Daily(rec, signupEventRequest(t, http.MethodGet, target, nil, true))
			if rec.Code != want {
				t.Fatalf("%s: got %d", target, rec.Code)
			}
		}
	})
	t.Run("get thresholds returns the defaults with version 0", func(t *testing.T) {
		h, _, _ := newHandler(nil)
		rec := httptest.NewRecorder()
		h.GetThresholds(rec, signupEventRequest(t, http.MethodGet, "/api/v1/admin/settings/signup-alerts", nil, true))
		var resp SignupBurstThresholdsResponse
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		if rec.Code != http.StatusOK || resp.Version != 0 || resp.PerIPPrefix != signupevent.DefaultBurstThresholds().PerIPPrefix || resp.IgnoredDomains == nil {
			t.Fatalf("got %d %s", rec.Code, rec.Body.String())
		}
	})

	valid := map[string]any{"per_ip_prefix": 5, "per_email_domain": 10, "window_minutes": 60, "version": 0,
		"reason": "tighten for launch", "totp_code": "123456"}
	with := func(k string, v any) map[string]any {
		m := map[string]any{}
		for kk, vv := range valid {
			m[kk] = vv
		}
		m[k] = v
		return m
	}
	refusals := []struct {
		name      string
		admin     bool
		step      StepUpVerifier
		body      map[string]any
		want      int
		stepCalls int
	}{
		{"no administrator", false, nil, valid, http.StatusUnauthorized, 0},
		{"invalid window, before the code is spent", true, nil, with("window_minutes", 1), http.StatusBadRequest, 0},
		{"negative threshold", true, nil, with("per_ip_prefix", -1), http.StatusBadRequest, 0},
		{"no reason", true, nil, with("reason", " "), http.StatusBadRequest, 0},
		{"no authenticator code", true, nil, with("totp_code", ""), http.StatusUnauthorized, 0},
		{"wrong authenticator code", true, fakeStepUp{err: admin.ErrInvalidMFACode}, valid, http.StatusUnauthorized, 0},
		{"stale version", true, nil, with("version", 4), http.StatusConflict, 1},
	}
	for _, tc := range refusals {
		t.Run(tc.name, func(t *testing.T) {
			h, mem, c := newHandler(tc.step)
			rec := httptest.NewRecorder()
			h.UpdateThresholds(rec, signupEventRequest(t, http.MethodPut, "/api/v1/admin/settings/signup-alerts", tc.body, tc.admin))
			if rec.Code != tc.want {
				t.Fatalf("expected %d, got %d %s", tc.want, rec.Code, rec.Body.String())
			}
			if mem.t != nil {
				t.Fatal("a refused change must not be stored")
			}
			if c.calls != tc.stepCalls {
				t.Fatalf("step-up calls = %d, want %d", c.calls, tc.stepCalls)
			}
		})
	}

	t.Run("update", func(t *testing.T) {
		h, mem, _ := newHandler(nil)
		rec := httptest.NewRecorder()
		h.UpdateThresholds(rec, signupEventRequest(t, http.MethodPut, "/api/v1/admin/settings/signup-alerts",
			with("ignored_domains", []string{"Gmail.com"}), true))
		var resp SignupBurstThresholdsResponse
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		if rec.Code != http.StatusOK || resp.Version != 1 || resp.PerIPPrefix != 5 || len(resp.IgnoredDomains) != 1 || resp.IgnoredDomains[0] != "gmail.com" {
			t.Fatalf("got %d %s", rec.Code, rec.Body.String())
		}
		if mem.t == nil || mem.t.PerEmailDomain != 10 {
			t.Fatal("not stored")
		}
	})
}
