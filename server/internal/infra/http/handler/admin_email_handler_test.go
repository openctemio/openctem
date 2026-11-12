package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/platformemail"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/crypto"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/platformsetting"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type settingMemRepo struct {
	mu   sync.Mutex
	rows map[string]platformsetting.State
}

func (m *settingMemRepo) Get(_ context.Context, key string) (platformsetting.State, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st, ok := m.rows[key]
	if !ok {
		return platformsetting.State{}, platformsetting.ErrNotFound
	}
	return st, nil
}

func (m *settingMemRepo) CreateIfAbsent(_ context.Context, key string, s platformsetting.State) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.rows[key]; ok {
		return false, nil
	}
	s.Version = 1
	m.rows[key] = s
	return true, nil
}

func (m *settingMemRepo) Update(_ context.Context, key string, v json.RawMessage, expected int, by shared.ID, at time.Time) (platformsetting.State, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st, ok := m.rows[key]
	if !ok || st.Version != expected {
		return platformsetting.State{}, platformsetting.ErrVersionConflict
	}
	st = platformsetting.State{Value: v, Version: expected + 1, Source: platformsetting.SourceConsole, UpdatedBy: &by, UpdatedAt: at}
	m.rows[key] = st
	return st, nil
}

func emailRequest(t *testing.T, method, path string, body any) *http.Request {
	t.Helper()
	a, err := admin.NewAdminUser("super@op.example", "Super", admin.AdminRoleSuperAdmin, nil)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	switch b := body.(type) {
	case nil:
	case string:
		buf.WriteString(b)
	default:
		_ = json.NewEncoder(&buf).Encode(b)
	}
	r := httptest.NewRequest(method, path, &buf)
	return r.WithContext(context.WithValue(r.Context(), middleware.AdminUserKey, a))
}

func newEmailHandler(t *testing.T, stepErr error) *AdminEmailHandler {
	t.Helper()
	enc, err := crypto.NewCipherFromKey("9f2c4e6a8b0d1f3e5a7c9b1d3f5e7a9c0b2d4f6e8a1c3e5b7d9f0a2c4e6b8d0f", "")
	if err != nil {
		t.Fatal(err)
	}
	svc := platformemail.NewService(&settingMemRepo{rows: map[string]platformsetting.State{}}, enc, nil, logger.NewNop())
	return NewAdminEmailHandler(svc, fakeStepUp{err: stepErr}, "OpenCTEM", logger.NewNop())
}

func TestAdminEmailHandler(t *testing.T) {
	const path = "/api/v1/admin/settings/email"
	body := func(code string, version int) map[string]any {
		return map[string]any{"enabled": true, "host": "smtp.example.com", "port": 587, "username": "mailer",
			"password": "s3cret-smtp-pass", "from": "noreply@example.com", "from_name": "OpenCTEM", "starttls": true,
			"version": version, "totp_code": code}
	}

	t.Run("save needs a fresh authenticator code", func(t *testing.T) {
		h := newEmailHandler(t, nil)
		rec := httptest.NewRecorder()
		h.Update(rec, emailRequest(t, http.MethodPut, path, body("", 0)))
		if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), string(codeStepUpRequired)) {
			t.Fatalf("no code: %d %s", rec.Code, rec.Body.String())
		}
		rec = httptest.NewRecorder()
		h2 := newEmailHandler(t, admin.ErrInvalidMFACode)
		h2.Update(rec, emailRequest(t, http.MethodPut, path, body("123456", 0)))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("bad code: %d", rec.Code)
		}
	})

	t.Run("password is write-only", func(t *testing.T) {
		h := newEmailHandler(t, nil)
		rec := httptest.NewRecorder()
		h.Update(rec, emailRequest(t, http.MethodPut, path, body("123456", 0)))
		if rec.Code != http.StatusOK {
			t.Fatalf("save: %d %s", rec.Code, rec.Body.String())
		}
		rec = httptest.NewRecorder()
		h.Get(rec, emailRequest(t, http.MethodGet, path, nil))
		if strings.Contains(rec.Body.String(), "s3cret-smtp-pass") || strings.Contains(rec.Body.String(), "password_encrypted") ||
			!strings.Contains(rec.Body.String(), `"password_set":true`) {
			t.Fatalf("GET leaks or omits the password state: %s", rec.Body.String())
		}
	})

	t.Run("stale version and unknown fields are refused", func(t *testing.T) {
		h := newEmailHandler(t, nil)
		rec := httptest.NewRecorder()
		h.Update(rec, emailRequest(t, http.MethodPut, path, body("123456", 5)))
		if rec.Code != http.StatusConflict {
			t.Fatalf("stale: %d", rec.Code)
		}
		rec = httptest.NewRecorder()
		h.Update(rec, emailRequest(t, http.MethodPut, path, `{"host":"x","skip_verify":true,"totp_code":"1"}`))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("unknown field: %d", rec.Code)
		}
	})

	t.Run("invalid settings are 400", func(t *testing.T) {
		h := newEmailHandler(t, nil)
		b := body("123456", 0)
		b["host"] = "smtp://evil"
		rec := httptest.NewRecorder()
		h.Update(rec, emailRequest(t, http.MethodPut, path, b))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("invalid host: %d", rec.Code)
		}
	})

	t.Run("test e-mail fails generically when not configured", func(t *testing.T) {
		h := newEmailHandler(t, nil)
		rec := httptest.NewRecorder()
		h.SendTest(rec, emailRequest(t, http.MethodPost, path+"/test", nil))
		if rec.Code != http.StatusBadGateway {
			t.Fatalf("test: %d", rec.Code)
		}
	})

	t.Run("no administrator session", func(t *testing.T) {
		h := newEmailHandler(t, nil)
		rec := httptest.NewRecorder()
		h.Update(rec, httptest.NewRequest(http.MethodPut, path, strings.NewReader("{}")))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("no session: %d", rec.Code)
		}
	})
}
