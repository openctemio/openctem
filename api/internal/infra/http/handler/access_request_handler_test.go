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

	"github.com/openctemio/openctem/api/internal/app/accessrequest"
	ardom "github.com/openctemio/openctem/api/pkg/domain/accessrequest"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	signupdom "github.com/openctemio/openctem/api/pkg/domain/signup"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type arMemRepo struct {
	mu   sync.Mutex
	rows []*ardom.Request
}

func (m *arMemRepo) Create(_ context.Context, r *ardom.Request) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rows = append(m.rows, r)
	return nil
}
func (m *arMemRepo) GetByID(context.Context, shared.ID) (*ardom.Request, error) {
	return nil, ardom.ErrNotFound
}
func (m *arMemRepo) GetByConfirmHash(context.Context, string) (*ardom.Request, error) {
	return nil, ardom.ErrNotFound
}
func (m *arMemRepo) Update(context.Context, *ardom.Request, ardom.Status) error { return nil }
func (m *arMemRepo) List(context.Context, ardom.Filter) ([]*ardom.Request, int, error) {
	return nil, 0, nil
}
func (m *arMemRepo) CountByIPSince(context.Context, string, time.Time) (int, error) { return 0, nil }
func (m *arMemRepo) CountByDomainSince(context.Context, string, time.Time) (int, error) {
	return 0, nil
}
func (m *arMemRepo) Purge(context.Context, time.Time, time.Time) (int64, error) { return 0, nil }

func postAR(t *testing.T, h *AccessRequestHandler, body map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(body)
	rec := httptest.NewRecorder()
	h.Submit(rec, httptest.NewRequest(http.MethodPost, "/api/v1/auth/access-requests", bytes.NewReader(b)))
	return rec
}

// A stored request and a silently dropped one (disposable address) get the
// same answer; a closed queue answers the sign-up refusal.
func TestAccessRequestHandler_Submit(t *testing.T) {
	repo := &arMemRepo{}
	open := signupdom.Static{Mode: signupdom.ModeAdminOnly, RequestAccess: true}
	h := NewAccessRequestHandler(accessrequest.NewService(repo, open, nil, nil, nil, "https://app.example.com", logger.NewNop()), logger.NewNop())

	stored := postAR(t, h, map[string]string{"company": "Acme", "email": "owner@acme.com"})
	dropped := postAR(t, h, map[string]string{"company": "Acme", "email": "owner@mailinator.com"})
	if stored.Code != http.StatusAccepted || dropped.Code != stored.Code || !bytes.Equal(stored.Body.Bytes(), dropped.Body.Bytes()) {
		t.Fatalf("answers differ: stored %d %s, dropped %d %s", stored.Code, stored.Body.String(), dropped.Code, dropped.Body.String())
	}
	if len(repo.rows) != 1 {
		t.Fatalf("only the real request is stored, got %d", len(repo.rows))
	}

	if rec := postAR(t, h, map[string]string{"company": "", "email": "x"}); rec.Code != http.StatusBadRequest {
		t.Fatalf("an invalid form is refused, got %d", rec.Code)
	}

	closed := NewAccessRequestHandler(accessrequest.NewService(&arMemRepo{}, signupdom.Static{Mode: signupdom.ModeAdminOnly}, nil, nil, nil, "", logger.NewNop()), logger.NewNop())
	rec := postAR(t, closed, map[string]string{"company": "Acme", "email": "owner@acme.com"})
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if rec.Code != http.StatusForbidden || body["code"] != string(CodeSignupNotAvailable) {
		t.Fatalf("a closed queue must refuse, got %d %s", rec.Code, rec.Body.String())
	}
}

func TestAccessRequestHandler_ConfirmBadToken(t *testing.T) {
	h := NewAccessRequestHandler(accessrequest.NewService(&arMemRepo{}, signupdom.Static{}, nil, nil, nil, "", logger.NewNop()), logger.NewNop())
	rec := httptest.NewRecorder()
	h.Confirm(rec, httptest.NewRequest(http.MethodPost, "/api/v1/auth/access-requests/confirm", bytes.NewBufferString(`{"token":"nope"}`)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}
