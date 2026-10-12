package unit

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/threat"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/threatactor"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
	"github.com/openctemio/openctem/api/pkg/validator"
)

// mockThreatActorRepo is a minimal threatactor.Repository for handler tests.
// Only Create is exercised; the rest satisfy the interface.
type mockThreatActorRepo struct {
	created int
}

func (m *mockThreatActorRepo) Create(_ context.Context, _ *threatactor.ThreatActor) error {
	m.created++
	return nil
}
func (m *mockThreatActorRepo) GetByID(_ context.Context, _, _ shared.ID) (*threatactor.ThreatActor, error) {
	return nil, shared.ErrNotFound
}
func (m *mockThreatActorRepo) Update(_ context.Context, _ *threatactor.ThreatActor) error { return nil }
func (m *mockThreatActorRepo) Delete(_ context.Context, _, _ shared.ID) error             { return nil }
func (m *mockThreatActorRepo) List(_ context.Context, _ threatactor.Filter, page pagination.Pagination) (pagination.Result[*threatactor.ThreatActor], error) {
	return pagination.NewResult([]*threatactor.ThreatActor{}, 0, page), nil
}
func (m *mockThreatActorRepo) LinkCVE(_ context.Context, _ *threatactor.ThreatActorCVE) error {
	return nil
}
func (m *mockThreatActorRepo) ListCVEsByActor(_ context.Context, _, _ shared.ID) ([]*threatactor.ThreatActorCVE, error) {
	return nil, nil
}
func (m *mockThreatActorRepo) ListActorsByCVE(_ context.Context, _ shared.ID, _ string) ([]*threatactor.ThreatActor, error) {
	return nil, nil
}

func newThreatActorHandler() (*handler.ThreatActorHandler, *mockThreatActorRepo) {
	repo := &mockThreatActorRepo{}
	svc := threat.NewActorService(repo, logger.NewNop())
	h := handler.NewThreatActorHandler(svc, validator.New(), logger.NewNop())
	return h, repo
}

func threatActorCreateRequest(body string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/threat-actors/", strings.NewReader(body))
	ctx := context.WithValue(req.Context(), middleware.TenantIDKey, shared.NewID().String())
	return req.WithContext(ctx)
}

func TestThreatActorHandler_Create_RejectsOversizedName(t *testing.T) {
	h, repo := newThreatActorHandler()

	body := `{"name":"` + strings.Repeat("A", 10000) + `","actor_type":"apt"}`
	rec := httptest.NewRecorder()
	h.Create(rec, threatActorCreateRequest(body))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for oversized name, got %d (body: %s)", rec.Code, rec.Body.String())
	}
	if repo.created != 0 {
		t.Errorf("expected repo.Create to NOT be called, got %d calls", repo.created)
	}
}

func TestThreatActorHandler_Create_RejectsBadActorType(t *testing.T) {
	h, _ := newThreatActorHandler()

	body := `{"name":"Fancy Bear","actor_type":"not-a-real-type"}`
	rec := httptest.NewRecorder()
	h.Create(rec, threatActorCreateRequest(body))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for bad actor_type, got %d", rec.Code)
	}
}

func TestThreatActorHandler_Create_AcceptsValid(t *testing.T) {
	h, repo := newThreatActorHandler()

	body := `{"name":"Fancy Bear","actor_type":"apt","description":"APT28","tags":["russia","apt"]}`
	rec := httptest.NewRecorder()
	h.Create(rec, threatActorCreateRequest(body))

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201 for valid actor, got %d (body: %s)", rec.Code, rec.Body.String())
	}
	if repo.created != 1 {
		t.Errorf("expected repo.Create called once, got %d", repo.created)
	}
}

// sanity: ensure the response DTO shape is JSON-encodable with failed/errors.
func TestBulkIngestErrorDTO_JSONShape(t *testing.T) {
	e := handler.BulkIngestError{Index: 3, Reason: "invalid severity"}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"index":3`) || !strings.Contains(string(b), `"reason":"invalid severity"`) {
		t.Errorf("unexpected JSON shape: %s", string(b))
	}
}
