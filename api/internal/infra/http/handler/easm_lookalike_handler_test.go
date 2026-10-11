package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	easmapp "github.com/openctemio/openctem/api/internal/app/easm"
	"github.com/openctemio/openctem/api/pkg/domain/lookalike"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type fakeLookalikes struct {
	tenants []shared.ID
}

func (f *fakeLookalikes) ListWatches(_ context.Context, id shared.ID) ([]lookalike.Watch, error) {
	f.tenants = append(f.tenants, id)
	return []lookalike.Watch{}, nil
}
func (f *fakeLookalikes) CreateWatch(_ context.Context, id shared.ID, _ *shared.ID, domain string, _ []string, _ int) (*lookalike.Watch, error) {
	f.tenants = append(f.tenants, id)
	if domain != "example.com" {
		return nil, easmapp.ErrNotOwnRoot
	}
	return &lookalike.Watch{ID: "w1", Domain: domain, Enabled: true}, nil
}
func (f *fakeLookalikes) UpdateWatch(_ context.Context, _ shared.ID, id string, enabled bool, _ []string, _ int) (*lookalike.Watch, error) {
	if id != "w1" {
		return nil, shared.ErrNotFound
	}
	return &lookalike.Watch{ID: id, Domain: "example.com", Enabled: enabled}, nil
}
func (f *fakeLookalikes) DeleteWatch(context.Context, shared.ID, string) error {
	return shared.ErrNotFound
}
func (f *fakeLookalikes) Registered(context.Context, shared.ID, string) ([]lookalike.CandidateRecord, error) {
	return []lookalike.CandidateRecord{{Domain: "examp1e.com", State: "registered"}}, nil
}

func TestEASMLookalikeHandler(t *testing.T) {
	tenantID := shared.NewID()
	svc := &fakeLookalikes{}
	aud := &settingsAudit{}
	h := NewEASMLookalikeHandler(svc, aud, logger.NewNop())

	w := httptest.NewRecorder()
	h.Create(w, seedReq(http.MethodPost, "/", `{"domain":"example.com","techniques":["tld"]}`, tenantID, "u1"))
	if w.Code != http.StatusCreated || svc.tenants[0] != tenantID || len(aud.actions) != 1 {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	h.Create(w, seedReq(http.MethodPost, "/", `{"domain":"victim.example"}`, tenantID, "u1"))
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "root domains") {
		t.Fatalf("someone else's domain: %d %s", w.Code, w.Body.String())
	}
	r := seedReq(http.MethodPut, "/", `{"enabled":false,"techniques":[]}`, tenantID, "u1")
	r.SetPathValue("id", "w1")
	w = httptest.NewRecorder()
	h.Update(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"enabled":false`) {
		t.Fatalf("update: %d %s", w.Code, w.Body.String())
	}
	r = seedReq(http.MethodDelete, "/", "", tenantID, "u1")
	r.SetPathValue("id", "nope")
	w = httptest.NewRecorder()
	h.Delete(w, r)
	if w.Code != http.StatusNotFound {
		t.Fatalf("delete unknown: %d", w.Code)
	}
	w = httptest.NewRecorder()
	h.List(w, seedReq(http.MethodGet, "/", "", tenantID, "u1"))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"techniques":["omission"`) {
		t.Fatalf("list: %d %s", w.Code, w.Body.String())
	}
}
