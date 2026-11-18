package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	cirunapp "github.com/openctemio/openctem/server/internal/app/cirun"
	"github.com/openctemio/openctem/server/pkg/domain/cirun"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/logger"
)

type fakeNewRepos struct {
	tenant   shared.ID
	decision cirun.NewRepositoryDecision
}

func (f *fakeNewRepos) ListNewRepositories(_ context.Context, tenantID, configID shared.ID) (*cirunapp.NewRepositoryList, error) {
	f.tenant = tenantID
	now := time.Now()
	return &cirunapp.NewRepositoryList{
		Config: &cirun.TrustConfig{ID: configID, Rules: cirun.Rules{AllRepositories: true, Owners: []string{"platform"}}},
		Rows: []cirun.NewRepository{
			{Kind: cirun.NewRepoProject, Name: "alice/a", Group: "alice", State: cirun.NewRepoPending, FirstSeen: now, LastSeen: now, Count: 2},
			{Kind: cirun.NewRepoProject, Name: "alice/b", Group: "alice", State: cirun.NewRepoPending, FirstSeen: now, LastSeen: now, Count: 1},
			{Kind: cirun.NewRepoProject, Name: "bob/x", Group: "bob", State: cirun.NewRepoPending, FirstSeen: now, LastSeen: now, Count: 1},
			{Kind: cirun.NewRepoGroup, Name: "eve", Group: "eve", State: cirun.NewRepoBlocked, DecidedBy: "admin@example.com"},
		},
	}, nil
}

func (f *fakeNewRepos) DecideNewRepositories(_ context.Context, tenantID, _ shared.ID, d cirun.NewRepositoryDecision, _ cirunapp.Actor) (*cirun.TrustConfig, error) {
	f.tenant, f.decision = tenantID, d
	if d.Action == "" {
		return nil, cirunapp.ErrNotAllRepositories
	}
	return &cirun.TrustConfig{}, nil
}

// Pending projects come grouped by top-level group; blocked and approved
// are listed apart; the tenant comes from the session.
func TestCINewRepositories(t *testing.T) {
	tenant, id := shared.NewID(), shared.NewID()
	h := NewCIAdminHandler(nil, nil, logger.NewNop())
	req := func(method, body string) *http.Request {
		r := tenantRequest(method, "/", body, tenant)
		r.SetPathValue("id", id.String())
		return r
	}
	w := httptest.NewRecorder()
	h.ListNewRepositories(w, req(http.MethodGet, ""))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("unwired: %d", w.Code)
	}
	f := &fakeNewRepos{}
	h.SetNewRepositoryService(f)
	w = httptest.NewRecorder()
	h.ListNewRepositories(w, req(http.MethodGet, ""))
	body := w.Body.String()
	if w.Code != http.StatusOK || f.tenant != tenant {
		t.Fatalf("list: %d %s", w.Code, body)
	}
	for _, want := range []string{`"pending":[{"group":"alice","projects":[{"name":"alice/a"`, `{"group":"bob"`,
		`"blocked":[{"kind":"group","name":"eve"`, `"approved_groups":["platform"]`} {
		if !strings.Contains(body, want) {
			t.Errorf("body lacks %s: %s", want, body)
		}
	}
	w = httptest.NewRecorder()
	h.DecideNewRepositories(w, req(http.MethodPost, `{"decision":"approve","items":[{"kind":"group","name":"alice"},{"kind":"project","name":"bob/x"}]}`))
	if w.Code != http.StatusOK || len(f.decision.Items) != 2 || f.decision.Action != cirun.DecisionApprove {
		t.Fatalf("decide: %d %+v %s", w.Code, f.decision, w.Body.String())
	}
	w = httptest.NewRecorder()
	h.DecideNewRepositories(w, req(http.MethodPost, `{"decision":"","items":[]}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("not an all-projects trust: %d", w.Code)
	}
	w = httptest.NewRecorder()
	h.DecideNewRepositories(w, req(http.MethodPost, `{"decision":"approve","items":[],"tenant_id":"x"}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("unknown field accepted: %d", w.Code)
	}
}
