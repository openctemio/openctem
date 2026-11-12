package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scanprofile"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

// ruleSourcesProfileRepo is auditProfileRepo with updates, scoped to the
// profile's tenant like the postgres repository.
type ruleSourcesProfileRepo struct{ auditProfileRepo }

func (r *ruleSourcesProfileRepo) GetByTenantAndID(_ context.Context, tenantID, id shared.ID) (*scanprofile.ScanProfile, error) {
	if p, ok := r.byID[id]; ok && p.TenantID.Equals(tenantID) {
		return p, nil
	}
	return nil, shared.ErrNotFound
}

func (r *ruleSourcesProfileRepo) Update(_ context.Context, p *scanprofile.ScanProfile) error {
	r.byID[p.ID] = p
	return nil
}

func TestScanProfileRuleSources(t *testing.T) {
	tenantID, otherTenant, userID := shared.NewID(), shared.NewID(), shared.NewID().String()
	repo := &ruleSourcesProfileRepo{auditProfileRepo{byID: map[shared.ID]*scanprofile.ScanProfile{}}}
	h := NewScanProfileHandler(scan.NewScanProfileService(repo, logger.NewNop()), validator.New(), logger.NewNop())
	read := func(w *httptest.ResponseRecorder) ScanProfileResponse {
		t.Helper()
		var resp ScanProfileResponse
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode %s: %v", w.Body.String(), err)
		}
		return resp
	}

	w := httptest.NewRecorder()
	h.Create(w, auditedRequest(http.MethodPost, "/api/v1/scan-profiles", []byte(`{"name":"default rules"}`), tenantID.String(), userID, ""))
	if w.Code != http.StatusCreated || read(w).RuleSources != "both" {
		t.Fatalf("create without rule sources: %d %s", w.Code, w.Body.String())
	}

	w = httptest.NewRecorder()
	h.Create(w, auditedRequest(http.MethodPost, "/api/v1/scan-profiles", []byte(`{"name":"mine","rule_sources":"tenant"}`), tenantID.String(), userID, ""))
	if w.Code != http.StatusCreated || read(w).RuleSources != "tenant" {
		t.Fatalf("create tenant: %d %s", w.Code, w.Body.String())
	}
	id := read(w).ID

	w = httptest.NewRecorder()
	h.Create(w, auditedRequest(http.MethodPost, "/api/v1/scan-profiles", []byte(`{"name":"bad","rule_sources":"everything"}`), tenantID.String(), userID, ""))
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("unknown value: %d %s", w.Code, w.Body.String())
	}

	w = httptest.NewRecorder()
	h.Update(w, auditedRequest(http.MethodPut, "/api/v1/scan-profiles/"+id, []byte(`{"rule_sources":"platform"}`), tenantID.String(), userID, id))
	if w.Code != http.StatusOK || read(w).RuleSources != "platform" {
		t.Fatalf("update: %d %s", w.Code, w.Body.String())
	}
	// Omitted leaves it unchanged.
	w = httptest.NewRecorder()
	h.Update(w, auditedRequest(http.MethodPut, "/api/v1/scan-profiles/"+id, []byte(`{"description":"x"}`), tenantID.String(), userID, id))
	if w.Code != http.StatusOK || read(w).RuleSources != "platform" {
		t.Fatalf("update without rule sources changed them: %d %s", w.Code, w.Body.String())
	}
	// Another organization cannot change it.
	w = httptest.NewRecorder()
	h.Update(w, auditedRequest(http.MethodPut, "/api/v1/scan-profiles/"+id, []byte(`{"rule_sources":"both"}`), otherTenant.String(), userID, id))
	if w.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant update: %d %s", w.Code, w.Body.String())
	}
	pid, _ := shared.IDFromString(id)
	if repo.byID[pid].RuleSources != "platform" {
		t.Fatalf("cross-tenant update changed the profile: %q", repo.byID[pid].RuleSources)
	}
}
