package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	easmapp "github.com/openctemio/openctem/api/internal/app/easm"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type fakeReviewer struct {
	tenant shared.ID
	query  easmapp.ReviewQuery
	res    *easmapp.DecisionResult
	err    error
}

func (f *fakeReviewer) Queue(_ context.Context, tenantID shared.ID, q easmapp.ReviewQuery) (*easmapp.ReviewPage, error) {
	f.tenant, f.query = tenantID, q
	return &easmapp.ReviewPage{Items: []easmapp.ReviewItem{}}, f.err
}

func (f *fakeReviewer) Decide(_ context.Context, tenantID shared.ID, _ []string, _ attribution.State, _ string) (*easmapp.DecisionResult, error) {
	f.tenant = tenantID
	return f.res, f.err
}

func easmRequest(method, target, body string, tenant shared.ID) *http.Request {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	return req.WithContext(context.WithValue(req.Context(), middleware.TenantIDKey, tenant.String()))
}

func TestEASMHandler_Candidates(t *testing.T) {
	tenant := shared.NewID()
	rv := &fakeReviewer{}
	h := NewEASMHandler(nil, logger.NewNop()).SetReview(rv, nil)

	rec := httptest.NewRecorder()
	h.Candidates(rec, easmRequest(http.MethodGet, "/api/v1/easm/candidates?states=needs_review&page=3&per_page=500&min_confidence=50", "", tenant))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	// The tenant comes from the token context, never from the request.
	if rv.tenant != tenant || rv.query.Limit != MaxPerPage || rv.query.Offset != 2*MaxPerPage || rv.query.MinConfidence != 50 {
		t.Fatalf("tenant %v query %+v", rv.tenant, rv.query)
	}

	rec = httptest.NewRecorder()
	h.Candidates(rec, easmRequest(http.MethodGet, "/api/v1/easm/candidates?states=owned", "", tenant))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown state: %d", rec.Code)
	}
}

func TestEASMHandler_Decide(t *testing.T) {
	tenant := shared.NewID()
	a, b := shared.NewID().String(), shared.NewID().String()
	rv := &fakeReviewer{res: &easmapp.DecisionResult{
		Decided:  []easmapp.Decision{{AssetID: a, From: "needs_review", To: "confirmed"}},
		NotFound: []string{b},
	}}
	audit := &fakeAuditor{}
	h := NewEASMHandler(nil, logger.NewNop()).SetReview(rv, audit)

	body := fmt.Sprintf(`{"asset_ids":[%q,%q],"state":"confirmed","note":"ours"}`, a, b)
	rec := httptest.NewRecorder()
	h.Decide(rec, easmRequest(http.MethodPost, "/api/v1/easm/candidates/decisions", body, tenant))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	var out easmapp.DecisionResult
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if len(out.Decided) != 1 || len(out.NotFound) != 1 || rv.tenant != tenant {
		t.Fatalf("response %+v", out)
	}
	// One audit event per decided asset, none for the not-found one.
	if len(audit.events) != 1 {
		t.Fatalf("audit events = %d, want 1", len(audit.events))
	}

	for name, body := range map[string]string{
		"bad json":  `{`,
		"long note": fmt.Sprintf(`{"asset_ids":[%q],"state":"confirmed","note":%q}`, a, strings.Repeat("x", maxDecisionNote+1)),
	} {
		rec := httptest.NewRecorder()
		h.Decide(rec, easmRequest(http.MethodPost, "/x", body, tenant))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d", name, rec.Code)
		}
	}

	rv.err = fmt.Errorf("%w: state must be confirmed", shared.ErrValidation)
	rec = httptest.NewRecorder()
	h.Decide(rec, easmRequest(http.MethodPost, "/x", `{"asset_ids":[],"state":"x"}`, tenant))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("validation error: %d", rec.Code)
	}
}
