package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	queryapp "github.com/openctemio/openctem/api/internal/app/query"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/querylang"
)

type fakeQueryExec struct{ err error }

func (f fakeQueryExec) Explain(context.Context, *querylang.Plan) (querylang.Estimate, error) {
	return querylang.Estimate{Rows: 10, Cost: 1}, f.err
}

func (f fakeQueryExec) Run(_ context.Context, p *querylang.Plan) (*querylang.Result, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &querylang.Result{Columns: p.Columns, Rows: [][]any{{int64(3)}}}, nil
}

func queryRequest(t *testing.T, h http.HandlerFunc, body string, admin bool) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/query/run", strings.NewReader(body))
	ctx := context.WithValue(req.Context(), middleware.TenantIDKey, "11111111-1111-1111-1111-111111111111")
	ctx = context.WithValue(ctx, middleware.UserIDKey, "22222222-2222-2222-2222-222222222222")
	ctx = context.WithValue(ctx, middleware.IsAdminKey, admin)
	rec := httptest.NewRecorder()
	h(rec, req.WithContext(ctx))
	return rec
}

func TestQueryHandler(t *testing.T) {
	h := NewQueryHandler(queryapp.NewService(fakeQueryExec{}, nil, logger.NewNop()), logger.NewNop())

	rec := queryRequest(t, h.Run, `{"query":"findings | count"}`, true)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"rows":[[3]]`) {
		t.Fatalf("run = %d %s", rec.Code, rec.Body)
	}

	rec = queryRequest(t, h.Run, `{"query":"findings where severity = bogus"}`, true)
	var body struct {
		Code    string `json:"code"`
		Details []struct {
			Start, End, Line, Column int
			Message                  string
		} `json:"details"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if rec.Code != http.StatusBadRequest || body.Code != "INVALID_QUERY" || len(body.Details) != 1 ||
		body.Details[0].Start != 26 || body.Details[0].End != 31 || body.Details[0].Column != 27 {
		t.Fatalf("invalid query = %d %s", rec.Code, rec.Body)
	}

	// The tenant is never taken from the body.
	rec = queryRequest(t, h.Run, `{"query":"findings | count","tenant_id":"33333333-3333-3333-3333-333333333333"}`, true)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown body field = %d", rec.Code)
	}
	rec = queryRequest(t, h.Run, `{"query":"`+strings.Repeat("a", maxQueryBody)+`"}`, true)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("oversized body = %d", rec.Code)
	}

	// A member without a data scope enforcer fails closed.
	rec = queryRequest(t, h.Run, `{"query":"findings | count"}`, false)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("member without enforcer = %d", rec.Code)
	}

	h = NewQueryHandler(queryapp.NewService(fakeQueryExec{err: querylang.ErrTimeout}, nil, logger.NewNop()), logger.NewNop())
	rec = queryRequest(t, h.Run, `{"query":"findings | count"}`, true)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("timeout = %d %s", rec.Code, rec.Body)
	}
	rec = queryRequest(t, h.Explain, `{"query":"findings | count by severity"}`, true)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"description"`) {
		t.Fatalf("explain = %d %s", rec.Code, rec.Body)
	}
}
