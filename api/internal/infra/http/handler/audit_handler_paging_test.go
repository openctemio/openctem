package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// pagingAuditRepo records the pagination each list query used and reports
// 45 matching rows, so the handler's page arithmetic is observable.
type pagingAuditRepo struct {
	fakeAuditRepo
	got []pagination.Pagination
}

func (m *pagingAuditRepo) List(_ context.Context, _ auditdom.Filter, p pagination.Pagination) (pagination.Result[*auditdom.AuditLog], error) {
	m.got = append(m.got, p)
	return pagination.NewResult[*auditdom.AuditLog](nil, 45, p), nil
}

func (m *pagingAuditRepo) ListByResource(_ context.Context, _ shared.ID, _ auditdom.ResourceType, _ string, p pagination.Pagination) (pagination.Result[*auditdom.AuditLog], error) {
	m.got = append(m.got, p)
	return pagination.NewResult[*auditdom.AuditLog](nil, 45, p), nil
}

func (m *pagingAuditRepo) ListByActor(_ context.Context, _ shared.ID, _ shared.ID, p pagination.Pagination) (pagination.Result[*auditdom.AuditLog], error) {
	m.got = append(m.got, p)
	return pagination.NewResult[*auditdom.AuditLog](nil, 45, p), nil
}

// TestAuditHandler_PagesAreOneBased pins the wire contract the web relies on:
// page is 1-based, page 1 is offset 0, a missing page means page 1, and the
// response echoes the page and per_page the query really used. Before the
// fix the resource and user history endpoints echoed page=0 for a missing
// page (and the list echoed per_page=500 while querying 100), so a client
// computing the next page from the response paged off by one.
func TestAuditHandler_PagesAreOneBased(t *testing.T) {
	tenantID := shared.NewID().String()
	userID := shared.NewID().String()

	type call struct {
		name   string
		target string
		serve  func(h *AuditHandler, w http.ResponseWriter, r *http.Request)
		setup  func(r *http.Request)
	}
	calls := []call{
		{
			name: "list", target: "/api/v1/audit-logs",
			serve: func(h *AuditHandler, w http.ResponseWriter, r *http.Request) { h.List(w, r) },
		},
		{
			name: "resource history", target: "/api/v1/audit-logs/resource/role/" + shared.NewID().String(),
			serve: func(h *AuditHandler, w http.ResponseWriter, r *http.Request) { h.GetResourceHistory(w, r) },
			setup: func(r *http.Request) { r.SetPathValue("type", "role"); r.SetPathValue("id", shared.NewID().String()) },
		},
		{
			name: "user activity", target: "/api/v1/audit-logs/user/" + userID,
			serve: func(h *AuditHandler, w http.ResponseWriter, r *http.Request) { h.GetUserActivity(w, r) },
			setup: func(r *http.Request) { r.SetPathValue("id", userID) },
		},
	}
	cases := []struct {
		query                         string
		wantPage, wantPer, wantOffset int
		wantTotalPages                int
	}{
		{"", 1, 20, 0, 3},
		{"?page=1&per_page=20", 1, 20, 0, 3},
		{"?page=2&per_page=20", 2, 20, 20, 3},
		{"?page=3&per_page=20", 3, 20, 40, 3},
		{"?page=1&per_page=500", 1, 100, 0, 1},
	}

	for _, c := range calls {
		for _, tc := range cases {
			t.Run(c.name+tc.query, func(t *testing.T) {
				repo := &pagingAuditRepo{}
				h := NewAuditHandler(audit.NewAuditService(repo, logger.NewNop()), nil, logger.NewNop())
				req := httptest.NewRequest(http.MethodGet, c.target+tc.query, nil)
				ctx := context.WithValue(req.Context(), middleware.TenantIDKey, tenantID)
				ctx = context.WithValue(ctx, middleware.UserIDKey, userID)
				req = req.WithContext(ctx)
				if c.setup != nil {
					c.setup(req)
				}
				rec := httptest.NewRecorder()
				c.serve(h, rec, req)
				if rec.Code != http.StatusOK {
					t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
				}
				if len(repo.got) != 1 {
					t.Fatalf("repository queried %d times, want 1", len(repo.got))
				}
				if off := repo.got[0].Offset(); off != tc.wantOffset {
					t.Errorf("offset = %d, want %d", off, tc.wantOffset)
				}
				var body AuditLogListResponse
				if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
					t.Fatalf("decode: %v", err)
				}
				if body.Page != tc.wantPage || body.PerPage != tc.wantPer || body.TotalPages != tc.wantTotalPages {
					t.Errorf("response page=%d per_page=%d total_pages=%d, want %d/%d/%d",
						body.Page, body.PerPage, body.TotalPages, tc.wantPage, tc.wantPer, tc.wantTotalPages)
				}
			})
		}
		// The shared page parser refuses a page that is not 1-based
		// (page=0, page=abc) instead of reading it as page 1.
		for _, bad := range []string{"?page=0&per_page=10", "?page=abc"} {
			t.Run(c.name+bad, func(t *testing.T) {
				repo := &pagingAuditRepo{}
				h := NewAuditHandler(audit.NewAuditService(repo, logger.NewNop()), nil, logger.NewNop())
				req := httptest.NewRequest(http.MethodGet, c.target+bad, nil)
				ctx := context.WithValue(req.Context(), middleware.TenantIDKey, tenantID)
				ctx = context.WithValue(ctx, middleware.UserIDKey, userID)
				req = req.WithContext(ctx)
				if c.setup != nil {
					c.setup(req)
				}
				rec := httptest.NewRecorder()
				c.serve(h, rec, req)
				if rec.Code != http.StatusBadRequest || len(repo.got) != 0 {
					t.Fatalf("status = %d after %d queries, want 400 before any query", rec.Code, len(repo.got))
				}
			})
		}
	}
}
