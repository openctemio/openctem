package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Each of these handlers sent a value straight to a column guarded by a CHECK
// constraint (or a varchar(2)), so a bad value came back as a 500 from the
// database instead of a 4xx from the API. The v0.9.0 API crawl hit all five
// with an ordinary request body. The handlers are built with no database: the
// value must be rejected before any query runs.
func TestEnumFieldsAreValidatedBeforeTheDatabase(t *testing.T) {
	nop := logger.NewNop()
	profiles := NewAttackerProfileHandler(nil, nop)
	services := NewBusinessServiceHandler(nil, nop)
	rules := NewPriorityRuleHandler(nil, nop)

	cases := []struct {
		name   string
		handle http.HandlerFunc
		body   string
	}{
		{"attacker profile create: unknown profile_type", profiles.Create, `{"name":"p","profile_type":"domain"}`},
		{"attacker profile update: unknown profile_type", profiles.Update, `{"name":"p","profile_type":"domain"}`},
		{"business service link: unknown dependency_type", services.LinkAsset, `{"asset_id":"` + shared.NewID().String() + `","dependency_type":"qa"}`},
		{"priority rule update: priority_class not P0-P3", rules.Update, `{"priority_class":"high"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tc.body))
			ctx := context.WithValue(req.Context(), middleware.TenantIDKey, shared.NewID().String())
			ctx = context.WithValue(ctx, middleware.UserIDKey, shared.NewID().String())
			rec := httptest.NewRecorder()
			func() {
				defer func() {
					if p := recover(); p != nil {
						t.Fatalf("reached the database with an invalid value (panic on nil db: %v)", p)
					}
				}()
				tc.handle(rec, req.WithContext(ctx))
			}()
			// 400, or 422 where the handler's validator answers with field details.
			if rec.Code != http.StatusBadRequest && rec.Code != http.StatusUnprocessableEntity {
				t.Fatalf("got %d, want 400/422 (%s)", rec.Code, rec.Body.String())
			}
		})
	}
}
