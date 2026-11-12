package handler

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// A priority rule is validated before it is stored. An empty condition list
// matched every finding (and the first matching rule wins), so one such rule
// re-classed the whole tenant; unknown fields were stored and never matched.
// The handler refuses both with 422 before touching the database (db is nil
// here: reaching it would panic).
func TestPriorityRuleWrite_RefusesInvalidConditions(t *testing.T) {
	h := NewPriorityRuleHandler(nil, logger.NewNop())
	tenant := shared.NewID().String()
	call := func(method string, body string, fn http.HandlerFunc) int {
		req := httptest.NewRequest(method, "/api/v1/priority-rules", bytes.NewBufferString(body))
		req = req.WithContext(context.WithValue(req.Context(), middleware.TenantIDKey, tenant))
		rr := httptest.NewRecorder()
		fn(rr, req)
		return rr.Code
	}

	creates := map[string]string{
		"no conditions":      `{"name":"all","priority_class":"P3"}`,
		"empty conditions":   `{"name":"all","priority_class":"P3","conditions":[]}`,
		"null conditions":    `{"name":"all","priority_class":"P3","conditions":null}`,
		"unknown field":      `{"name":"x","priority_class":"P3","conditions":[{"field":"nope","operator":"eq","value":true}]}`,
		"unknown key":        `{"name":"x","priority_class":"P3","conditions":[{"field":"is_in_kev","operator":"eq","value":true,"extra":1}]}`,
		"wrong value type":   `{"name":"x","priority_class":"P3","conditions":[{"field":"is_in_kev","operator":"eq","value":"yes"}]}`,
		"bad operator/field": `{"name":"x","priority_class":"P3","conditions":[{"field":"is_in_kev","operator":"gte","value":true}]}`,
		"name too long":      `{"name":"` + string(bytes.Repeat([]byte("n"), 101)) + `","priority_class":"P3","conditions":[{"field":"is_in_kev","operator":"eq","value":true}]}`,
	}
	for name, body := range creates {
		if code := call(http.MethodPost, body, h.Create); code != http.StatusUnprocessableEntity {
			t.Errorf("create with %s = %d, want 422", name, code)
		}
	}
	if code := call(http.MethodPut, `{"conditions":[]}`, h.Update); code != http.StatusUnprocessableEntity {
		t.Errorf("update to empty conditions = %d, want 422", code)
	}
}
