package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/openctem/server/pkg/apierror"
	"github.com/openctemio/openctem/server/pkg/domain/component"
	"github.com/openctemio/openctem/server/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// A read stopped by its statement timeout is a 503 QUERY_TIMEOUT the console
// can show ("narrow the filter"), never a 500, on the grouped findings view
// and on the components list, facets and summary.
func TestQueryTimeout_IsServiceUnavailableNotInternal(t *testing.T) {
	cases := map[string]func(http.ResponseWriter){
		"finding groups": func(w http.ResponseWriter) {
			(&FindingActionsHandler{logger: logger.NewNop()}).handleError(w, fmt.Errorf("group: %w", vulnerability.ErrFindingQueryTimeout))
		},
		"components": func(w http.ResponseWriter) {
			(&ComponentHandler{logger: logger.NewNop()}).handleServiceError(w, fmt.Errorf("list: %w", component.ErrQueryTimeout))
		},
	}
	for name, write := range cases {
		rec := httptest.NewRecorder()
		write(rec)
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s: status %d, want 503", name, rec.Code)
		}
		var body struct {
			Code string `json:"code"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.Code != string(apierror.CodeQueryTimeout) {
			t.Fatalf("%s: body %s, want code %s", name, rec.Body.String(), apierror.CodeQueryTimeout)
		}
	}
}
