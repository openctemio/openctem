package handler

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/suppression"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/logger"
)

// These error mappers each fell through to 500 for caller-caused errors —
// an id that does not exist (or belongs to another tenant) and an action on a
// record that is no longer in the right state. The v0.9.0 API crawl hit all of
// them:
//
//	POST /findings/{id}/validate, /request-verification   → 500 (not found)
//	POST /compliance/findings/{id}/controls[/auto-map]    → 500 (not found)
//	POST /suppressions/{id}/approve|reject on a decided rule → 500 (conflict)
func TestErrorMappersAnswerCallerErrorsWith4xx(t *testing.T) {
	notFoundFinding := fmt.Errorf("finding lookup: %w", vulnerability.FindingNotFoundError(shared.NewID()))
	conflict := fmt.Errorf("%w: can only approve pending rules", shared.ErrConflict)

	findings := NewFindingActionsHandler(nil, logger.NewNop())
	compliance := NewComplianceHandler(nil, logger.NewNop())
	suppressions := NewSuppressionHandler(nil, logger.NewNop())

	cases := []struct {
		name  string
		write func(http.ResponseWriter, error)
		err   error
		want  int
	}{
		{"finding actions: finding not found", findings.handleError, notFoundFinding, http.StatusNotFound},
		{"finding actions: conflict", findings.handleError, conflict, http.StatusConflict},
		{"compliance: finding not found", compliance.handleError, fmt.Errorf("%w: finding not found", shared.ErrNotFound), http.StatusNotFound},
		{"suppression: rule no longer pending", suppressions.handleServiceError, conflict, http.StatusConflict},
		{"suppression: domain not-found still 404", suppressions.handleServiceError, suppression.ErrRuleNotFound, http.StatusNotFound},
		{"finding actions: unknown error stays 500", findings.handleError, fmt.Errorf("boom"), http.StatusInternalServerError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			tc.write(rec, tc.err)
			if rec.Code != tc.want {
				t.Fatalf("got %d, want %d (body %s)", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}
