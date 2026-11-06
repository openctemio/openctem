package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/finding"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// A group exception above the bulk ceiling answers 400 BULK_TOO_LARGE (not a
// server error), so the console can ask the caller to confirm and resend with
// "approved": true.
func TestRemediationTaskHandler_BulkGuardRefusalsAreClientErrors(t *testing.T) {
	h := &RemediationTaskHandler{logger: logger.NewNop()}
	for _, tc := range []struct {
		err  error
		code string
	}{
		{fmt.Errorf("%w: request touches 600 rows, ceiling 500 (acquire operator approval)", finding.ErrBulkTooLarge), "BULK_TOO_LARGE"},
		{fmt.Errorf("%w: would use 40 of 10 remaining this hour", finding.ErrBulkBudgetExceeded), "BULK_BUDGET_EXCEEDED"},
	} {
		w := httptest.NewRecorder()
		h.handleError(w, tc.err)
		var body struct {
			Code string `json:"code"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		if w.Code != http.StatusBadRequest || body.Code != tc.code {
			t.Errorf("%v: status %d code %q, want 400 %s", tc.err, w.Code, body.Code, tc.code)
		}
	}
}
