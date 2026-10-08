package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// A scan whose workflow is missing (or another organization's) is answered
// "Scan workflow not found", not "Scan not found": the scan being created
// is not what is missing. A missing scan keeps its own message.
func TestScanHandler_WorkflowNotFoundIsNamed(t *testing.T) {
	h := &ScanHandler{logger: logger.NewNop()}
	for _, c := range []struct {
		err      error
		code     string
		messageS string
	}{
		{fmt.Errorf("create: %w", scanworkflow.ErrScanWorkflowNotFound), "SCAN_WORKFLOW_NOT_FOUND", "Scan workflow not found"},
		{shared.ErrNotFound, "NOT_FOUND", "Scan not found"},
	} {
		rec := httptest.NewRecorder()
		h.handleServiceError(rec, c.err)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%v: status %d, want 404", c.err, rec.Code)
		}
		var body struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if body.Code != c.code || body.Message != c.messageS {
			t.Errorf("%v: %+v, want %s %q", c.err, body, c.code, c.messageS)
		}
	}
}
