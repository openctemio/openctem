package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	scansvc "github.com/openctemio/openctem/server/internal/app/scan"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// A trigger whose scan was found but whose workflow, or a reference of a
// step, was not is answered with its own code, never "Scan not found" (the
// console toasted "Scan not found" on Run now for a scan it was showing).
func TestScanHandler_TriggerReferenceNotFoundIsNamed(t *testing.T) {
	h := &ScanHandler{logger: logger.NewNop()}
	for _, c := range []struct {
		err  error
		code string
	}{
		{shared.NewDomainError(scansvc.CodePipelineNotFound, "This scan's workflow was not found: it may have been deleted. Edit the scan and choose another workflow.", shared.ErrNotFound), "PIPELINE_NOT_FOUND"},
		{fmt.Errorf("trigger: %w", shared.NewDomainError(scansvc.CodeScanDependencyMissing, "Something this scan uses was not found.", shared.ErrNotFound)), "SCAN_DEPENDENCY_MISSING"},
		// A missing scan, and any other not-found, keep the plain answer.
		{shared.ErrNotFound, "NOT_FOUND"},
		{shared.NewDomainError("SOMETHING_ELSE", "x", shared.ErrNotFound), "NOT_FOUND"},
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
		if body.Code != c.code {
			t.Errorf("%v: code %q, want %q", c.err, body.Code, c.code)
		}
		if c.code != "NOT_FOUND" && body.Message == "Scan not found" {
			t.Errorf("%v: message %q names the scan", c.err, body.Message)
		}
	}
}
