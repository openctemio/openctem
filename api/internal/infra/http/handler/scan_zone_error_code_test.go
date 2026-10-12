package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	scansvc "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scanzone"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func errorBody(t *testing.T, rec *httptest.ResponseRecorder) (code, message string) {
	t.Helper()
	var b struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &b); err != nil {
		t.Fatalf("body %q: %v", rec.Body.String(), err)
	}
	return b.Code, b.Message
}

// The scan-zone contract promises its domain codes in the error body, so a
// client can tell a duplicate name from a second default zone or a zone in use.
func TestScanZoneHandler_ErrorBodyCarriesContractCode(t *testing.T) {
	h := &ScanZoneHandler{logger: logger.NewNop()}
	cases := []struct {
		err    error
		status int
		code   string
	}{
		{scanzone.ErrZoneNameTaken, http.StatusConflict, "ZONE_NAME_TAKEN"},
		{scanzone.ErrDefaultZoneTaken, http.StatusConflict, "DEFAULT_ZONE_EXISTS"},
		{scanzone.ErrZoneInUse, http.StatusConflict, "ZONE_IN_USE"},
		{scanzone.ErrZoneSelectedByScans(2), http.StatusConflict, "ZONE_IN_USE"},
		{scanzone.ErrTooManyZones, http.StatusBadRequest, "TOO_MANY_ZONES"},
		{shared.NewDomainError("VALIDATION", "bad range", shared.ErrValidation), http.StatusBadRequest, "BAD_REQUEST"},
		{scanzone.ErrZoneNotFound, http.StatusNotFound, "NOT_FOUND"},
	}
	for _, tc := range cases {
		rec := httptest.NewRecorder()
		h.handleError(rec, tc.err)
		code, msg := errorBody(t, rec)
		if rec.Code != tc.status || code != tc.code || msg == "" {
			t.Errorf("%v: status=%d code=%q message=%q, want %d %s", tc.err, rec.Code, code, msg, tc.status, tc.code)
		}
	}
}

// Trigger refusals reach the client with their code, as the contract says.
func TestScanHandler_TriggerRefusalKeepsItsCode(t *testing.T) {
	h := &ScanHandler{logger: logger.NewNop()}
	for _, c := range []string{"NO_ZONE_COVERAGE", "ZONE_SPLIT_REQUIRED", "TOO_MANY_JOBS", "NO_TARGETS",
		"ALL_TARGETS_EXCLUDED", "PLATFORM_SENSOR_REFUSED", "SCAN_ZONE_NOT_FOUND",
		"NO_SENSOR_FOR_TOOL", "NO_SENSOR_AVAILABLE", "TOOL_NOT_FOUND", "TOOL_DISABLED", "TOOL_NOT_SCANNER"} {
		rec := httptest.NewRecorder()
		h.handleServiceError(rec, shared.NewDomainError(c, "refused: "+c, shared.ErrValidation))
		code, msg := errorBody(t, rec)
		if rec.Code != http.StatusBadRequest || code != c || msg != "refused: "+c {
			t.Errorf("%s: status=%d code=%q message=%q", c, rec.Code, code, msg)
		}
	}
	rec := httptest.NewRecorder()
	h.handleServiceError(rec, shared.NewDomainError("VALIDATION", "name is required", shared.ErrValidation))
	if code, _ := errorBody(t, rec); code != "BAD_REQUEST" {
		t.Errorf("generic validation code = %q, want BAD_REQUEST", code)
	}
}

// A NO_SENSOR_FOR_TOOL refusal carries the tool and the counts behind it.
func TestScanHandler_ToolUnavailableDetails(t *testing.T) {
	h := &ScanHandler{logger: logger.NewNop()}
	rec := httptest.NewRecorder()
	h.handleServiceError(rec, fmt.Errorf("failed to trigger scan: %w", &scansvc.ToolUnavailableError{
		Domain: shared.NewDomainError(scansvc.CodeNoSensorForTool, "No online sensor has semgrep", shared.ErrValidation),
		Tool:   "semgrep", Step: "sast", Status: "offline_only", SensorsTotal: 2,
	}))
	var b struct {
		Code    string                 `json:"code"`
		Message string                 `json:"message"`
		Details ToolUnavailableDetails `json:"details"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &b); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusBadRequest || b.Code != scansvc.CodeNoSensorForTool || b.Message != "No online sensor has semgrep" ||
		b.Details.Tool != "semgrep" || b.Details.Step != "sast" || b.Details.Status != "offline_only" || b.Details.SensorsTotal != 2 {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
}
