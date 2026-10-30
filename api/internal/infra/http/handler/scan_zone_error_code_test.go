package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
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

// The target refusals a run start answers keep their code too: the live
// console showed "BAD_REQUEST" for a scan whose targets were unconfirmed,
// with no way to tell what to fix.
func TestScanHandler_TargetRefusalKeepsItsCode(t *testing.T) {
	h := &ScanHandler{logger: logger.NewNop()}
	for _, c := range []string{"ALL_TARGETS_UNCONFIRMED", "NO_COMPATIBLE_TARGETS", "TIER_EXCEEDS",
		"INTERNAL_TARGET_OUTSIDE_ZONES", "NO_RESOLVING_TARGETS", "INTENSITY_EXCEEDED", "LIVENESS_NEEDS_HOST_DISCOVERY"} {
		rec := httptest.NewRecorder()
		h.handleServiceError(rec, fmt.Errorf("trigger: %w", shared.NewDomainError(c, "refused: "+c, shared.ErrValidation)))
		code, msg := errorBody(t, rec)
		if rec.Code != http.StatusBadRequest || code != c || msg != "refused: "+c {
			t.Errorf("%s: status=%d code=%q message=%q", c, rec.Code, code, msg)
		}
	}
}

// A governed scan's refused run says it needs (or waits for) an approval;
// any other forbidden stays a plain 403 with no message.
func TestScanHandler_ApprovalRefusalKeepsItsCode(t *testing.T) {
	h := &ScanHandler{logger: logger.NewNop()}
	for _, c := range []string{"SCAN_APPROVAL_REQUIRED", "SCAN_APPROVAL_PENDING"} {
		rec := httptest.NewRecorder()
		h.handleServiceError(rec, shared.NewDomainError(c, "needs approval", shared.ErrForbidden))
		code, msg := errorBody(t, rec)
		if rec.Code != http.StatusForbidden || code != c || msg != "needs approval" {
			t.Errorf("%s: status=%d code=%q message=%q", c, rec.Code, code, msg)
		}
	}
	rec := httptest.NewRecorder()
	h.handleServiceError(rec, shared.NewDomainError("SOMETHING_INTERNAL", "secret detail", shared.ErrForbidden))
	code, msg := errorBody(t, rec)
	if rec.Code != http.StatusForbidden || code == "SOMETHING_INTERNAL" || msg == "secret detail" {
		t.Errorf("other forbidden: status=%d code=%q message=%q, want a plain 403", rec.Code, code, msg)
	}
}

// A trigger with nothing to scan reaches the client with the real reasons,
// the per-target refusals, and no scan name or id: the quick scan's name
// ("Quick Scan - <time>-<hex>") never appears in what the user reads.
func TestScanHandler_NothingToScanCarriesReasonsAndNoIDs(t *testing.T) {
	h := &ScanHandler{logger: logger.NewNop()}
	err := fmt.Errorf("failed to trigger scan: %w", scansvc.NothingToScanError([]scanzone.Uncovered{
		{Target: "go.example.com", Reason: "does not resolve in DNS", Kind: scanzone.KindUnresolved},
	}))
	rec := httptest.NewRecorder()
	h.handleServiceError(rec, err)
	var b struct {
		Code    string `json:"code"`
		Message string `json:"message"`
		Details struct {
			Refused []struct {
				Target string `json:"target"`
				Code   string `json:"code"`
			} `json:"refused"`
		} `json:"details"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &b); err != nil {
		t.Fatalf("body %q: %v", rec.Body.String(), err)
	}
	if rec.Code != http.StatusBadRequest || b.Code != scansvc.CodeNoResolvingTargets {
		t.Fatalf("status=%d code=%q, want 400 %s", rec.Code, b.Code, scansvc.CodeNoResolvingTargets)
	}
	if b.Message != "Nothing to scan: go.example.com does not resolve in DNS. Next: fix the DNS record, or scan the address instead." {
		t.Errorf("message = %q", b.Message)
	}
	if len(b.Details.Refused) != 1 || b.Details.Refused[0].Code != "unresolved" || b.Details.Refused[0].Target != "go.example.com" {
		t.Errorf("details = %+v", b.Details)
	}
	for _, leak := range []string{"Quick Scan", "scan \"", "zone"} {
		if strings.Contains(rec.Body.String(), leak) {
			t.Errorf("body carries %q: %s", leak, rec.Body.String())
		}
	}
	if regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-`).MatchString(b.Message) {
		t.Errorf("message carries a UUID: %q", b.Message)
	}
}
