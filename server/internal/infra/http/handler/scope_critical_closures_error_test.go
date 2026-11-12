package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/openctem/server/internal/app/scope"
)

// A closing exclusion that would close critical, P0 or KEV findings without
// the confirm is a 409 EXCLUSION_CLOSES_CRITICAL_FINDINGS whose details
// carry the count, so the client can ask the person and resend with
// confirm_critical (research/438).
func TestWriteScopeEntryError_CriticalClosures(t *testing.T) {
	rec := httptest.NewRecorder()
	if !writeScopeEntryError(rec, fmt.Errorf("create: %w", &scope.CriticalClosuresError{Count: 3})) {
		t.Fatal("not handled")
	}
	if rec.Code != http.StatusConflict {
		t.Fatalf("status %d, want 409", rec.Code)
	}
	var body struct {
		Code    string `json:"code"`
		Details struct {
			CriticalFindings int `json:"critical_findings"`
		} `json:"details"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Code != scope.CodeClosesCriticalFindings || body.Details.CriticalFindings != 3 {
		t.Fatalf("body %s", rec.Body.String())
	}
}
