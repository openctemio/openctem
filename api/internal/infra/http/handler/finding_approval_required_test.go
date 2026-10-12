package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

// Setting false_positive / accepted / accepted_risk directly is refused
// because those need an approver. The refusal used to come back as a bare
// 403 "Access denied", indistinguishable from a missing permission, so the
// UI could not tell the user what to do. It must carry its own code and say
// which permission the approver needs.
func TestHandleServiceError_ApprovalRequired(t *testing.T) {
	h := NewVulnerabilityHandler(nil, validator.New(), logger.NewNop())
	err := fmt.Errorf("update status: %w", &vulnerability.ApprovalRequiredError{Status: vulnerability.FindingStatusFalsePositive})

	rec := httptest.NewRecorder()
	h.handleServiceError(rec, err, "Finding")

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	var body struct {
		Code    string         `json:"code"`
		Message string         `json:"message"`
		Details map[string]any `json:"details"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v (%s)", err, rec.Body.String())
	}
	if body.Code != "APPROVAL_REQUIRED" {
		t.Fatalf("code = %q, want APPROVAL_REQUIRED", body.Code)
	}
	if !strings.Contains(body.Message, "findings:approve") || !strings.Contains(body.Message, "false positive") {
		t.Fatalf("message %q must name the status and the approver permission", body.Message)
	}
	if body.Details["required_permission"] != "findings:approve" || body.Details["status"] != "false_positive" {
		t.Fatalf("details = %v", body.Details)
	}
}
