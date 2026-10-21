package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	remediationapp "github.com/openctemio/openctem/api/internal/app/remediation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestOwnerAccessErrorAnswers422WithCountsOnly(t *testing.T) {
	h := NewRemediationTaskHandler(nil, nil)
	for _, c := range []struct {
		needsPerm bool
		code      string
	}{{true, "OWNER_NEEDS_ACCESS"}, {false, "OWNER_ACCESS_CONFIRMATION_REQUIRED"}} {
		w := httptest.NewRecorder()
		h.handleError(w, &remediationapp.OwnerAccessError{MissingFindings: 3, MissingAssets: 2, NeedsPermission: c.needsPerm})
		if w.Code != http.StatusUnprocessableEntity {
			t.Fatalf("status %d", w.Code)
		}
		var raw map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &raw)
		d, _ := raw["details"].(map[string]any)
		if raw["code"] != c.code || d["missing_findings"] != float64(3) || d["missing_assets"] != float64(2) || len(d) != 2 {
			t.Fatalf("body %s", w.Body.String())
		}
	}
}

func TestParseTaskUpdateAcceptsConsentFlag(t *testing.T) {
	raw := rawBody(t, `{"version":1,"assignee_user_id":"`+shared.NewID().String()+`","confirm_owner_access":true}`)
	if _, err := parseTaskUpdate(raw); err != nil {
		t.Fatal(err)
	}
	if !confirmOwnerAccess(raw) {
		t.Fatal("flag lost")
	}
	if confirmOwnerAccess(rawBody(t, `{"version":1}`)) {
		t.Fatal("flag set without the field")
	}
}

func TestOwnerAccessErrorIsAValidationError(t *testing.T) {
	var err error = &remediationapp.OwnerAccessError{}
	if !isValidation(err) {
		t.Fatal("must unwrap to a validation error")
	}
}

func isValidation(err error) bool { return errors.Is(err, shared.ErrValidation) }
