package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/validator"
)

// F-14: verify handleError never leaks wrapped internal errors to the
// client. This is enforced by CLAUDE.md Security Checklist §2 — an
// error chain like `failed to update capability: duplicate key violates
// unique constraint "capabilities_name_key" (SQLSTATE 23505)` must NOT
// reach the response body.
//
// Every case here:
//   1. Invokes handleError with a wrapped sentinel domain error whose
//      inner text contains a recognisable "leak marker".
//   2. Asserts the response JSON body does NOT contain the leak marker.
//   3. Asserts the HTTP status matches the sentinel's expected mapping.

const leakMarker = "LEAKED_INTERNAL_DETAIL_123"

// assertNoLeak is the single assertion that matters for F-14.
func assertNoLeak(t *testing.T, body string) {
	t.Helper()
	if strings.Contains(body, leakMarker) {
		t.Fatalf("handleError leaked internal error text to client: %q", body)
	}
}

func runHandleError(t *testing.T, inner error) (*httptest.ResponseRecorder, string) {
	t.Helper()
	h := NewCapabilityHandler(nil, validator.New(), logger.NewNop())

	rec := httptest.NewRecorder()
	h.handleError(rec, inner, "capability")

	raw := rec.Body.String()
	// Best-effort: decode, ignore shape — we only care about body string.
	var obj map[string]any
	_ = json.Unmarshal([]byte(raw), &obj)
	return rec, raw
}

func TestHandleError_Conflict_NoLeak(t *testing.T) {
	err := fmt.Errorf("%w: duplicate key %s", shared.ErrConflict, leakMarker)
	rec, body := runHandleError(t, err)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rec.Code)
	}
	assertNoLeak(t, body)
}

func TestHandleError_Validation_NoLeak(t *testing.T) {
	err := fmt.Errorf("%w: %s", shared.ErrValidation, leakMarker)
	rec, body := runHandleError(t, err)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	assertNoLeak(t, body)
}

func TestHandleError_Forbidden_NoLeak(t *testing.T) {
	err := fmt.Errorf("%w: %s", shared.ErrForbidden, leakMarker)
	rec, body := runHandleError(t, err)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	assertNoLeak(t, body)
}

func TestHandleError_NotFound_UsesResourceName(t *testing.T) {
	err := fmt.Errorf("%w: %s", shared.ErrNotFound, leakMarker)
	rec, body := runHandleError(t, err)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	// NotFound uses the resource name, not the error text — so the
	// marker from inside the error must not be in the body.
	assertNoLeak(t, body)
}
