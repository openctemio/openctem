package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A duplicate answers 409 with a code per kind and the existing row's id and
// status in the details, also when wrapped by the service.
func TestWriteScopeEntryError_Duplicate(t *testing.T) {
	id := shared.NewID()
	for _, tc := range []struct {
		err  error
		code string
	}{
		{scopedom.NewTargetDuplicate(scopedom.Existing{ID: id, Status: scopedom.StatusPending}), scopedom.CodeEntryExists},
		{fmt.Errorf("create: %w", scopedom.NewExclusionDuplicate(scopedom.Existing{ID: id, Status: scopedom.StatusPending})), scopedom.CodeExclusionExists},
	} {
		w := httptest.NewRecorder()
		if !writeScopeEntryError(w, tc.err) {
			t.Fatalf("%s: not handled", tc.code)
		}
		var body struct {
			Code    string                `json:"code"`
			Details ScopeDuplicateDetails `json:"details"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if w.Code != http.StatusConflict || body.Code != tc.code || body.Details.ID != id.String() || body.Details.Status != "pending" {
			t.Fatalf("got %d %+v, want 409 %s with id and status", w.Code, body, tc.code)
		}
	}
	// A plain conflict still falls through to the generic answer.
	if writeScopeEntryError(httptest.NewRecorder(), errors.New("x")) {
		t.Fatal("a plain error was handled as a duplicate")
	}
}
