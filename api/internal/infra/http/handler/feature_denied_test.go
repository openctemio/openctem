package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/limits"
)

// A change refused by the plan answers 403 FEATURE_NOT_INCLUDED naming the
// feature in words; an unreadable plan answers 503; other errors pass.
func TestWriteFeatureDenied(t *testing.T) {
	w := httptest.NewRecorder()
	if !WriteFeatureDenied(w, &limits.ErrFeatureDenied{Feature: limits.FeatureSSOConnections}) {
		t.Fatal("a feature refusal must be written")
	}
	var body struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if w.Code != http.StatusForbidden || body.Code != "FEATURE_NOT_INCLUDED" || !strings.Contains(body.Message, "Single sign-on connections") {
		t.Fatalf("got %d %+v", w.Code, body)
	}
	w = httptest.NewRecorder()
	if !WriteFeatureDenied(w, &limits.ErrFeatureDenied{Feature: limits.FeatureSCIM, Unavailable: true}) || w.Code != http.StatusServiceUnavailable {
		t.Fatalf("unavailable: %d", w.Code)
	}
	if WriteFeatureDenied(httptest.NewRecorder(), errors.New("other")) {
		t.Fatal("other errors are not feature refusals")
	}
}
