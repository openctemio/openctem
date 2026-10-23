package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// A findings read that ran past its statement timeout answers 503
// QUERY_TIMEOUT, not a 500; other errors are left to the caller.
func TestWriteFindingQueryTimeout(t *testing.T) {
	w := httptest.NewRecorder()
	if !writeFindingQueryTimeout(w, fmt.Errorf("count: %w", vulnerability.ErrFindingQueryTimeout)) {
		t.Fatal("timeout not handled")
	}
	var body struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if w.Code != http.StatusServiceUnavailable || body.Code != "QUERY_TIMEOUT" {
		t.Fatalf("timeout = %d %s, want 503 QUERY_TIMEOUT", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	if writeFindingQueryTimeout(w, errors.New("boom")) || w.Body.Len() != 0 {
		t.Fatal("a non-timeout error was answered as a timeout")
	}
}
