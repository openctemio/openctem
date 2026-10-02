package handler

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// accept-with-refresh with an unknown invitation token answered 500: the auth
// error mapper had no case for a lookup miss.
func TestHandleAuthError_NotFoundIs404(t *testing.T) {
	h := &LocalAuthHandler{logger: logger.NewNop()}
	rec := httptest.NewRecorder()
	h.handleAuthError(rec, fmt.Errorf("%w: invitation not found or expired", shared.ErrNotFound))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("got %d, want 404 (%s)", rec.Code, rec.Body.String())
	}
}
