package handler

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// The repository reports a taken dashboard name as shared.ErrConflict; the
// handler answers 409 with the reason, not 500.
func TestUserDashboardHandler_ErrorStatus(t *testing.T) {
	h := NewUserDashboardHandler(nil, logger.NewNop())
	cases := []struct {
		err  error
		want int
	}{
		{fmt.Errorf("%w: you already have a dashboard with this name", shared.ErrConflict), http.StatusConflict},
		{shared.ErrNotFound, http.StatusNotFound},
		{fmt.Errorf("%w: name is required", shared.ErrValidation), http.StatusBadRequest},
		{errors.New("boom"), http.StatusInternalServerError},
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		h.handleError(rec, c.err)
		if rec.Code != c.want {
			t.Fatalf("%v: status %d, want %d", c.err, rec.Code, c.want)
		}
		if c.want == http.StatusConflict && !strings.Contains(rec.Body.String(), "you already have a dashboard with this name") {
			t.Fatalf("conflict body %s", rec.Body.String())
		}
	}
}
