package handler

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/exposure"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The four-eyes refusals answer 403/409/404, never 500.
func TestWriteDispositionError(t *testing.T) {
	cases := []struct {
		err  error
		want int
	}{
		{fmt.Errorf("wrap: %w", exposure.ErrDispositionSelfApproval), http.StatusForbidden},
		{exposure.ErrDispositionConflict, http.StatusConflict},
		{exposure.ErrNoPendingDisposition, http.StatusNotFound},
		{fmt.Errorf("%w: decided by someone else", shared.ErrConflict), http.StatusConflict},
		{fmt.Errorf("%w: needs a signed-in approver", shared.ErrForbidden), http.StatusForbidden},
	}
	for _, c := range cases {
		w := httptest.NewRecorder()
		if !writeDispositionError(w, c.err) || w.Code != c.want {
			t.Errorf("%v: got %d, want %d", c.err, w.Code, c.want)
		}
	}
	if writeDispositionError(httptest.NewRecorder(), errors.New("other")) {
		t.Error("an unrelated error was handled")
	}
}
