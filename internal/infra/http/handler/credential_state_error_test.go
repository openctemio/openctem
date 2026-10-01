package handler

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/api/pkg/domain/exposure"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// Every failed credential action used to answer 404 "credential not found
// not found" and log at ERROR, including a refused state transition.
func TestCredentialStateChangeError_Status(t *testing.T) {
	h := &CredentialImportHandler{logger: logger.NewNop()}
	ev, err := exposure.NewExposureEvent(shared.NewID(), exposure.EventTypeCredentialLeaked, exposure.SeverityHigh, "a@b.c", "src", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := ev.Resolve(shared.NewID(), ""); err != nil {
		t.Fatal(err)
	}
	transition := ev.Resolve(shared.NewID(), "") // resolved -> resolved is refused

	for name, tc := range map[string]struct {
		err  error
		want int
	}{
		"unknown credential":      {exposure.NewExposureEventNotFoundError("x"), http.StatusNotFound},
		"other tenant":            {shared.ErrNotFound, http.StatusNotFound},
		"malformed id":            {fmt.Errorf("%w: invalid credential id", shared.ErrValidation), http.StatusBadRequest},
		"invalid transition":      {transition, http.StatusConflict},
		"unexpected (db) failure": {errors.New("connection refused"), http.StatusInternalServerError},
	} {
		rec := httptest.NewRecorder()
		h.writeStateChangeError(rec, "resolve", "id", tc.err)
		if rec.Code != tc.want {
			t.Errorf("%s: got %d, want %d (%s)", name, rec.Code, tc.want, rec.Body.String())
		}
	}
	if !errors.Is(transition, shared.ErrValidation) {
		t.Error("a refused transition must still be a validation error for other callers")
	}
}
