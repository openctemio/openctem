package handler

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/api/internal/app/template"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// A template source whose server answered 404 made POST
// /template-sources/{id}/sync return 500.
func TestTemplateSyncError_Status(t *testing.T) {
	h := &TemplateSourceHandler{logger: logger.NewNop()}
	for name, tc := range map[string]struct {
		err  error
		want int
	}{
		"upstream 404": {fmt.Errorf("%w: %w", template.ErrSourceFetchFailed, errors.New("unexpected status 404")), http.StatusBadGateway},
		"unknown":      {shared.ErrNotFound, http.StatusNotFound},
		"refused":      {shared.NewDomainError("SYNC_IN_PROGRESS", "source is already being synced", nil), http.StatusBadRequest},
		"other":        {errors.New("db down"), http.StatusInternalServerError},
	} {
		rec := httptest.NewRecorder()
		h.writeSyncError(rec, "id", tc.err)
		if rec.Code != tc.want {
			t.Errorf("%s: got %d, want %d", name, rec.Code, tc.want)
		}
	}
}
