package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

type recordingOrgReader struct{ got admin.OrganizationFilter }

func (r *recordingOrgReader) ListOrganizations(_ context.Context, f admin.OrganizationFilter) ([]*admin.Organization, int, error) {
	r.got = f
	return nil, 0, nil
}
func (r *recordingOrgReader) GetOrganization(context.Context, shared.ID) (*admin.Organization, error) {
	return nil, shared.ErrNotFound
}

// The organization list passes the owner filter through, and refuses values
// it does not know (no free-form SQL input reaches the query).
func TestAdminOrganizationListFilterParams(t *testing.T) {
	cases := []struct {
		query string
		want  int
		owner string
	}{
		{"", http.StatusOK, ""},
		{"owner=none", http.StatusOK, admin.OrganizationOwnerNone},
		{"owner=present", http.StatusOK, admin.OrganizationOwnerPresent},
		{"owner=maybe", http.StatusBadRequest, ""},
		{"owner=none'--", http.StatusBadRequest, ""},
	}
	for _, c := range cases {
		reader := &recordingOrgReader{}
		h := NewAdminOrganizationHandler(reader, nil, nil, validator.New(), logger.NewNop())
		rec := httptest.NewRecorder()
		h.List(rec, httptest.NewRequest(http.MethodGet, "/api/v1/admin/tenants?"+c.query, nil))
		if rec.Code != c.want {
			t.Fatalf("%q: status %d, want %d (%s)", c.query, rec.Code, c.want, rec.Body.String())
		}
		if c.want == http.StatusOK && reader.got.Owner != c.owner {
			t.Fatalf("%q: filter %+v", c.query, reader.got)
		}
	}
}
