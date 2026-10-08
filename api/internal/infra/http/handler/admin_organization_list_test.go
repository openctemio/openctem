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

// The organization list passes the owner and plan filters through, and
// refuses values it does not know (no free-form SQL input reaches the query).
func TestAdminOrganizationListFilterParams(t *testing.T) {
	cases := []struct {
		query      string
		want       int
		owner, pln string
	}{
		{"", http.StatusOK, "", ""},
		{"owner=none&plan=free", http.StatusOK, admin.OrganizationOwnerNone, "free"},
		{"owner=present&plan=enterprise", http.StatusOK, admin.OrganizationOwnerPresent, "enterprise"},
		{"owner=maybe", http.StatusBadRequest, "", ""},
		{"plan=gold", http.StatusBadRequest, "", ""},
		{"plan=free'--", http.StatusBadRequest, "", ""},
	}
	for _, c := range cases {
		reader := &recordingOrgReader{}
		h := NewAdminOrganizationHandler(reader, nil, nil, validator.New(), logger.NewNop())
		rec := httptest.NewRecorder()
		h.List(rec, httptest.NewRequest(http.MethodGet, "/api/v1/admin/tenants?"+c.query, nil))
		if rec.Code != c.want {
			t.Fatalf("%q: status %d, want %d (%s)", c.query, rec.Code, c.want, rec.Body.String())
		}
		if c.want == http.StatusOK && (reader.got.Owner != c.owner || reader.got.Plan != c.pln) {
			t.Fatalf("%q: filter %+v", c.query, reader.got)
		}
	}
}
