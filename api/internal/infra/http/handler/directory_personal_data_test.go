package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/accessrequest"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	ardom "github.com/openctemio/openctem/api/pkg/domain/accessrequest"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	signupdom "github.com/openctemio/openctem/api/pkg/domain/signup"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type listingRepo struct {
	arMemRepo
	items []*ardom.Request
}

func (l *listingRepo) List(context.Context, ardom.Filter) ([]*ardom.Request, int, error) {
	return l.items, len(l.items), nil
}

func asAdminRole(r *http.Request, role admin.AdminRole) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), middleware.AdminRoleKey, string(role)))
}

// A read-only administrator reads the queue without the requesters' personal
// data: the address is masked and the free-text note is not sent. ops_admin
// and super_admin read both.
func TestAccessRequestList_MasksPersonalDataForReadonly(t *testing.T) {
	now := time.Now()
	repo := &listingRepo{items: []*ardom.Request{{
		ID: shared.NewID(), Company: "Acme", Email: "jane.doe@acme.example", Domain: "acme.example",
		Note: "we run the payroll for 400 people", Status: ardom.StatusPending, CreatedAt: now, ConfirmedAt: &now,
	}}}
	open := signupdom.Static{Mode: signupdom.ModeAdminOnly, RequestAccess: true}
	h := NewAccessRequestHandler(accessrequest.NewService(repo, open, nil, nil, nil, "https://app.example.com", logger.NewNop()), logger.NewNop())

	get := func(role admin.AdminRole) (AccessRequestListResponse, string) {
		t.Helper()
		rec := httptest.NewRecorder()
		h.List(rec, asAdminRole(httptest.NewRequest(http.MethodGet, "/api/v1/admin/access-requests", nil), role))
		var out AccessRequestListResponse
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &out) != nil || len(out.Data) != 1 {
			t.Fatalf("%s: %d %s", role, rec.Code, rec.Body.String())
		}
		return out, rec.Body.String()
	}

	out, body := get(admin.AdminRoleReadonly)
	if !out.Redacted || out.Data[0].Email != "j***@acme.example" || out.Data[0].Note != "" ||
		strings.Contains(body, "jane.doe") || strings.Contains(body, "payroll") {
		t.Fatalf("read-only list leaks personal data: %s", body)
	}
	if out.Data[0].Company != "Acme" || out.Data[0].Domain != "acme.example" || !out.Data[0].Confirmed {
		t.Fatalf("the rest of the row must stay: %+v", out.Data[0])
	}
	for _, role := range []admin.AdminRole{admin.AdminRoleOpsAdmin, admin.AdminRoleSuperAdmin} {
		out, _ := get(role)
		if out.Redacted || out.Data[0].Email != "jane.doe@acme.example" || out.Data[0].Note == "" {
			t.Fatalf("%s must see the request in full: %+v", role, out)
		}
	}
	// No role in the context (a route wired without the admin gate) is treated
	// as read-only, never as full access.
	rec := httptest.NewRecorder()
	h.List(rec, httptest.NewRequest(http.MethodGet, "/api/v1/admin/access-requests", nil))
	if strings.Contains(rec.Body.String(), "jane.doe") {
		t.Fatalf("a request without a role saw an address: %s", rec.Body.String())
	}
}

func TestMaskEmail(t *testing.T) {
	for in, want := range map[string]string{
		"jane.doe@acme.example": "j***@acme.example",
		"x@y.example":           "x***@y.example",
		"@y.example":            "***",
		"no-at-sign":            "***",
		"":                      "***",
	} {
		if got := maskEmail(in); got != want {
			t.Errorf("maskEmail(%q) = %q, want %q", in, got, want)
		}
	}
}

// The organization list never carries the owners' addresses; the single
// organization view does, for roles that may see personal data; a read-only
// administrator gets the owner count and neither addresses, domains nor the
// free-text suspension reason.
func TestOrganizationResponse_OwnerAddressesAndReason(t *testing.T) {
	o := &admin.Organization{
		Name: "Acme", Slug: "acme", OwnerEmails: []string{"b@acme.example", "a@acme.example", "c@other.example"},
		Status: "suspended", SuspendedReason: "abuse report 4411",
	}
	list := toAdminOrganizationResponse(o, true, false)
	if len(list.OwnerEmails) != 0 || list.OwnerCount != 3 ||
		strings.Join(list.OwnerDomains, ",") != "acme.example,other.example" || list.SuspendedReason == "" {
		t.Fatalf("list item: %+v", list)
	}
	one := toAdminOrganizationResponse(o, true, true)
	if len(one.OwnerEmails) != 3 || one.OwnerCount != 3 {
		t.Fatalf("single view: %+v", one)
	}
	ro := toAdminOrganizationResponse(o, false, true)
	if len(ro.OwnerEmails) != 0 || len(ro.OwnerDomains) != 0 || ro.OwnerCount != 3 || ro.SuspendedReason != "" {
		t.Fatalf("read-only view: %+v", ro)
	}
	if raw, _ := json.Marshal(ro); strings.Contains(string(raw), "acme.example") || strings.Contains(string(raw), "abuse") {
		t.Fatalf("read-only JSON leaks: %s", raw)
	}
	// Empty, never null.
	if raw, _ := json.Marshal(toAdminOrganizationResponse(&admin.Organization{}, false, false)); strings.Contains(string(raw), `"owner_emails":null`) || strings.Contains(string(raw), `"owner_domains":null`) {
		t.Fatalf("null arrays: %s", raw)
	}
}
