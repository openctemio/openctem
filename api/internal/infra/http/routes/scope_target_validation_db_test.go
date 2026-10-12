package routes

import (
	"net/http"
	"strings"
	"testing"
)

// A scope target the caller got wrong is answered 400 with what to write
// instead, never 500: a bare AWS account id, a malformed pattern, an unknown
// target type. An exclusion with an unknown type is 400 too.
func TestScopeTargetBadPatternIs400_DB(t *testing.T) {
	h := newChangeAuditHarness(t)
	tid := h.tenant()
	admin := h.member(tid, "admin")

	body := h.expect(admin, http.MethodPost, "/api/v1/scope/targets",
		`{"target_type":"cloud_account","pattern":"123456789012"}`, http.StatusBadRequest)
	if !strings.Contains(body, "AWS:123456789012") {
		t.Fatalf("no AWS:<id> hint in %s", body)
	}
	for _, b := range []string{
		`{"target_type":"cloud_account","pattern":"OCI:tenancy"}`,
		`{"target_type":"ip_address","pattern":"300.1.1.1"}`,
		`{"target_type":"url","pattern":"ftp://example.com"}`,
		`{"target_type":"not_a_type","pattern":"example.com"}`,
	} {
		h.expect(admin, http.MethodPost, "/api/v1/scope/targets", b, http.StatusBadRequest)
		h.expect(admin, http.MethodPost, "/api/v1/scope/targets/preview", b, http.StatusBadRequest)
	}
	h.expect(admin, http.MethodPost, "/api/v1/scope/exclusions",
		`{"exclusion_type":"not_a_type","pattern":"example.com","reason":"r"}`, http.StatusBadRequest)

	h.expect(admin, http.MethodPost, "/api/v1/scope/targets",
		`{"target_type":"cloud_account","pattern":"AWS:123456789012"}`, http.StatusCreated)
}
