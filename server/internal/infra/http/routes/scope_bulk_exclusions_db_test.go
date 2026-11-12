package routes

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	scopeapp "github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// unrestrictedScope resolves every caller to the whole tenant (the data
// scope negative is in the repository test).
type unrestrictedScope struct{}

func (unrestrictedScope) Resolve(context.Context, shared.ID) (*shared.DataScope, error) {
	return nil, nil
}

// Mark out of scope in bulk (research/124, RFC-054 §15.8): the preview counts
// only the caller's tenant's assets, the bulk add needs scope:write and
// answers per item, and the undo is the existing bulk delete.
func TestScopeBulkExclusions_DB(t *testing.T) {
	h := newChangeAuditHarness(t, func(s *scopeapp.Service, _ *handler.ScopeHandler, db *postgres.DB) {
		cov := postgres.NewScopeCoverageRepository(db)
		s.SetCoverage(cov, unrestrictedScope{})
		s.SetExclusionMatches(cov)
	})
	org, other := h.tenant(), h.tenant()
	owner := h.member(org, "owner")
	reader := h.member(org, "viewer")
	h.customRoleMember(reader, org, permission.ScopeRead)
	h.mintToken(&reader, org)
	otherOwner := h.member(other, "owner")
	asset := func(tenant, name, typ string) {
		h.exec(`INSERT INTO assets (tenant_id, name, asset_type, status) VALUES ($1, $2, $3, 'active')`, tenant, name, typ)
	}
	asset(org, "a.inv-bulk.example", "subdomain")
	asset(org, "b.inv-bulk.example", "subdomain")
	asset(org, "203.0.113.5", "ip_address")
	asset(other, "c.inv-bulk.example", "subdomain")

	preview := func(u policyUser, body string) handler.PreviewScopeExclusionsResponse {
		t.Helper()
		var out handler.PreviewScopeExclusionsResponse
		if err := json.Unmarshal([]byte(h.expect(u, http.MethodPost, "/api/v1/scope/exclusions/bulk/preview", body, http.StatusOK)), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	items := `{"items":[{"exclusion_type":"domain","pattern":"*.inv-bulk.example"},{"exclusion_type":"cidr","pattern":"203.0.113.0/24"},{"exclusion_type":"scanner","pattern":"nuclei"}]}`
	p := preview(reader, items)
	if len(p.Items) != 3 || p.Items[0].Matched != 2 || p.Items[1].Matched != 1 || p.Items[2].Code == "" {
		t.Fatalf("preview = %+v", p.Items)
	}
	for _, n := range p.Items[0].Sample {
		if strings.HasPrefix(n, "c.") {
			t.Fatal("the preview named another tenant's asset")
		}
	}
	// The other tenant sees only its own asset.
	if q := preview(otherOwner, items); q.Items[0].Matched != 1 || q.Items[1].Matched != 0 {
		t.Fatalf("other tenant preview = %+v", q.Items)
	}

	// scope:read alone may not add exclusions.
	h.expect(reader, http.MethodPost, "/api/v1/scope/exclusions/bulk", items, http.StatusForbidden)

	var res handler.BulkCreateScopeExclusionsResponse
	body := `{"items":[{"exclusion_type":"domain","pattern":"*.inv-bulk.example"},{"exclusion_type":"domain","pattern":"*.inv-bulk.example"},{"exclusion_type":"scanner","pattern":"nuclei"}]}`
	if err := json.Unmarshal([]byte(h.expect(owner, http.MethodPost, "/api/v1/scope/exclusions/bulk", body, http.StatusOK)), &res); err != nil {
		t.Fatal(err)
	}
	if res.Created != 1 || res.Existing != 1 || res.Refused != 1 || res.Results[0].ID == "" || res.Results[0].Status == "" {
		t.Fatalf("bulk = %+v", res)
	}
	var n int
	if err := h.db.QueryRow(`SELECT count(*) FROM scope_exclusions WHERE pattern = '*.inv-bulk.example' AND tenant_id = $1`, other).Scan(&n); err != nil || n != 0 {
		t.Fatalf("exclusion written for another tenant: %d %v", n, err)
	}
	if rows := h.auditRows(org, "scope_exclusion.created"); len(rows) == 0 {
		t.Fatal("no audit event for the bulk exclusion")
	}
	// The other tenant cannot undo it.
	undo := `{"exclusion_ids":["` + res.Results[0].ID + `"]}`
	h.expect(otherOwner, http.MethodPost, "/api/v1/scope/exclusions/bulk/delete", undo, http.StatusOK)
	if err := h.db.QueryRow(`SELECT count(*) FROM scope_exclusions WHERE id = $1`, res.Results[0].ID).Scan(&n); err != nil || n != 1 {
		t.Fatalf("another tenant removed the exclusion: %d %v", n, err)
	}
	// Undo: the existing bulk delete.
	h.expect(owner, http.MethodPost, "/api/v1/scope/exclusions/bulk/delete", undo, http.StatusOK)
	if err := h.db.QueryRow(`SELECT count(*) FROM scope_exclusions WHERE id = $1`, res.Results[0].ID).Scan(&n); err != nil || n != 0 {
		t.Fatalf("undo left the exclusion: %d %v", n, err)
	}
}
