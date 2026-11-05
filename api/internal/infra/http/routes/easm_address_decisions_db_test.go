package routes

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	easmapp "github.com/openctemio/openctem/api/internal/app/easm"
	scopeapp "github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Bulk decisions on the addresses card through the real routes
// (research/425). SECURITY: only addresses on the caller's own card are
// written; another organization's caller and a caller without the
// permission write nothing; each decision is one audit event; a "not ours"
// network answer is the organization's own row.
func TestEASMAddressDecisions_DB(t *testing.T) {
	var scopeSvc *scopeapp.Service
	changeAuditExtraHandlers = func(hs *Handlers, db *postgres.DB) {
		log := logger.NewNop()
		attr := postgres.NewAttributionRepository(db)
		gate := easmapp.NewActiveGate(attr, postgres.NewAssetRepository(db), scopeSvc, postgres.NewVerifiedDomainNameRepository(db))
		org := func(context.Context, shared.ID) (string, error) { return "Decide Org", nil }
		declined := postgres.NewEASMDeclinedNetworkRepository(db)
		cards := easmapp.NewSuggestionService(attr, gate, nil, org, nil)
		cards.SetDeclined(declined)
		review := easmapp.NewReviewService(attr, nil)
		hs.EASM = handler.NewEASMHandler(easmapp.NewService(postgres.NewEASMSummaryRepository(db), nil), log).
			SetReview(review, auditapp.NewAuditService(postgres.NewAuditRepository(db), log)).
			SetSuggestions(cards).
			SetAddressDecisions(easmapp.NewAddressDecisions(cards, scopeSvc, review, nil, declined, nil))
	}
	t.Cleanup(func() { changeAuditExtraHandlers = nil })
	h := newChangeAuditHarness(t, func(s *scopeapp.Service, _ *handler.ScopeHandler, _ *postgres.DB) { scopeSvc = s })
	orgID, otherID := h.tenant(), h.tenant()
	admin := h.member(orgID, "admin")
	viewer := h.member(orgID, "viewer")
	otherAdmin := h.member(otherID, "admin")

	h.expect(admin, http.MethodPost, "/api/v1/scope/targets", `{"target_type":"domain","pattern":"*.decide-db.example"}`, http.StatusCreated)
	asset := func(tenant, name, typ, props string) string {
		var id string
		if err := h.db.QueryRowContext(context.Background(), `INSERT INTO assets (tenant_id, name, asset_type, status, properties) VALUES ($1, $2, $3, 'active', $4::jsonb) RETURNING id`,
			tenant, name, typ, props).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	behind := func(tenant, nameID, ipID string) {
		h.exec(`INSERT INTO asset_attributions (asset_id, tenant_id, state, confidence) VALUES ($1, $2, 'needs_review', 60)`, ipID, tenant)
		h.exec(`INSERT INTO asset_relationships (tenant_id, source_asset_id, target_asset_id, relationship_type) VALUES ($1, $2, $3, 'resolves_to')`,
			tenant, nameID, ipID)
	}
	www := asset(orgID, "www.decide-db.example", "subdomain", `{}`)
	ip := asset(orgID, "203.0.113.90", "ip_address", `{}`)
	behind(orgID, www, ip)
	mail := asset(orgID, "mail.decide-db.example", "subdomain", `{}`)
	foreign := asset(orgID, "192.0.2.77", "ip_address", `{"asn": 7552, "asn_org": "Other Telecom"}`)
	behind(orgID, mail, foreign)
	// An address of another organization that nothing of the caller's points at.
	asset(otherID, "198.51.100.66", "ip_address", `{}`)

	count := func(q string, args ...any) int {
		t.Helper()
		var n int
		if err := h.db.QueryRowContext(context.Background(), q, args...).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	entries := func(tenant, pattern string) int {
		return count(`SELECT COUNT(*) FROM scope_targets WHERE tenant_id = $1 AND pattern = '`+pattern+`'`, tenant)
	}
	add := `{"addresses":["203.0.113.90"]}`
	h.expect(viewer, http.MethodPost, "/api/v1/easm/suggestions/addresses/add", add, http.StatusForbidden)
	body := h.expect(otherAdmin, http.MethodPost, "/api/v1/easm/suggestions/addresses/add", add, http.StatusBadRequest)
	if !strings.Contains(body, "DECISION_NOT_PENDING") {
		t.Fatalf("other org: %s", body)
	}
	h.expect(admin, http.MethodPost, "/api/v1/easm/suggestions/addresses/add", `{"addresses":["203.0.113.90","198.51.100.66"]}`, http.StatusBadRequest)
	if entries(orgID, "203.0.113.90")+entries(otherID, "203.0.113.90")+entries(orgID, "198.51.100.66") != 0 {
		t.Fatal("a refused decision wrote an entry")
	}
	// The shared address (another organization's network) is never in a bulk.
	h.expect(admin, http.MethodPost, "/api/v1/easm/suggestions/addresses/add", `{"addresses":["203.0.113.90","192.0.2.77"]}`, http.StatusBadRequest)

	var res easmapp.AddressAddResult
	if err := json.Unmarshal([]byte(h.expect(admin, http.MethodPost, "/api/v1/easm/suggestions/addresses/add", add, http.StatusOK)), &res); err != nil {
		t.Fatal(err)
	}
	if res.Created != 1 || entries(orgID, "203.0.113.90") != 1 {
		t.Fatalf("add %+v", res)
	}
	if n := count(`SELECT COUNT(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'easm_address_decision.added'`, orgID); n != 1 {
		t.Fatalf("decision audit events %d", n)
	}
	// Added: no longer pending, so a second add is refused.
	h.expect(admin, http.MethodPost, "/api/v1/easm/suggestions/addresses/add", add, http.StatusBadRequest)

	// "Is this network yours?" No: the organization's own row, the address rejected.
	h.expect(otherAdmin, http.MethodPost, "/api/v1/easm/suggestions/networks/not-ours", `{"key":"other_network:AS7552"}`, http.StatusBadRequest)
	var ans easmapp.NetworkAnswerResult
	if err := json.Unmarshal([]byte(h.expect(admin, http.MethodPost, "/api/v1/easm/suggestions/networks/not-ours", `{"key":"other_network:AS7552"}`, http.StatusOK)), &ans); err != nil {
		t.Fatal(err)
	}
	if ans.DeclinedID == "" || ans.Rejected == nil || len(ans.Rejected.AssetIDs) != 1 {
		t.Fatalf("not ours %+v", ans)
	}
	if n := count(`SELECT COUNT(*) FROM asset_attributions WHERE tenant_id = $1 AND asset_id = '`+foreign+`' AND state = 'rejected'`, orgID); n != 1 {
		t.Fatal("the network's address was not rejected")
	}
	h.expect(otherAdmin, http.MethodDelete, "/api/v1/easm/suggestions/networks/declined/"+ans.DeclinedID, "", http.StatusNotFound)
	h.expect(admin, http.MethodDelete, "/api/v1/easm/suggestions/networks/declined/"+ans.DeclinedID, "", http.StatusNoContent)
	if n := count(`SELECT COUNT(*) FROM easm_declined_networks WHERE tenant_id = $1`, orgID); n != 0 {
		t.Fatalf("undo left %d rows", n)
	}
}
