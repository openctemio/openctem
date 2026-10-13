package routes

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	easmapp "github.com/openctemio/openctem/api/internal/app/easm"
	scopeapp "github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// GET /api/v1/easm/suggestions through the real routes (research/117): the
// address behind an in-scope name is offered as one card and nothing is
// added by reading it; can_add follows the scope write permission; a caller
// without assets:read is refused; another organization sees none of it.
func TestEASMSuggestionCards_DB(t *testing.T) {
	var scopeSvc *scopeapp.Service
	changeAuditExtraHandlers = func(hs *Handlers, db *postgres.DB) {
		log := logger.NewNop()
		attr := postgres.NewAttributionRepository(db)
		gate := easmapp.NewActiveGate(attr, postgres.NewAssetRepository(db), scopeSvc, postgres.NewVerifiedDomainNameRepository(db))
		org := func(context.Context, shared.ID) (string, error) { return "Suggest Org", nil }
		hs.EASM = handler.NewEASMHandler(easmapp.NewService(postgres.NewEASMSummaryRepository(db), nil), log).
			SetReview(easmapp.NewReviewService(attr, nil), auditapp.NewAuditService(postgres.NewAuditRepository(db), log)).
			SetSuggestions(easmapp.NewSuggestionService(attr, gate, nil, org, nil))
	}
	t.Cleanup(func() { changeAuditExtraHandlers = nil })
	h := newChangeAuditHarness(t, func(s *scopeapp.Service, _ *handler.ScopeHandler, _ *postgres.DB) { scopeSvc = s })
	orgID, otherID := h.tenant(), h.tenant()
	admin := h.member(orgID, "admin")
	viewer := h.member(orgID, "viewer")
	noRead := h.member(orgID, "viewer")
	h.customRoleMember(noRead, orgID, permission.ScopeRead)
	h.mintToken(&noRead, orgID)
	otherAdmin := h.member(otherID, "admin")

	h.expect(admin, http.MethodPost, "/api/v1/scope/targets", `{"target_type":"domain","pattern":"*.cards-db.example"}`, http.StatusCreated)
	asset := func(tenant, name, typ string) string {
		var id string
		if err := h.db.QueryRow(`INSERT INTO assets (tenant_id, name, asset_type, status) VALUES ($1, $2, $3, 'active') RETURNING id`,
			tenant, name, typ).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	name := asset(orgID, "www.cards-db.example", "subdomain")
	ip := asset(orgID, "203.0.113.90", "ip_address")
	h.exec(`INSERT INTO asset_attributions (asset_id, tenant_id, state, confidence) VALUES ($1, $2, 'needs_review', 60)`, ip, orgID)
	h.exec(`INSERT INTO asset_relationships (tenant_id, source_asset_id, target_asset_id, relationship_type) VALUES ($1, $2, $3, 'resolves_to')`,
		orgID, name, ip)

	read := func(u policyUser) easmapp.SuggestionCards {
		t.Helper()
		var out easmapp.SuggestionCards
		if err := json.Unmarshal([]byte(h.expect(u, http.MethodGet, "/api/v1/easm/suggestions", "", http.StatusOK)), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	out := read(admin)
	if !out.CanAdd || len(out.Cards) != 1 || out.Cards[0].Kind != easmapp.CardAddressesBehindNames || out.Cards[0].Count != 1 ||
		out.Cards[0].Addresses[0].Address != "203.0.113.90" || out.Cards[0].UnknownNetworkCount != 1 || out.Total != 1 {
		t.Fatalf("admin cards %+v", out)
	}
	var n int
	_ = h.db.QueryRow(`SELECT count(*) FROM scope_targets WHERE tenant_id = $1 AND pattern = '203.0.113.90'`, orgID).Scan(&n)
	if n != 0 {
		t.Fatal("reading the suggestions added an entry")
	}
	if out = read(viewer); out.CanAdd || len(out.Cards) != 1 {
		t.Fatalf("viewer cards %+v", out)
	}
	h.expect(noRead, http.MethodGet, "/api/v1/easm/suggestions", "", http.StatusForbidden)
	if out = read(otherAdmin); len(out.Cards) != 0 {
		t.Fatalf("another organization saw cards: %+v", out)
	}
}
