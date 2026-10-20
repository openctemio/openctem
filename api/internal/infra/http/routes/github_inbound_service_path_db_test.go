package routes

// The inbound GitHub webhook over the real route registration and a migrated
// database: the URL names one GitHub integration and its own secret signs
// the delivery; an issue closed as completed is a fix claim through the
// finding service rules for EVERY finding linked to the issue (proof of fix
// requested), never a close; closed as not planned opens a pending risk
// acceptance request; closed, pentest and other-tenant findings are left
// alone; a replay with a new delivery id changes nothing; another tenant's
// integration URL refuses this integration's signature.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	integrationapp "github.com/openctemio/openctem/api/internal/app/integration"
	"github.com/openctemio/openctem/api/internal/app/ticketbridge"
	"github.com/openctemio/openctem/api/internal/app/ticketing"
	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/crypto"
	"github.com/openctemio/openctem/api/pkg/domain/integration"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func TestGitHubInbound_ServicePathPerIntegration(t *testing.T) {
	h := newGroupScopeHarness(t)
	ctx := context.Background()
	db := &postgres.DB{DB: h.db}
	log := logger.NewNop()
	findingRepo := postgres.NewFindingRepository(db)
	h.vuln.SetApprovalRepository(postgres.NewFindingApprovalRepository(db))
	var mu sync.Mutex
	var queued, hooked []shared.ID
	h.vuln.SetProofOfFixQueuer(func(_ context.Context, _ shared.ID, ids []shared.ID) int {
		mu.Lock()
		defer mu.Unlock()
		queued = append(queued, ids...)
		return len(ids)
	})

	cipher, err := crypto.NewCipher([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	intRepo := postgres.NewIntegrationRepository(db)
	extRepo := postgres.NewIntegrationSCMExtensionRepository(db, intRepo)
	intSvc := integrationapp.NewIntegrationService(intRepo, extRepo, cipher, log)

	other, otherAsset := shared.NewID(), shared.NewID()
	h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, other.String(), "gh-inbound-"+other.String())
	h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type, exposure, criticality) VALUES ($1, $2, 'other-tenant.example.com', 'domain', 'public', 'high')`,
		otherAsset.String(), other.String())

	mkGitHub := func(tenant shared.ID, org string) (shared.ID, string) {
		intg := integration.NewIntegration(shared.NewID(), tenant, "GitHub "+tenant.String()[:8],
			integration.CategorySCM, integration.ProviderGitHub, integration.AuthTypeToken)
		intg.SetStatus(integration.StatusConnected)
		if err := intRepo.Create(ctx, intg); err != nil {
			t.Fatal(err)
		}
		ext := integration.NewSCMExtension(intg.ID())
		ext.SetSCMOrganization(org)
		if err := extRepo.Create(ctx, ext); err != nil {
			t.Fatal(err)
		}
		secret, err := intSvc.RotateGitHubWebhookSecret(ctx, tenant, intg.ID())
		if err != nil {
			t.Fatal(err)
		}
		return intg.ID(), secret
	}
	intgA, secretA := mkGitHub(h.tenant, "acme")
	intgB, _ := mkGitHub(other, "acme")
	t.Cleanup(func() {
		_, _ = h.db.Exec(`DELETE FROM integrations WHERE id IN ($1, $2)`, intgA.String(), intgB.String())
	})

	gh := ticketing.NewGitHubTicketService(findingRepo, intRepo, cipher, log)
	gh.SetInboundApplier(ticketbridge.GitHub{Vuln: h.vuln})
	gh.SetWorkItemFindingLister(findingRepo)
	gh.SetFixClaimHook(func(_ context.Context, _ shared.ID, id shared.ID) error {
		mu.Lock()
		defer mu.Unlock()
		hooked = append(hooked, id)
		return nil
	})
	wh := handler.NewGitHubWebhookHandler(intSvc, log)
	wh.SetIssueSink(gh)
	wh.SetDeliveryGuard(&memDeliveries{seen: map[string]bool{}})
	router := infrahttp.NewChiRouter()
	registerGitHubWebhookRoute(router, wh, log)
	mux := router.(interface{ Handler() http.Handler }).Handler()

	issue := fmt.Sprintf("https://github.com/acme/app/issues/%d", 1000+len(intgA.String()))
	add := func(tenant, asset shared.ID, source, status, url string) shared.ID {
		id := shared.NewID()
		h.exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status, work_item_uris)
			VALUES ($1::uuid, $2, $3, $4, 'gh-inbound', 'linked to one issue', 'high', $1::text, $5, ARRAY[$6]::text[])`,
			id.String(), tenant.String(), asset.String(), source, status, url)
		return id
	}
	fNew := add(h.tenant, h.assetA, "sast", "new", issue)
	fConfirmed := add(h.tenant, h.assetA, "sast", "confirmed", issue)
	fInProgress := add(h.tenant, h.assetB, "sast", "in_progress", issue)
	fResolved := add(h.tenant, h.assetA, "sast", "resolved", issue)
	fPentest := add(h.tenant, h.assetA, "pentest", "in_progress", issue)
	fOther := add(other, otherAsset, "sast", "in_progress", issue)

	send := func(intg shared.ID, secret, delivery, body string) int {
		req := httptest.NewRequest(http.MethodPost, "/hooks/github-integrations/"+intg.String(), strings.NewReader(body))
		req.Header.Set("X-Hub-Signature-256", hubSign(secret, body))
		req.Header.Set("X-GitHub-Event", "issues")
		req.Header.Set("X-GitHub-Delivery", delivery)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec.Code
	}
	closed := func(url, reason string) string {
		return fmt.Sprintf(`{"action":"closed","issue":{"html_url":%q,"state_reason":%q},"repository":{"full_name":"acme/app"},"sender":{"login":"octocat"}}`, url, reason)
	}
	status := func(id shared.ID) string {
		var st string
		if err := h.db.QueryRow(`SELECT status FROM findings WHERE id = $1`, id.String()).Scan(&st); err != nil {
			t.Fatal(err)
		}
		return st
	}

	// Another tenant's integration URL never accepts this integration's
	// signature, and nothing moves.
	if code := send(intgB, secretA, "aaaaaaaa-0000-0000-0000-000000000001", closed(issue, "completed")); code != http.StatusUnauthorized {
		t.Fatalf("A's signature on B's URL: %d, want 401", code)
	}
	if st := status(fOther); st != "in_progress" {
		t.Fatalf("other tenant's finding moved to %s", st)
	}

	// Closed as completed: a fix claim for every open linked finding.
	if code := send(intgA, secretA, "aaaaaaaa-0000-0000-0000-000000000002", closed(issue, "completed")); code != http.StatusOK {
		t.Fatalf("completed: %d", code)
	}
	for _, id := range []shared.ID{fNew, fConfirmed, fInProgress} {
		if st := status(id); st != "fix_applied" {
			t.Errorf("linked finding %s = %s, want fix_applied", id, st)
		}
	}
	if st := status(fResolved); st != "resolved" {
		t.Errorf("a resolved finding was moved to %s by an issue", st)
	}
	if st := status(fPentest); st != "in_progress" {
		t.Errorf("a pentest finding was moved to %s by an issue", st)
	}
	if st := status(fOther); st != "in_progress" {
		t.Errorf("another tenant's finding with the same issue URL moved to %s", st)
	}
	if len(hooked) != 3 || len(queued) != 3 {
		t.Errorf("proof of fix: hook %d, queued %d; want 3 and 3", len(hooked), len(queued))
	}
	// The GitHub account is recorded in the timeline.
	var withSender int
	if err := h.db.QueryRow(`SELECT COUNT(*) FROM finding_activities WHERE finding_id = $1 AND changes::text LIKE '%octocat%'`,
		fConfirmed.String()).Scan(&withSender); err != nil {
		t.Fatal(err)
	}
	if withSender == 0 {
		t.Error("no timeline entry records the GitHub sender")
	}

	// The same signed body with a new delivery id is a replay: nothing runs.
	if code := send(intgA, secretA, "aaaaaaaa-0000-0000-0000-000000000003", closed(issue, "completed")); code != http.StatusOK {
		t.Fatalf("replay: %d", code)
	}
	if len(hooked) != 3 {
		t.Errorf("a replay requested proof of fix again (%d)", len(hooked))
	}

	// Closed as not planned: a pending risk acceptance request, no claim.
	issue2 := issue + "0"
	fAsk := add(h.tenant, h.assetA, "sast", "confirmed", issue2)
	if code := send(intgA, secretA, "aaaaaaaa-0000-0000-0000-000000000004", closed(issue2, "not_planned")); code != http.StatusOK {
		t.Fatalf("not_planned: %d", code)
	}
	if st := status(fAsk); st != "confirmed" {
		t.Errorf("not planned moved the finding to %s; it is not a fix claim", st)
	}
	var pending int
	if err := h.db.QueryRow(`SELECT COUNT(*) FROM finding_status_approvals WHERE finding_id = $1 AND status = 'pending' AND requested_status = 'accepted'`,
		fAsk.String()).Scan(&pending); err != nil {
		t.Fatal(err)
	}
	if pending != 1 {
		t.Errorf("pending risk acceptance requests = %d, want 1", pending)
	}
	if len(hooked) != 3 {
		t.Errorf("not planned requested proof of fix (%d)", len(hooked))
	}

	// Reopened: the claimed findings go back to in progress.
	reopened := fmt.Sprintf(`{"action":"reopened","issue":{"html_url":%q},"repository":{"full_name":"acme/app"},"sender":{"login":"octocat"}}`, issue)
	if code := send(intgA, secretA, "aaaaaaaa-0000-0000-0000-000000000005", reopened); code != http.StatusOK {
		t.Fatalf("reopened: %d", code)
	}
	if st := status(fNew); st != "in_progress" {
		t.Errorf("reopened after completed = %s, want in_progress", st)
	}
}
