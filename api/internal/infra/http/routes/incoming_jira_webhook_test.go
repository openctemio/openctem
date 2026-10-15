package routes

// The inbound Jira webhook over the real route registration and a real
// database: the URL names one Jira integration, the delivery must carry
// Jira's own X-Hub-Signature (sha256=<hex HMAC of the raw body>) under that
// integration's secret, and a replayed or stale delivery is refused.

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	integrationapp "github.com/openctemio/openctem/api/internal/app/integration"
	"github.com/openctemio/openctem/api/internal/app/jira"
	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/crypto"
	"github.com/openctemio/openctem/api/pkg/domain/integration"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"

	_ "github.com/lib/pq"
)

// memDeliveries is an in-memory delivery-id store (Redis in production).
type memDeliveries struct {
	mu      sync.Mutex
	seen    map[string]bool
	replays int
}

func (m *memDeliveries) FirstDelivery(_ context.Context, key string, _ time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.seen[key] {
		m.replays++
		return false, nil
	}
	m.seen[key] = true
	return true, nil
}

// flakyFindings fails the first lookups (a transient database error), then
// finds nothing.
type flakyFindings struct {
	vulnerability.FindingRepository
	mu    sync.Mutex
	fails int
	calls int
}

func (f *flakyFindings) GetByWorkItemURI(context.Context, shared.ID, string) (*vulnerability.Finding, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.fails > 0 {
		f.fails--
		return nil, errors.New("transient")
	}
	return nil, shared.ErrNotFound
}

type jiraInbound struct {
	mux     http.Handler
	svc     *integrationapp.IntegrationService
	guard   *memDeliveries
	repo    *flakyFindings
	handler *handler.JiraWebhookHandler
	tenantA shared.ID
	tenantB shared.ID
	jiraA   shared.ID
	jiraB   shared.ID
}

func newJiraInbound(t *testing.T) *jiraInbound {
	t.Helper()
	dbURL := testdb.URL()
	if dbURL == "" {
		testdb.Skipf(t, "DATABASE_URL not set; skipping inbound Jira webhook route test")
	}
	sqldb, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sqldb.Close() })
	db := &postgres.DB{DB: sqldb}
	ctx := context.Background()
	cipher, err := crypto.NewCipher([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	repo := postgres.NewIntegrationRepository(db)
	svc := integrationapp.NewIntegrationService(repo, nil, cipher, logger.NewNop())

	j := &jiraInbound{svc: svc, tenantA: shared.NewID(), tenantB: shared.NewID()}
	for _, tid := range []shared.ID{j.tenantA, j.tenantB} {
		if _, err := sqldb.ExecContext(ctx, `INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`,
			tid.String(), "jira-inbound-"+tid.String()); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = sqldb.ExecContext(ctx, `DELETE FROM integrations WHERE tenant_id IN ($1, $2)`, j.tenantA.String(), j.tenantB.String())
		_, _ = sqldb.ExecContext(ctx, `DELETE FROM tenants WHERE id IN ($1, $2)`, j.tenantA.String(), j.tenantB.String())
	})
	mk := func(tid shared.ID) shared.ID {
		intg := integration.NewIntegration(shared.NewID(), tid, "Jira "+tid.String(),
			integration.CategoryTicketing, integration.ProviderJira, integration.AuthTypeToken)
		intg.SetStatus(integration.StatusConnected)
		if err := repo.Create(ctx, intg); err != nil {
			t.Fatal(err)
		}
		return intg.ID()
	}
	j.jiraA, j.jiraB = mk(j.tenantA), mk(j.tenantB)

	j.repo = &flakyFindings{}
	h := handler.NewJiraWebhookHandler(jira.NewSyncService(j.repo, nil, logger.NewNop()), nil, logger.NewNop())
	j.handler = h
	h.SetDeliveryVerifier(svc)
	j.guard = &memDeliveries{seen: map[string]bool{}}
	h.SetDeliveryGuard(j.guard)
	router := infrahttp.NewChiRouter()
	registerIncomingWebhookRoutes(router, h, logger.NewNop())
	j.mux = router.(interface{ Handler() http.Handler }).Handler()
	return j
}

func jiraBody(ts time.Time) string {
	return fmt.Sprintf(`{"webhookEvent":"jira:issue_updated","timestamp":%d,"issue":{"key":"OPS-1"}}`, ts.UnixMilli())
}

func hubSign(secret, body string) string {
	m := hmac.New(sha256.New, []byte(secret))
	_, _ = m.Write([]byte(body))
	return "sha256=" + hex.EncodeToString(m.Sum(nil))
}

func (m *memDeliveries) ReleaseDelivery(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.seen, key)
	return nil
}

func (j *jiraInbound) send(integrationID string, sig, delivery, body string) int {
	req := httptest.NewRequest(http.MethodPost, "/hooks/jira-integrations/"+integrationID, strings.NewReader(body))
	if sig != "" {
		req.Header.Set("X-Hub-Signature", sig)
	}
	if delivery != "" {
		req.Header.Set("X-Atlassian-Webhook-Identifier", delivery)
	}
	rec := httptest.NewRecorder()
	j.mux.ServeHTTP(rec, req)
	return rec.Code
}

func TestIncomingJiraWebhook_HubSignaturePerIntegration(t *testing.T) {
	j := newJiraInbound(t)
	ctx := context.Background()
	secretA, err := j.svc.RotateJiraWebhookSecret(ctx, j.tenantA, j.jiraA)
	if err != nil {
		t.Fatal(err)
	}
	const secretB = "tenant-b-chose-this-secret"
	if err := j.svc.ReplaceJiraWebhookSecret(ctx, j.tenantB, j.jiraB, secretB); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	n := 0
	id := func() string { n++; return fmt.Sprintf("delivery-%d-%d", now.UnixNano(), n) }

	t.Run("stock Jira delivery signed with the integration's secret is accepted", func(t *testing.T) {
		body := jiraBody(now)
		if code := j.send(j.jiraA.String(), hubSign(secretA, body), id(), body); code != http.StatusOK {
			t.Fatalf("got %d, want 200", code)
		}
		body = jiraBody(now.Add(time.Second))
		if code := j.send(j.jiraB.String(), hubSign(secretB, body), id(), body); code != http.StatusOK {
			t.Fatalf("an entered secret: got %d, want 200", code)
		}
	})
	t.Run("wrong secret, missing header, malformed header are refused", func(t *testing.T) {
		body := jiraBody(now)
		for name, sig := range map[string]string{
			"wrong secret": hubSign("not-the-secret-at-all", body),
			"missing":      "",
			"no prefix":    strings.TrimPrefix(hubSign(secretA, body), "sha256="),
			"not hex":      "sha256=zz",
		} {
			if code := j.send(j.jiraA.String(), sig, id(), body); code != http.StatusUnauthorized {
				t.Errorf("%s: got %d, want 401", name, code)
			}
		}
	})
	t.Run("another integration's secret never verifies (cross-tenant)", func(t *testing.T) {
		body := jiraBody(now)
		if code := j.send(j.jiraA.String(), hubSign(secretB, body), id(), body); code != http.StatusUnauthorized {
			t.Fatalf("B's secret on A's URL: got %d, want 401", code)
		}
		if code := j.send(j.jiraB.String(), hubSign(secretA, body), id(), body); code != http.StatusUnauthorized {
			t.Fatalf("A's secret on B's URL: got %d, want 401", code)
		}
	})
	t.Run("unknown integration and a malformed id are refused", func(t *testing.T) {
		body := jiraBody(now)
		if code := j.send(shared.NewID().String(), hubSign(secretA, body), id(), body); code != http.StatusUnauthorized {
			t.Errorf("unknown integration: got %d, want 401", code)
		}
		if code := j.send("not-a-uuid", hubSign(secretA, body), id(), body); code != http.StatusUnauthorized {
			t.Errorf("bad id: got %d, want 401", code)
		}
	})
	t.Run("a replayed delivery is not processed twice", func(t *testing.T) {
		body := jiraBody(now.Add(2 * time.Second))
		d := id()
		if code := j.send(j.jiraA.String(), hubSign(secretA, body), d, body); code != http.StatusOK {
			t.Fatalf("first: got %d", code)
		}
		// Acknowledged (so Jira does not retry) but not processed again.
		if code := j.send(j.jiraA.String(), hubSign(secretA, body), d, body); code != http.StatusOK {
			t.Fatalf("replay: got %d, want 200 (acknowledged, ignored)", code)
		}
		if j.guard.replays != 1 {
			t.Fatalf("replay not detected: %d", j.guard.replays)
		}
		// Without an identifier the body hash is the delivery id.
		body2 := jiraBody(now.Add(3 * time.Second))
		for i := 0; i < 2; i++ {
			if code := j.send(j.jiraA.String(), hubSign(secretA, body2), "", body2); code != http.StatusOK {
				t.Fatalf("no identifier: got %d", code)
			}
		}
		if j.guard.replays != 2 {
			t.Fatalf("replay without identifier not detected: %d", j.guard.replays)
		}
		// The identifier is not signed: the same body under a new identifier
		// is still a replay.
		if code := j.send(j.jiraA.String(), hubSign(secretA, body), id(), body); code != http.StatusOK {
			t.Fatalf("same body, new identifier: got %d", code)
		}
		if j.guard.replays != 3 {
			t.Fatalf("same body under a new identifier was processed again: %d", j.guard.replays)
		}
	})
	t.Run("a delivery that failed to process is processed on Jira's retry", func(t *testing.T) {
		body := fmt.Sprintf(`{"webhookEvent":"jira:issue_updated","timestamp":%d,"issue":{"key":"OPS-9","self":"https://x.atlassian.net/rest/api/2/issue/9"},"changelog":{"items":[{"field":"status","toString":"Done"}]}}`, now.Add(5*time.Second).UnixMilli())
		d := id()
		j.repo.fails = 1
		if code := j.send(j.jiraA.String(), hubSign(secretA, body), d, body); code != http.StatusInternalServerError {
			t.Fatalf("failing delivery: got %d, want 500", code)
		}
		before := j.repo.calls
		if code := j.send(j.jiraA.String(), hubSign(secretA, body), d, body); code != http.StatusOK {
			t.Fatalf("retry: got %d, want 200", code)
		}
		if j.repo.calls != before+1 {
			t.Fatalf("the retry was dropped as a replay (lookups %d -> %d)", before, j.repo.calls)
		}
	})
	t.Run("a stale or undated delivery is refused", func(t *testing.T) {
		body := jiraBody(now.Add(-2 * time.Hour))
		if code := j.send(j.jiraA.String(), hubSign(secretA, body), id(), body); code != http.StatusUnauthorized {
			t.Errorf("two hours old: got %d, want 401", code)
		}
		body = `{"webhookEvent":"jira:issue_updated","issue":{"key":"OPS-1"}}`
		if code := j.send(j.jiraA.String(), hubSign(secretA, body), id(), body); code != http.StatusUnauthorized {
			t.Errorf("no timestamp: got %d, want 401", code)
		}
	})
	t.Run("rotation invalidates the old secret at once", func(t *testing.T) {
		newSecret, err := j.svc.RotateJiraWebhookSecret(ctx, j.tenantA, j.jiraA)
		if err != nil {
			t.Fatal(err)
		}
		body := jiraBody(now.Add(4 * time.Second))
		if code := j.send(j.jiraA.String(), hubSign(secretA, body), id(), body); code != http.StatusUnauthorized {
			t.Errorf("old secret after rotation: got %d, want 401", code)
		}
		if code := j.send(j.jiraA.String(), hubSign(newSecret, body), id(), body); code != http.StatusOK {
			t.Errorf("new secret: got %d, want 200", code)
		}
	})
	t.Run("a tenant cannot read, rotate or set another tenant's integration secret", func(t *testing.T) {
		if _, err := j.svc.RotateJiraWebhookSecret(ctx, j.tenantB, j.jiraA); err == nil {
			t.Error("B rotated A's secret")
		}
		if err := j.svc.ReplaceJiraWebhookSecret(ctx, j.tenantB, j.jiraA, "tenant-b-tries-to-take-over"); err == nil {
			t.Error("B set A's secret")
		}
		if _, err := j.svc.JiraWebhookHasSecret(ctx, j.tenantB, j.jiraA); err == nil {
			t.Error("B read A's webhook state")
		}
	})
	t.Run("without a delivery store nothing is processed", func(t *testing.T) {
		j.handler.SetDeliveryGuard(nil)
		defer j.handler.SetDeliveryGuard(j.guard)
		body := jiraBody(now.Add(6 * time.Second))
		if code := j.send(j.jiraB.String(), hubSign(secretB, body), id(), body); code != http.StatusServiceUnavailable {
			t.Fatalf("no delivery store: got %d, want 503", code)
		}
	})
	t.Run("a weak entered secret is refused", func(t *testing.T) {
		for _, s := range []string{"short", "has a space in it ok", strings.Repeat("x", 300)} {
			if err := j.svc.ReplaceJiraWebhookSecret(ctx, j.tenantA, j.jiraA, s); err == nil {
				t.Errorf("secret %q accepted", s)
			}
		}
	})
}
