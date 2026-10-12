package routes

// Finding evidence authorization (docs/architecture/finding-evidence.md) over
// the real route registration, middleware chain (permission gate, rate limit,
// step-up, DataScopeGuard), handler, service, encryption and a migrated
// database:
//   - reading returns masked items only, never cached;
//   - another tenant's finding, or one outside the caller's data scope, is 404;
//   - reveal needs findings:evidence:reveal (403), a recent sign-in (403
//     STEP_UP_REQUIRED) and a user session (an API key is 403
//     STEP_UP_UNAVAILABLE);
//   - a reveal returns only the requested values, no-store, and writes one
//     audit row and one timeline entry, neither holding the value;
//   - expired secrets are 410; the per-user rate limit answers 429.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/lib/pq"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/datascope"
	evidenceapp "github.com/openctemio/openctem/api/internal/app/evidence"
	tenantapp "github.com/openctemio/openctem/api/internal/app/tenant"
	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/crypto"
	evidencedom "github.com/openctemio/openctem/api/pkg/domain/evidence"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

const evToken = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJldmlkZW5jZS10ZXN0In0.c2lnbmF0dXJlLXZhbHVlLTEyMzQ1Ng"

// recentAuth is a step-up checker: users in the set signed in just now.
type recentAuth struct {
	mu    sync.Mutex
	users map[string]bool
}

func (r *recentAuth) RecentAuthAt(_ context.Context, userID, _ string) (time.Time, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.users[userID] {
		return time.Now(), nil
	}
	return time.Time{}, middleware.ErrNoRecentAuth
}

type evHarness struct {
	t   *testing.T
	db  *sql.DB
	srv *httptest.Server
	svc *evidenceapp.Service

	tenantA, tenantB                  shared.ID
	revealer, reader, scoped, limited shared.ID
	findingA1, findingA2, findingB    shared.ID
	steppedUp                         *recentAuth
}

func newEvidenceAuthzHarness(t *testing.T) *evHarness {
	t.Helper()
	url := testdb.URL()
	if url == "" {
		t.Skip("DATABASE_URL not set to a test database; skipping evidence authz DB test")
	}
	db, err := sql.Open("postgres", url)
	if err != nil {
		t.Skipf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Ping(); err != nil {
		testdb.Skipf(t, "cannot reach test DB: %v", err)
	}
	h := &evHarness{t: t, db: db, steppedUp: &recentAuth{users: map[string]bool{}}}
	h.seed()

	pg := &postgres.DB{DB: db}
	log := logger.NewNop()
	enforcer := datascope.New(postgres.NewDataScopeRepository(pg),
		func(ctx context.Context) datascope.Caller {
			return datascope.Caller{UserID: middleware.GetUserID(ctx), IsAdmin: middleware.IsAdmin(ctx)}
		}, log)
	prevGuard, prevStepUp := dataScopeGuardMiddleware, stepUpChecker
	dataScopeGuardMiddleware = middleware.DataScopeGuard(enforcer)
	stepUpChecker = h.steppedUp
	t.Cleanup(func() { dataScopeGuardMiddleware, stepUpChecker = prevGuard, prevStepUp })

	cipher, err := crypto.NewCipher([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	tenantSvc := tenantapp.NewTenantService(postgres.NewTenantRepository(pg), log)
	h.svc = evidenceapp.NewService(postgres.NewFindingEvidenceRepository(pg), cipher, tenantSvc,
		postgres.NewFindingActivityRepository(pg), auditapp.NewAuditService(postgres.NewAuditRepository(pg), log), log)

	router := infrahttp.NewChiRouter()
	registerFindingEvidenceItemRoutes(router, handler.NewFindingEvidenceItemsHandler(h.svc, log), Middleware(h.auth), nil, log)
	h.srv = httptest.NewServer(router.(interface{ Handler() http.Handler }).Handler())
	t.Cleanup(h.srv.Close)
	return h
}

func (h *evHarness) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		ctx = context.WithValue(ctx, middleware.UserIDKey, r.Header.Get("X-Test-User"))
		ctx = context.WithValue(ctx, middleware.TenantIDKey, h.tenantA.String())
		ctx = context.WithValue(ctx, middleware.SessionIDKey, "session-"+r.Header.Get("X-Test-User"))
		ctx = context.WithValue(ctx, middleware.PermissionsKey, strings.Split(r.Header.Get("X-Test-Perms"), ","))
		if r.Header.Get("X-Test-APIKey") == "1" {
			ctx = context.WithValue(ctx, middleware.APIKeyIDKey, "key-1")
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (h *evHarness) exec(q string, args ...any) {
	h.t.Helper()
	if _, err := h.db.ExecContext(context.Background(), q, args...); err != nil {
		h.t.Fatalf("seed %q: %v", q, err)
	}
}

func (h *evHarness) seed() {
	h.tenantA, h.tenantB = shared.NewID(), shared.NewID()
	h.revealer, h.reader, h.scoped, h.limited = shared.NewID(), shared.NewID(), shared.NewID(), shared.NewID()
	h.findingA1, h.findingA2, h.findingB = shared.NewID(), shared.NewID(), shared.NewID()
	users := []shared.ID{h.revealer, h.reader, h.scoped, h.limited}
	for _, tid := range []shared.ID{h.tenantA, h.tenantB} {
		h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, tid.String(), "ev-"+tid.String())
	}
	h.t.Cleanup(func() {
		ctx := context.Background()
		for _, tid := range []shared.ID{h.tenantA, h.tenantB} {
			_, _ = h.db.ExecContext(ctx, `DELETE FROM tenants WHERE id = $1`, tid.String())
		}
		for _, u := range users {
			_, _ = h.db.ExecContext(ctx, `DELETE FROM users WHERE id = $1`, u.String())
		}
	})
	for _, u := range users {
		h.exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'member')`, u.String(), u.String()+"@ev.test")
		h.exec(`INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, 'member')`, u.String(), h.tenantA.String())
	}
	assetA1, assetA2, assetB := shared.NewID(), shared.NewID(), shared.NewID()
	for _, a := range []struct {
		id, tenant shared.ID
		name       string
	}{{assetA1, h.tenantA, "a1.example.com"}, {assetA2, h.tenantA, "a2.example.com"}, {assetB, h.tenantB, "b.example.com"}} {
		h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type, status) VALUES ($1, $2, $3, 'domain', 'active')`,
			a.id.String(), a.tenant.String(), a.name)
	}
	for _, f := range []struct{ id, tenant, asset shared.ID }{
		{h.findingA1, h.tenantA, assetA1}, {h.findingA2, h.tenantA, assetA2}, {h.findingB, h.tenantB, assetB},
	} {
		h.exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, rule_id, message, severity, fingerprint, status)
			VALUES ($1::uuid, $2, $3, 'dast', 'nuclei', 'exposed-panel', 'hit', 'high', $1::text, 'confirmed')`,
			f.id.String(), f.tenant.String(), f.asset.String())
	}
	// revealer, reader and limited see both of tenant A's assets; scoped sees A1 only.
	for _, u := range []shared.ID{h.revealer, h.reader, h.limited} {
		for _, a := range []shared.ID{assetA1, assetA2} {
			h.exec(`INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES ($1, $2, $3, 'secondary')`,
				u.String(), h.tenantA.String(), a.String())
		}
	}
	h.exec(`INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES ($1, $2, $3, 'secondary')`,
		h.scoped.String(), h.tenantA.String(), assetA1.String())
}

// store puts one HTTP exchange carrying evToken on the finding.
func (h *evHarness) store(tenant, finding shared.ID) {
	h.t.Helper()
	items := evidencedom.FromToolProperties(map[string]any{
		"request":  "GET /admin HTTP/1.1\r\nHost: a1.example.com\r\nAuthorization: Bearer " + evToken + "\r\n\r\n",
		"response": "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<script>alert(1)</script> Admin panel",
	}, "https://a1.example.com/admin", "nuclei exposed-panel")
	h.svc.StoreDetections(context.Background(), tenant, []evidenceapp.Detection{
		{Fingerprint: finding.String(), Items: items, Meta: evidenceapp.Meta{ToolName: "nuclei", RuleID: "exposed-panel"}},
	})
}

type evResp struct {
	code    int
	body    string
	headers http.Header
}

func (h *evHarness) do(user shared.ID, perms []permission.Permission, method, path, body string, apiKey bool) evResp {
	h.t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, h.srv.URL+path, rd)
	if err != nil {
		h.t.Fatal(err)
	}
	names := make([]string, 0, len(perms))
	for _, p := range perms {
		names = append(names, p.String())
	}
	req.Header.Set("X-Test-User", user.String())
	req.Header.Set("X-Test-Perms", strings.Join(names, ","))
	if apiKey {
		req.Header.Set("X-Test-APIKey", "1")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return evResp{code: resp.StatusCode, body: string(b), headers: resp.Header}
}

func (h *evHarness) list(user shared.ID, finding shared.ID) (evResp, handler.FindingEvidenceItemListResponse) {
	h.t.Helper()
	r := h.do(user, []permission.Permission{permission.FindingsRead}, http.MethodGet, "/api/v1/findings/"+finding.String()+"/evidence-items/", "", false)
	var out handler.FindingEvidenceItemListResponse
	if r.code == http.StatusOK {
		if err := json.Unmarshal([]byte(r.body), &out); err != nil {
			h.t.Fatal(err)
		}
	}
	return r, out
}

func (h *evHarness) count(q string, args ...any) int {
	h.t.Helper()
	var n int
	if err := h.db.QueryRowContext(context.Background(), q, args...).Scan(&n); err != nil {
		h.t.Fatal(err)
	}
	return n
}

func TestEvidenceItems_ReadIsMaskedAndScoped(t *testing.T) {
	h := newEvidenceAuthzHarness(t)
	h.store(h.tenantA, h.findingA1)
	h.store(h.tenantA, h.findingA2)
	h.store(h.tenantB, h.findingB)

	r, out := h.list(h.reader, h.findingA1)
	if r.code != http.StatusOK || len(out.Data) != 1 {
		t.Fatalf("list = %d %s", r.code, r.body)
	}
	if strings.Contains(r.body, evToken) || !strings.Contains(r.body, "«secret:authorization#1»") {
		t.Fatalf("list must carry the placeholder, never the token: %s", r.body)
	}
	if cc := r.headers.Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("Cache-Control = %q", cc)
	}
	it := out.Data[0]
	if !it.SecretsAvailable || len(it.Revealable) != 1 || !strings.HasPrefix(it.Curl, "curl ") || strings.Contains(it.Curl, evToken) {
		t.Errorf("item = %+v", it)
	}
	// Tool content is returned as data (a JSON string), for text-only rendering.
	if !strings.Contains(it.Item.HTTP.Response.Body, "<script>alert(1)</script>") {
		t.Errorf("response body = %q", it.Item.HTTP.Response.Body)
	}
	// The stored rows never hold the plaintext: not the item, not the ciphertext.
	if n := h.count(`SELECT count(*) FROM finding_evidence WHERE content::text LIKE '%' || $1 || '%'`, evToken); n != 0 {
		t.Errorf("%d evidence rows hold the token in clear", n)
	}
	if n := h.count(`SELECT count(*) FROM finding_evidence_secrets WHERE ciphertext LIKE '%' || $1 || '%'`, evToken); n != 0 {
		t.Errorf("%d secret rows hold the token in clear", n)
	}
	if n := h.count(`SELECT count(*) FROM findings WHERE row_to_json(findings)::text LIKE '%' || $1 || '%'`, evToken); n != 0 {
		t.Errorf("%d findings rows hold the token", n)
	}

	if r, _ := h.list(h.reader, h.findingB); r.code != http.StatusNotFound {
		t.Errorf("another tenant's finding = %d, want 404", r.code)
	}
	if r, _ := h.list(h.scoped, h.findingA2); r.code != http.StatusNotFound {
		t.Errorf("out-of-scope finding = %d, want 404", r.code)
	}
	if r := h.do(h.reader, nil, http.MethodGet, "/api/v1/findings/"+h.findingA1.String()+"/evidence-items/", "", false); r.code != http.StatusForbidden {
		t.Errorf("without findings:read = %d, want 403", r.code)
	}
}

func TestEvidenceItems_RevealGates(t *testing.T) {
	h := newEvidenceAuthzHarness(t)
	h.store(h.tenantA, h.findingA1)
	h.store(h.tenantA, h.findingA2)
	h.store(h.tenantB, h.findingB)
	_, out := h.list(h.reader, h.findingA1)
	item := out.Data[0]
	ph := item.Revealable[0]
	revealPath := func(finding shared.ID, itemID string) string {
		return "/api/v1/findings/" + finding.String() + "/evidence-items/" + itemID + "/reveal"
	}
	body := `{"placeholders":["` + ph + `"],"purpose":"view"}`
	perms := []permission.Permission{permission.FindingsRead, permission.EvidenceReveal}
	auditRows := func() int {
		return h.count(`SELECT count(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'finding.evidence_revealed'`, h.tenantA.String())
	}

	// No permission.
	if r := h.do(h.reader, []permission.Permission{permission.FindingsRead}, http.MethodPost, revealPath(h.findingA1, item.ID), body, false); r.code != http.StatusForbidden {
		t.Fatalf("without findings:evidence:reveal = %d %s", r.code, r.body)
	}
	// Permission, no recent sign-in.
	if r := h.do(h.revealer, perms, http.MethodPost, revealPath(h.findingA1, item.ID), body, false); r.code != http.StatusForbidden || !strings.Contains(r.body, "STEP_UP_REQUIRED") {
		t.Fatalf("without step-up = %d %s", r.code, r.body)
	}
	h.steppedUp.users[h.revealer.String()] = true
	h.steppedUp.users[h.scoped.String()] = true
	// An API key can never step up.
	if r := h.do(h.revealer, perms, http.MethodPost, revealPath(h.findingA1, item.ID), body, true); r.code != http.StatusForbidden || !strings.Contains(r.body, "STEP_UP_UNAVAILABLE") {
		t.Fatalf("api key = %d %s", r.code, r.body)
	}
	if auditRows() != 0 {
		t.Fatal("a refused reveal wrote an audit row")
	}

	r := h.do(h.revealer, perms, http.MethodPost, revealPath(h.findingA1, item.ID), body, false)
	if r.code != http.StatusOK {
		t.Fatalf("reveal = %d %s", r.code, r.body)
	}
	var rev handler.RevealEvidenceResponse
	if err := json.Unmarshal([]byte(r.body), &rev); err != nil {
		t.Fatal(err)
	}
	if rev.Values[ph] != evToken || len(rev.Values) != 1 || rev.MaskAfterSeconds != 60 {
		t.Errorf("reveal = %+v", rev)
	}
	if cc := r.headers.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q", cc)
	}
	if auditRows() != 1 {
		t.Errorf("audit rows = %d, want 1", auditRows())
	}
	if n := h.count(`SELECT count(*) FROM audit_logs WHERE tenant_id = $1 AND row_to_json(audit_logs)::text LIKE '%' || $2 || '%'`, h.tenantA.String(), evToken); n != 0 {
		t.Error("the audit row holds the revealed value")
	}
	if n := h.count(`SELECT count(*) FROM finding_activities WHERE tenant_id = $1 AND finding_id = $2 AND activity_type = 'evidence_revealed'
			AND changes->>'purpose' = 'view' AND changes::text NOT LIKE '%' || $3 || '%'`, h.tenantA.String(), h.findingA1.String(), evToken); n != 1 {
		t.Errorf("timeline entries = %d, want 1", n)
	}

	// Another finding's path with this item: 404 (the item belongs to A1).
	if r := h.do(h.revealer, perms, http.MethodPost, revealPath(h.findingA2, item.ID), body, false); r.code != http.StatusNotFound {
		t.Errorf("item under another finding = %d", r.code)
	}
	// Another tenant's finding and item: 404.
	var bItem string
	if err := h.db.QueryRow(`SELECT id FROM finding_evidence WHERE finding_id = $1`, h.findingB.String()).Scan(&bItem); err != nil {
		t.Fatal(err)
	}
	if r := h.do(h.revealer, perms, http.MethodPost, revealPath(h.findingB, bItem), body, false); r.code != http.StatusNotFound {
		t.Errorf("another tenant = %d", r.code)
	}
	if r := h.do(h.revealer, perms, http.MethodPost, revealPath(h.findingA1, bItem), body, false); r.code != http.StatusNotFound {
		t.Errorf("another tenant's item under own finding = %d", r.code)
	}
	// Out of data scope: 404.
	_, outA2 := h.list(h.revealer, h.findingA2)
	if r := h.do(h.scoped, perms, http.MethodPost, revealPath(h.findingA2, outA2.Data[0].ID), body, false); r.code != http.StatusNotFound {
		t.Errorf("out of scope = %d", r.code)
	}
	// Bad input.
	for _, b := range []string{`{"placeholders":[]}`, `{"placeholders":["nope"]}`, `{"placeholders":["` + ph + `"],"purpose":"exfiltrate"}`, `{"x":1}`} {
		if r := h.do(h.revealer, perms, http.MethodPost, revealPath(h.findingA1, item.ID), b, false); r.code != http.StatusBadRequest {
			t.Errorf("body %s = %d", b, r.code)
		}
	}
	if auditRows() != 1 {
		t.Errorf("refused reveals wrote audit rows: %d", auditRows())
	}

	// Expired secrets: 410, and nothing is returned.
	h.exec(`UPDATE finding_evidence_secrets SET expires_at = now() - interval '1 minute' WHERE tenant_id = $1`, h.tenantA.String())
	if r := h.do(h.revealer, perms, http.MethodPost, revealPath(h.findingA1, item.ID), body, false); r.code != http.StatusGone {
		t.Errorf("expired = %d %s", r.code, r.body)
	}
}

func TestEvidenceItems_RevealRateLimit(t *testing.T) {
	h := newEvidenceAuthzHarness(t)
	h.store(h.tenantA, h.findingA1)
	_, out := h.list(h.reader, h.findingA1)
	h.steppedUp.users[h.limited.String()] = true
	path := "/api/v1/findings/" + h.findingA1.String() + "/evidence-items/" + out.Data[0].ID + "/reveal"
	body := `{"placeholders":["` + out.Data[0].Revealable[0] + `"]}`
	perms := []permission.Permission{permission.EvidenceReveal}
	limited := false
	for i := 0; i < evidenceRevealBurst+5; i++ {
		if r := h.do(h.limited, perms, http.MethodPost, path, body, false); r.code == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited {
		t.Error("no 429 after the burst")
	}
}

func TestEvidenceItems_ErasureAndRetention(t *testing.T) {
	h := newEvidenceAuthzHarness(t)
	h.store(h.tenantB, h.findingB)
	if h.count(`SELECT count(*) FROM finding_evidence_secrets WHERE tenant_id = $1`, h.tenantB.String()) != 1 {
		t.Fatal("no secret stored")
	}
	// Retention sweep: an expired secret is deleted and its record can no longer reveal.
	h.exec(`UPDATE finding_evidence SET secrets_expire_at = now() - interval '1 second' WHERE tenant_id = $1`, h.tenantB.String())
	h.exec(`UPDATE finding_evidence_secrets SET expires_at = now() - interval '1 second' WHERE tenant_id = $1`, h.tenantB.String())
	if err := h.svc.Sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := h.count(`SELECT count(*) FROM finding_evidence_secrets WHERE tenant_id = $1`, h.tenantB.String()); n != 0 {
		t.Errorf("expired secrets left: %d", n)
	}
	if n := h.count(`SELECT count(*) FROM finding_evidence WHERE tenant_id = $1 AND masked_count = 0`, h.tenantB.String()); n != 1 {
		t.Errorf("record kept with no revealable values: %d", n)
	}
	// Finding deletion and tenant erasure remove everything.
	h.store(h.tenantB, h.findingB)
	h.exec(`DELETE FROM findings WHERE tenant_id = $1 AND id = $2`, h.tenantB.String(), h.findingB.String())
	if n := h.count(`SELECT count(*) FROM finding_evidence WHERE tenant_id = $1`, h.tenantB.String()); n != 0 {
		t.Errorf("evidence left after finding deletion: %d", n)
	}
	h.store(h.tenantA, h.findingA1)
	h.exec(`DELETE FROM tenants WHERE id = $1`, h.tenantA.String())
	if n := h.count(`SELECT count(*) FROM finding_evidence_secrets WHERE tenant_id = $1`, h.tenantA.String()); n != 0 {
		t.Errorf("secrets left after tenant erasure: %d", n)
	}
}

func TestEvidenceItems_CiphertextIsBoundToItsRecord(t *testing.T) {
	h := newEvidenceAuthzHarness(t)
	h.store(h.tenantA, h.findingA1)
	h.store(h.tenantA, h.findingA2)
	_, a1 := h.list(h.reader, h.findingA1)
	_, a2 := h.list(h.reader, h.findingA2)
	// Copy A2's ciphertext over A1's: decrypts, but is bound to A2's record.
	h.exec(`UPDATE finding_evidence_secrets s SET ciphertext = o.ciphertext
		FROM finding_evidence_secrets o WHERE s.evidence_id = $1 AND o.evidence_id = $2`, a1.Data[0].ID, a2.Data[0].ID)
	itemID, _ := shared.IDFromString(a1.Data[0].ID)
	uid := h.revealer
	_, err := h.svc.Reveal(context.Background(), evidenceapp.RevealInput{
		TenantID: h.tenantA, FindingID: h.findingA1, EvidenceID: itemID, Placeholders: a1.Data[0].Revealable,
		ActorID: &uid, Audit: auditapp.AuditContext{ActorID: uid.String()},
	})
	if !errors.Is(err, evidencedom.ErrSecretUnreadable) {
		t.Errorf("swapped ciphertext = %v, want ErrSecretUnreadable", err)
	}
}

func TestEvidenceItems_DedupAndPrune(t *testing.T) {
	h := newEvidenceAuthzHarness(t)
	h.store(h.tenantA, h.findingA1)
	h.store(h.tenantA, h.findingA1) // the same proof again: not stored twice
	if n := h.count(`SELECT count(*) FROM finding_evidence WHERE finding_id = $1`, h.findingA1.String()); n != 1 {
		t.Fatalf("records after a repeat = %d, want 1", n)
	}
	for i := range evidencedom.MaxDetectionPerFinding + 3 {
		items := []evidencedom.Item{{Kind: evidencedom.KindRawText, Text: "banner " + strings.Repeat("x", i+1)}}
		h.svc.StoreDetections(context.Background(), h.tenantA, []evidenceapp.Detection{{Fingerprint: h.findingA1.String(), Items: items}})
	}
	if n := h.count(`SELECT count(*) FROM finding_evidence WHERE finding_id = $1`, h.findingA1.String()); n != evidencedom.MaxDetectionPerFinding {
		t.Errorf("records = %d, want the newest %d", n, evidencedom.MaxDetectionPerFinding)
	}
	// Pruned records take their secrets with them.
	if n := h.count(`SELECT count(*) FROM finding_evidence_secrets s WHERE NOT EXISTS (SELECT 1 FROM finding_evidence e WHERE e.id = s.evidence_id)`); n != 0 {
		t.Errorf("orphan secrets = %d", n)
	}
}
