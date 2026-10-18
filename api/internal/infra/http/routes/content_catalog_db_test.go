package routes

// The content catalog over its real routes and a private database
// (RFC-099): offline import of a signed bundle, install / update / pin /
// rollback / uninstall, the permission gates, tenant isolation, revocation,
// rollback protection, the approval option and the stale revocation list.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	catalogapp "github.com/openctemio/openctem/api/internal/app/contentcatalog"
	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/contentpkg"
	catalogdom "github.com/openctemio/openctem/api/pkg/domain/contentcatalog"
	notificationdom "github.com/openctemio/openctem/api/pkg/domain/notification"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

const (
	ccSastIdentity  = "https://github.com/openctemio/sast-rules/.github/workflows/release.yml@refs/tags/v0.1.0"
	ccIssuer        = "https://token.actions.githubusercontent.com"
	ccTestSigPrefix = "test-publisher-signature:"
)

// ccPublisher verifies the real sast-rules Sigstore bundle offline and, for
// packages the test builds, a test signature naming the artifact digest.
type ccPublisher struct{ real *contentpkg.SigstoreVerifier }

func (p ccPublisher) Verify(sig, artifact []byte, want contentpkg.Publisher) (time.Time, error) {
	if s := string(sig); strings.HasPrefix(s, ccTestSigPrefix) {
		if s != ccTestSigPrefix+contentpkg.Digest(artifact)+"|"+want.Identity {
			return time.Time{}, contentpkg.ErrPublisherSignature
		}
		return time.Now(), nil
	}
	return p.real.Verify(sig, artifact, want)
}

type ccHarness struct {
	t                     *testing.T
	db                    *sql.DB
	svc                   *catalogapp.Service
	srv                   *httptest.Server
	root, online          ed25519.PrivateKey
	keySet                []byte
	now                   time.Time
	tenantA, tenantB      shared.ID
	userA1, userA2, userB shared.ID
	sastArt, sastSig      []byte
	notices               []shared.ID
}

type ccNotifier struct{ h *ccHarness }

func (n ccNotifier) Notify(_ context.Context, p notificationdom.NotificationParams) error {
	if p.AudienceID != nil {
		n.h.notices = append(n.h.notices, *p.AudienceID)
	}
	return nil
}

var ccAllPerms = []string{permission.ContentRead.String(), permission.ContentInstall.String(), //nolint:gochecknoglobals // test fixture
	permission.SettingsWrite.String()}

func newCCHarness(t *testing.T) *ccHarness {
	t.Helper()
	db := testdb.PrivateDatabase(t, "content_catalog", filepath.Join("..", "..", "..", "..", "migrations"))
	h := &ccHarness{t: t, db: db, now: time.Now().UTC()}
	_, h.root, _ = ed25519.GenerateKey(rand.Reader)
	_, h.online, _ = ed25519.GenerateKey(rand.Reader)
	var err error
	h.keySet, err = contentpkg.SignKeySet(h.root, 1, h.now.Add(-time.Hour), h.now.Add(170*24*time.Hour), h.online.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	fixtures := filepath.Join("..", "..", "..", "..", "pkg", "contentpkg", "testdata", "sigstore")
	if h.sastArt, err = os.ReadFile(filepath.Join(fixtures, "sast-rules-0.1.0.tar.gz")); err != nil {
		t.Fatal(err)
	}
	if h.sastSig, err = os.ReadFile(filepath.Join(fixtures, "sast-rules-0.1.0.tar.gz.sigstore.json")); err != nil {
		t.Fatal(err)
	}
	real, err := contentpkg.NewSigstoreVerifier("")
	if err != nil {
		t.Fatal(err)
	}
	h.tenantA, h.tenantB = shared.NewID(), shared.NewID()
	h.userA1, h.userA2, h.userB = shared.NewID(), shared.NewID(), shared.NewID()
	for _, tn := range []shared.ID{h.tenantA, h.tenantB} {
		h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, tn.String(), "cc-"+tn.String())
	}
	for u, tn := range map[shared.ID]shared.ID{h.userA1: h.tenantA, h.userA2: h.tenantA, h.userB: h.tenantB} {
		role := "member"
		if u == h.userA1 || u == h.userA2 {
			role = "admin"
		}
		h.exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'cc')`, u.String(), u.String()+"@cc.test")
		h.exec(`INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, $3)`, u.String(), tn.String(), role)
	}

	pg := &postgres.DB{DB: db}
	log := logger.NewNop()
	audit := auditapp.NewAuditService(postgres.NewAuditRepository(pg), log)
	h.svc = catalogapp.NewService(postgres.NewContentCatalogRepository(pg),
		[]string{contentpkg.RootKeyID(h.root.Public().(ed25519.PublicKey))}, ccPublisher{real: real},
		func() string { return "v0.9.7" }, audit, log)
	h.svc.SetNotifier(ccNotifier{h: h})

	prevStepUp := stepUpChecker
	stepUpChecker = recentAuthFunc(time.Now)
	t.Cleanup(func() { stepUpChecker = prevStepUp })
	router := infrahttp.NewChiRouter()
	registerContentCatalogRoutes(router, handler.NewContentCatalogHandler(h.svc, log), ccAuth, nil)
	h.srv = httptest.NewServer(router.(interface{ Handler() http.Handler }).Handler())
	t.Cleanup(h.srv.Close)
	return h
}

// ccAuth stands in for the authenticator: the caller, its organization and
// its permissions travel in test headers.
func ccAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), middleware.UserIDKey, r.Header.Get("X-Test-User"))
		ctx = context.WithValue(ctx, middleware.TenantIDKey, r.Header.Get("X-Test-Tenant"))
		ctx = context.WithValue(ctx, middleware.SessionIDKey, "cc-session")
		ctx = context.WithValue(ctx, middleware.IsAdminKey, false)
		ctx = context.WithValue(ctx, middleware.PermissionsKey, strings.Split(r.Header.Get("X-Test-Perms"), ","))
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (h *ccHarness) exec(q string, args ...any) {
	h.t.Helper()
	if _, err := h.db.Exec(q, args...); err != nil {
		h.t.Fatalf("%s: %v", q, err)
	}
}

func (h *ccHarness) do(user, tenant shared.ID, perms []string, method, path string, body any) (int, map[string]any) {
	h.t.Helper()
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req, _ := http.NewRequestWithContext(context.Background(), method, h.srv.URL+"/api/v1/content"+path, rdr)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Test-User", user.String())
	req.Header.Set("X-Test-Tenant", tenant.String())
	req.Header.Set("X-Test-Perms", strings.Join(perms, ","))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	if len(out) == 0 && len(raw) > 0 {
		out["_raw"] = string(raw)
	}
	return resp.StatusCode, out
}

func (h *ccHarness) a1(method, path string, body any) (int, map[string]any) {
	return h.do(h.userA1, h.tenantA, ccAllPerms, method, path, body)
}

func sensorManifestCC(version string, tier string) []byte {
	return []byte(fmt.Sprintf(`apiVersion: openctem.io/package/v1
id: openctem/sensor
version: %s
type: sensors
title: Scanning sensor
artifact:
  media_type: application/vnd.oci.image.index.v1+json
  digest: %s
  size: 2048
  ref: ghcr.io/openctemio/sensor
compatibility:
  platform: ">=0.9.0"
  protocol: ">=3"
permissions:
  tier: %s
  side_effects: none
  network: targets-only
license:
  spdx: GPL-3.0-only
  service_use: true
  redistribution: true
provenance:
  build_identity: https://github.com/openctemio/sensor/.github/workflows/docker-publish.yml@refs/tags/v%s
  build_issuer: %s
`, version, contentpkg.Digest([]byte("image "+version)), tier, version, ccIssuer))
}

func sastManifestCC(art []byte) []byte {
	return []byte(fmt.Sprintf(`apiVersion: openctem.io/package/v1
id: openctem/sast-rules
version: 0.1.0
type: rules
title: Official SAST rules
content_kind: semgrep-rules
artifact:
  media_type: application/gzip
  digest: %s
  size: %d
compatibility:
  platform: ">=0.9.0"
permissions:
  tier: T0
  side_effects: none
  network: none
license:
  spdx: MIT
  service_use: true
  redistribution: true
provenance:
  build_identity: %s
  build_issuer: %s
`, contentpkg.Digest(art), len(art), ccSastIdentity, ccIssuer))
}

// extraRulesCC is a third-party rules package that depends on the
// official rules and whose license forbids service use.
func extraRulesCC(reviewed time.Time) contentpkg.PackageInput {
	art := []byte("extra rules archive")
	identity := "https://github.com/acme/rules/.github/workflows/release.yml@refs/tags/v1.0.0"
	m := []byte(fmt.Sprintf(`apiVersion: openctem.io/package/v1
id: acme/extra-rules
version: 1.0.0
type: rules
title: Extra rules
content_kind: semgrep-rules
artifact:
  media_type: application/gzip
  digest: %s
  size: %d
compatibility:
  platform: ">=0.9.0"
permissions:
  tier: T0
  side_effects: none
  network: none
license:
  spdx: CC-BY-NC-4.0
  service_use: false
  redistribution: true
dependencies:
  - id: openctem/sast-rules
    version: ">=0.1.0, <1.0.0"
provenance:
  build_identity: %s
  build_issuer: %s
`, contentpkg.Digest(art), len(art), identity, ccIssuer))
	return contentpkg.PackageInput{ManifestRaw: m, Artifact: art,
		Publisher: []byte(ccTestSigPrefix + contentpkg.Digest(art) + "|" + identity), Origin: contentpkg.OriginCatalog,
		ReviewedAt: reviewed}
}

type ccBundle struct {
	seq      uint64
	rvSeq    uint64
	rvExpiry time.Duration
	entries  []contentpkg.RevocationEntry
	pkgs     []contentpkg.PackageInput
}

func (h *ccHarness) bundle(b ccBundle) []byte {
	h.t.Helper()
	if b.rvExpiry == 0 {
		b.rvExpiry = 20 * 24 * time.Hour
	}
	var buf bytes.Buffer
	err := contentpkg.WriteBundle(&buf, contentpkg.BundleInput{KeySet: h.keySet, Online: h.online, Sequence: b.seq,
		IssuedAt: h.now.Add(-time.Minute), ExpiresAt: h.now.Add(60 * 24 * time.Hour),
		Revocations: contentpkg.Revocations{Sequence: b.rvSeq, IssuedAt: h.now.Add(-time.Minute),
			ExpiresAt: h.now.Add(-time.Minute).Add(b.rvExpiry), Entries: b.entries},
		Packages: b.pkgs})
	if err != nil {
		h.t.Fatal(err)
	}
	return buf.Bytes()
}

func (h *ccHarness) basePackages() []contentpkg.PackageInput {
	return []contentpkg.PackageInput{
		{ManifestRaw: sastManifestCC(h.sastArt), Artifact: h.sastArt, Publisher: h.sastSig, Origin: contentpkg.OriginFirstParty, ReviewedAt: h.now},
		{ManifestRaw: sensorManifestCC("0.23.0", "T1"), Origin: contentpkg.OriginFirstParty, ReviewedAt: h.now},
		{ManifestRaw: sensorManifestCC("0.24.0", "T1"), Origin: contentpkg.OriginFirstParty, ReviewedAt: h.now},
		extraRulesCC(h.now),
	}
}

func (h *ccHarness) count(q string, args ...any) int {
	h.t.Helper()
	var n int
	if err := h.db.QueryRow(q, args...).Scan(&n); err != nil {
		h.t.Fatal(err)
	}
	return n
}

func status(m map[string]any, path ...string) string {
	var v any = m
	for _, p := range path {
		mm, ok := v.(map[string]any)
		if !ok {
			return ""
		}
		v = mm[p]
	}
	s, _ := v.(string)
	return s
}

//nolint:cyclop,maintidx // one database, the whole lifecycle in order
func TestContentCatalog_DB(t *testing.T) {
	h := newCCHarness(t)
	ctx := context.Background()

	t.Run("nothing is trusted before an import", func(t *testing.T) {
		code, body := h.a1(http.MethodGet, "/trust", nil)
		if code != http.StatusOK || body["revocations_stale"] != true || body["roots_configured"].(float64) != 1 {
			t.Fatalf("trust: %d %v", code, body)
		}
	})

	t.Run("a tampered bundle stores nothing", func(t *testing.T) {
		raw := h.bundle(ccBundle{seq: 10, rvSeq: 1, pkgs: h.basePackages()})
		bad := bytes.Replace(raw, []byte("Official SAST rules"), []byte("Official SAST rulez"), 1)
		if _, err := h.svc.Import(ctx, bytes.NewReader(bad), nil); !errors.Is(err, catalogapp.ErrVerification) {
			t.Fatalf("tampered: %v", err)
		}
		if n := h.count(`SELECT COUNT(*) FROM content_packages`); n != 0 {
			t.Fatalf("%d rows stored", n)
		}
	})

	t.Run("offline import", func(t *testing.T) {
		res, err := h.svc.Import(ctx, bytes.NewReader(h.bundle(ccBundle{seq: 10, rvSeq: 1, pkgs: h.basePackages()})), nil)
		if err != nil {
			t.Fatal(err)
		}
		if res.Added != 4 || res.IndexSequence != 10 || res.RevocationsStale {
			t.Fatalf("import: %+v", res)
		}
		// The same bundle again (Ed25519 signatures are deterministic): a no-op.
		again, err := h.svc.Import(ctx, bytes.NewReader(h.bundle(ccBundle{seq: 10, rvSeq: 1, pkgs: h.basePackages()})), nil)
		if err != nil || !again.Unchanged || again.Added != 0 || again.Existing != 4 {
			t.Fatalf("repeated import: %v %+v", err, again)
		}
		// Same sequence, other contents: refused.
		if _, err := h.svc.Import(ctx, bytes.NewReader(h.bundle(ccBundle{seq: 10, rvSeq: 1, pkgs: h.basePackages()[:2]})), nil); !errors.Is(err, catalogapp.ErrRollback) {
			t.Fatalf("same sequence, other contents: %v", err)
		}
		if _, err := h.svc.Import(ctx, bytes.NewReader(h.bundle(ccBundle{seq: 9, rvSeq: 1, pkgs: h.basePackages()})), nil); !errors.Is(err, catalogapp.ErrRollback) {
			t.Fatalf("older index: %v", err)
		}
	})

	t.Run("permission gates", func(t *testing.T) {
		if code, _ := h.do(h.userA1, h.tenantA, []string{"assets:read"}, http.MethodGet, "/packages", nil); code != http.StatusForbidden {
			t.Fatalf("no content:read: %d", code)
		}
		read := []string{permission.ContentRead.String()}
		if code, _ := h.do(h.userA1, h.tenantA, read, http.MethodGet, "/packages", nil); code != http.StatusOK {
			t.Fatalf("content:read lists: %d", code)
		}
		if code, _ := h.do(h.userA1, h.tenantA, read, http.MethodPost, "/installs",
			map[string]any{"package_id": "openctem/sast-rules", "version": "0.1.0"}); code != http.StatusForbidden {
			t.Fatalf("install without content:install: %d", code)
		}
		if code, _ := h.do(h.userA1, h.tenantA, []string{permission.ContentInstall.String(), permission.ContentRead.String()},
			http.MethodPut, "/settings", map[string]any{"require_approval": true}); code != http.StatusForbidden {
			t.Fatalf("settings without settings:write: %d", code)
		}
	})

	t.Run("install, dependencies, license acknowledgement", func(t *testing.T) {
		code, body := h.a1(http.MethodPost, "/installs", map[string]any{"package_id": "acme/extra-rules", "version": "1.0.0", "acknowledge_license": true})
		if code != http.StatusUnprocessableEntity || !strings.Contains(fmt.Sprint(body), "openctem/sast-rules") {
			t.Fatalf("missing dependency: %d %v", code, body)
		}
		if code, body = h.a1(http.MethodPost, "/installs", map[string]any{"package_id": "openctem/sast-rules", "version": "0.1.0"}); code != http.StatusCreated {
			t.Fatalf("install: %d %v", code, body)
		}
		if code, body = h.a1(http.MethodPost, "/installs", map[string]any{"package_id": "acme/extra-rules", "version": "1.0.0"}); code != http.StatusUnprocessableEntity ||
			!strings.Contains(fmt.Sprint(body), "service") {
			t.Fatalf("license not acknowledged: %d %v", code, body)
		}
		if code, body = h.a1(http.MethodPost, "/installs", map[string]any{"package_id": "acme/extra-rules", "version": "1.0.0", "acknowledge_license": true}); code != http.StatusCreated {
			t.Fatalf("with acknowledgement: %d %v", code, body)
		}
		if code, _ = h.a1(http.MethodDelete, "/installs/openctem/sast-rules", nil); code != http.StatusUnprocessableEntity {
			t.Fatalf("uninstall a dependency: %d", code)
		}
		if code, _ = h.a1(http.MethodPost, "/installs", map[string]any{"package_id": "openctem/sast-rules", "version": "0.1.0"}); code != http.StatusConflict {
			t.Fatalf("install twice: %d", code)
		}
	})

	t.Run("update, pin, rollback", func(t *testing.T) {
		if code, body := h.a1(http.MethodPost, "/installs", map[string]any{"package_id": "openctem/sensor", "version": "0.23.0"}); code != http.StatusCreated {
			t.Fatalf("install sensor: %d %v", code, body)
		}
		if code, _ := h.a1(http.MethodPost, "/installs/openctem/sensor/update", map[string]any{"version": "0.23.0"}); code != http.StatusUnprocessableEntity {
			t.Fatalf("update to the same version: %d", code)
		}
		code, body := h.a1(http.MethodPost, "/installs/openctem/sensor/update", map[string]any{"version": "0.24.0"})
		if code != http.StatusOK || status(body, "install", "installed", "version") != "0.24.0" || status(body, "install", "previous", "version") != "0.23.0" {
			t.Fatalf("update: %d %v", code, body)
		}
		code, body = h.a1(http.MethodPost, "/installs/openctem/sensor/rollback", map[string]any{})
		if code != http.StatusOK || status(body, "install", "installed", "version") != "0.23.0" || body["install"].(map[string]any)["pinned"] != true {
			t.Fatalf("rollback pins: %d %v", code, body)
		}
		code, body = h.a1(http.MethodPut, "/installs/openctem/sensor/pin", map[string]any{"pinned": false})
		if code != http.StatusOK || body["pinned"] != false {
			t.Fatalf("unpin: %d %v", code, body)
		}
	})

	t.Run("tenant isolation", func(t *testing.T) {
		all := ccAllPerms
		code, body := h.do(h.userB, h.tenantB, all, http.MethodGet, "/installs", nil)
		if code != http.StatusOK || body["_raw"] != "[]\n" && body["_raw"] != "[]" {
			t.Fatalf("B sees A's installs: %d %v", code, body)
		}
		if code, _ := h.do(h.userB, h.tenantB, all, http.MethodPost, "/installs/openctem/sensor/update", map[string]any{"version": "0.24.0"}); code != http.StatusNotFound {
			t.Fatalf("B updates A's installation: %d", code)
		}
		if code, _ := h.do(h.userB, h.tenantB, all, http.MethodDelete, "/installs/openctem/sast-rules", nil); code != http.StatusNotFound {
			t.Fatalf("B uninstalls A's installation: %d", code)
		}
		code, body = h.do(h.userB, h.tenantB, all, http.MethodGet, "/packages/openctem/sensor", nil)
		if code != http.StatusOK || body["install"] != nil {
			t.Fatalf("B sees A's installation in the package view: %d %v", code, body)
		}
		if n := h.count(`SELECT COUNT(*) FROM content_installs WHERE tenant_id = $1`, h.tenantA.String()); n != 3 {
			t.Fatalf("A has %d installations", n)
		}
	})

	t.Run("the console lists the instance catalog only", func(t *testing.T) {
		// An organization's private package (copied from an imported row).
		h.exec(`INSERT INTO content_packages (id, tenant_id, package_id, version, type, origin, title, manifest,
			manifest_raw, manifest_digest, artifact_media_type, artifact_digest, artifact_size, statement, tier, service_use)
			SELECT gen_random_uuid(), $1, 'acme/private', version, type, 'organization', title, manifest, manifest_raw,
			manifest_digest, artifact_media_type, artifact_digest, artifact_size, statement, tier, service_use
			FROM content_packages WHERE tenant_id IS NULL AND package_id = 'openctem/sensor' LIMIT 1`, h.tenantA.String())
		want := h.count(`SELECT COUNT(DISTINCT package_id) FROM content_packages WHERE tenant_id IS NULL`)
		items, total, err := h.svc.ListInstance(ctx, catalogdom.Filter{})
		if err != nil || total != want || len(items) != want || want == 0 {
			t.Fatalf("instance listing: %d %d %v", total, len(items), err)
		}
		for _, it := range items {
			if it.Latest.PackageID == "acme/private" || it.Latest.TenantID != nil || it.Install != nil {
				t.Fatalf("the console listing carries organization data: %+v", it.Latest.PackageID)
			}
		}
		if _, err := h.svc.InstanceVersions(ctx, "acme/private"); !errors.Is(err, catalogdom.ErrNotFound) {
			t.Fatalf("an organization's private package must not be visible to the console: %v", err)
		}
		if v, err := h.svc.InstanceVersions(ctx, "openctem/sensor"); err != nil || len(v) == 0 {
			t.Fatalf("instance versions: %d %v", len(v), err)
		}
	})

	t.Run("approval option: four eyes, isolation", func(t *testing.T) {
		if code, body := h.a1(http.MethodPut, "/settings", map[string]any{"require_approval": true}); code != http.StatusOK || body["require_approval"] != true {
			t.Fatalf("settings: %d %v", code, body)
		}
		code, body := h.a1(http.MethodPost, "/installs/openctem/sensor/update", map[string]any{"version": "0.24.0", "note": "new release"})
		if code != http.StatusAccepted || status(body, "request", "status") != "pending" {
			t.Fatalf("request: %d %v", code, body)
		}
		id := status(body, "request", "id")
		if code, _ := h.a1(http.MethodPost, "/installs/openctem/sensor/update", map[string]any{"version": "0.24.0"}); code != http.StatusConflict {
			t.Fatalf("second pending request: %d", code)
		}
		if code, _ := h.a1(http.MethodPost, "/requests/"+id+"/approve", map[string]any{}); code != http.StatusForbidden {
			t.Fatalf("self approval: %d", code)
		}
		if code, _ := h.do(h.userB, h.tenantB, ccAllPerms, http.MethodPost, "/requests/"+id+"/approve", map[string]any{}); code != http.StatusNotFound {
			t.Fatalf("another organization approves: %d", code)
		}
		code, body = h.do(h.userA2, h.tenantA, ccAllPerms, http.MethodPost, "/requests/"+id+"/approve", map[string]any{"reason": "ok"})
		if code != http.StatusOK || status(body, "install", "installed", "version") != "0.24.0" || status(body, "request", "status") != "approved" {
			t.Fatalf("approval: %d %v", code, body)
		}
		if code, _ := h.do(h.userA2, h.tenantA, ccAllPerms, http.MethodPost, "/requests/"+id+"/approve", map[string]any{}); code != http.StatusConflict {
			t.Fatalf("approve twice: %d", code)
		}
		if n := h.count(`SELECT COUNT(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'content_package.request_approved'`, h.tenantA.String()); n != 1 {
			t.Fatalf("approval audit rows: %d", n)
		}
		// Switching approval off waits 24 hours and tells the administrators.
		code, body = h.a1(http.MethodPut, "/settings", map[string]any{"require_approval": false})
		if code != http.StatusOK || body["require_approval"] != true || body["approval_off_at"] == nil {
			t.Fatalf("switch-off is pending: %d %v", code, body)
		}
		if len(h.notices) != 1 || h.notices[0] != h.userA2 {
			t.Fatalf("administrators notified: %v", h.notices)
		}
		if code, _ := h.a1(http.MethodPost, "/installs/openctem/sensor/rollback", map[string]any{}); code != http.StatusAccepted {
			t.Fatalf("approval still applies during the delay: %d", code)
		}
		h.exec(`UPDATE content_install_requests SET status = 'canceled' WHERE tenant_id = $1 AND status = 'pending'`, h.tenantA.String())
		// Turning it on cancels the switch-off.
		if code, body = h.a1(http.MethodPut, "/settings", map[string]any{"require_approval": true}); code != http.StatusOK || body["approval_off_at"] != nil {
			t.Fatalf("turn on cancels: %d %v", code, body)
		}
		h.a1(http.MethodPut, "/settings", map[string]any{"require_approval": false})
		// After the delay approval no longer applies.
		h.exec(`UPDATE content_catalog_settings SET approval_off_at = now() - interval '1 minute' WHERE tenant_id = $1`, h.tenantA.String())
		if code, body = h.a1(http.MethodGet, "/settings", nil); code != http.StatusOK || body["require_approval"] != false {
			t.Fatalf("after the delay: %d %v", code, body)
		}
	})

	t.Run("revocation through a newer bundle", func(t *testing.T) {
		entries := []contentpkg.RevocationEntry{{ID: "openctem/sast-rules", Version: "0.1.0", Reason: "bad rule", Severity: "high", RevokedAt: h.now}}
		res, err := h.svc.Import(ctx, bytes.NewReader(h.bundle(ccBundle{seq: 11, rvSeq: 2, entries: entries, pkgs: h.basePackages()[1:]})), nil)
		if err != nil {
			t.Fatal(err)
		}
		if res.RevokedVersions != 1 || res.RevokedInstalls != 1 {
			t.Fatalf("revoked: %+v", res)
		}
		code, body := h.a1(http.MethodGet, "/packages/openctem/sast-rules", nil)
		if code != http.StatusOK || status(body, "install", "status") != "revoked" {
			t.Fatalf("A's installation: %d %v", code, body)
		}
		if code, body := h.do(h.userB, h.tenantB, ccAllPerms, http.MethodPost, "/installs",
			map[string]any{"package_id": "openctem/sast-rules", "version": "0.1.0"}); code != http.StatusUnprocessableEntity ||
			!strings.Contains(fmt.Sprint(body), "revoked") {
			t.Fatalf("install a revoked version: %d %v", code, body)
		}
		// An older bundle that still lists the version cannot bring it back.
		if _, err := h.svc.Import(ctx, bytes.NewReader(h.bundle(ccBundle{seq: 12, rvSeq: 3, pkgs: h.basePackages()})), nil); err != nil {
			t.Fatal(err)
		}
		if n := h.count(`SELECT COUNT(*) FROM content_packages WHERE package_id = 'openctem/sast-rules' AND revoked_at IS NULL`); n != 0 {
			t.Fatal("the revoked version came back")
		}
	})

	t.Run("unpinned installations follow a newer version that asks for nothing more", func(t *testing.T) {
		pk := []contentpkg.PackageInput{
			{ManifestRaw: sensorManifestCC("0.25.0", "T1"), Origin: contentpkg.OriginFirstParty, ReviewedAt: h.now},
			{ManifestRaw: sensorManifestCC("0.26.0", "T2"), Origin: contentpkg.OriginFirstParty, ReviewedAt: h.now},
		}
		res, err := h.svc.Import(ctx, bytes.NewReader(h.bundle(ccBundle{seq: 13, rvSeq: 4, pkgs: pk})), nil)
		if err != nil {
			t.Fatal(err)
		}
		if res.AutoUpdated != 1 {
			t.Fatalf("auto updated: %+v", res)
		}
		code, body := h.a1(http.MethodGet, "/packages/openctem/sensor", nil)
		if code != http.StatusOK || status(body, "install", "installed", "version") != "0.25.0" {
			t.Fatalf("followed to 0.25.0, not the T2 0.26.0: %d %v", code, body)
		}
	})

	t.Run("a stale revocation list blocks new executables only", func(t *testing.T) {
		if _, err := h.svc.Import(ctx, bytes.NewReader(h.bundle(ccBundle{seq: 14, rvSeq: 5, rvExpiry: 2 * time.Hour, pkgs: h.basePackages()[1:3]})), nil); err != nil {
			t.Fatal(err)
		}
		h.svc.UseClock(func() time.Time { return h.now.Add(3 * time.Hour) })
		defer h.svc.UseClock(time.Now)
		code, body := h.do(h.userB, h.tenantB, ccAllPerms, http.MethodPost, "/installs", map[string]any{"package_id": "openctem/sensor", "version": "0.24.0"})
		if code != http.StatusUnprocessableEntity || !strings.Contains(fmt.Sprint(body), "revocation list") {
			t.Fatalf("executable with a stale list: %d %v", code, body)
		}
		if code, body := h.a1(http.MethodGet, "/trust", nil); code != http.StatusOK || body["revocations_stale"] != true {
			t.Fatalf("trust: %d %v", code, body)
		}
	})

	t.Run("an expired bundle is refused", func(t *testing.T) {
		h.svc.UseClock(func() time.Time { return h.now.Add(61 * 24 * time.Hour) })
		defer h.svc.UseClock(time.Now)
		_, err := h.svc.Import(ctx, bytes.NewReader(h.bundle(ccBundle{seq: 20, rvSeq: 6, pkgs: h.basePackages()[1:2]})), nil)
		if !errors.Is(err, catalogapp.ErrVerification) || !strings.Contains(err.Error(), "expired") {
			t.Fatalf("expired: %v", err)
		}
	})

	t.Run("audit rows carry the digest", func(t *testing.T) {
		if n := h.count(`SELECT COUNT(*) FROM audit_logs WHERE tenant_id = $1 AND action LIKE 'content_package.%'
			AND metadata->>'artifact_digest' LIKE 'sha256:%'`, h.tenantA.String()); n < 4 {
			t.Fatalf("audit rows with digests: %d", n)
		}
	})
}
