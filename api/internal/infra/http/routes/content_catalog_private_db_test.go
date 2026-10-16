package routes

// Private content packages (RFC-099): an organization publishes to itself
// only, the instance to every organization; revocation reaches the
// installations; the gates and tenant isolation hold.

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
	"testing"

	catalogapp "github.com/openctemio/openctem/api/internal/app/contentcatalog"
	contentpackapp "github.com/openctemio/openctem/api/internal/app/contentpack"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/infra/storage"
	"github.com/openctemio/openctem/api/pkg/contentpkg"
	dom "github.com/openctemio/openctem/api/pkg/domain/contentcatalog"
	"github.com/openctemio/openctem/api/pkg/domain/contentpack"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func wordlistArchive(t *testing.T, words string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	_ = tw.WriteHeader(&tar.Header{Name: "words.txt", Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(words))})
	_, _ = tw.Write([]byte(words))
	_ = tw.Close()
	_ = gz.Close()
	return buf.Bytes()
}

func wordlistManifest(id, version string, art []byte) []byte {
	return []byte(fmt.Sprintf(`apiVersion: openctem.io/package/v1
id: %s
version: %s
type: wordlists
title: Internal wordlist
content_kind: wordlist
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
  spdx: LicenseRef-internal
  service_use: true
  redistribution: false
provenance:
  build_identity: https://git.example.com/sec/words/ci@refs/tags/v%s
  build_issuer: https://git.example.com
`, id, version, contentpkg.Digest(art), len(art), version))
}

func (h *ccHarness) publish(user, tenant shared.ID, perms []string, manifest, art []byte) (int, map[string]any) {
	h.t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, _ := mw.CreateFormFile("manifest", "package.yaml")
	_, _ = fw.Write(manifest)
	fw, _ = mw.CreateFormFile("artifact", "artifact.tar.gz")
	_, _ = fw.Write(art)
	_ = mw.Close()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, h.srv.URL+"/api/v1/content/private-packages", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("X-Test-User", user.String())
	req.Header.Set("X-Test-Tenant", tenant.String())
	req.Header.Set("X-Test-Perms", strings.Join(perms, ","))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, map[string]any{"_raw": string(raw)}
}

func TestContentCatalogPrivate_DB(t *testing.T) {
	h := newCCHarness(t)
	ctx := context.Background()
	pg := &postgres.DB{DB: h.db}
	log := logger.NewNop()
	signer, _ := contentpack.NewSigner(bytes.Repeat([]byte{9}, 32))
	store := storage.NewLocalStorage(t.TempDir())
	h.svc.SetPublishing(&catalogapp.Publishing{
		TenantPacks:   contentpackapp.NewService(postgres.NewContentPackRepository(pg), store, signer, nil, log),
		PlatformPacks: contentpackapp.NewPlatformService(postgres.NewPlatformContentPackRepository(pg), store, signer, log),
		Signer:        signer,
		Slug: func(_ context.Context, id shared.ID) (string, error) {
			return "cc-" + id.String(), nil
		},
	})
	slugA := "cc-" + h.tenantA.String()
	perms := append([]string{permission.ContentPublish.String()}, ccAllPerms...)
	art := wordlistArchive(t, "admin\nroot\n")
	idA := slugA + "/words"

	t.Run("publish needs content:publish", func(t *testing.T) {
		if code, _ := h.publish(h.userA1, h.tenantA, ccAllPerms, wordlistManifest(idA, "1.0.0", art), art); code != http.StatusForbidden {
			t.Fatalf("without content:publish: %d", code)
		}
	})

	t.Run("namespace must be the organization's slug, never reserved", func(t *testing.T) {
		code, body := h.publish(h.userA1, h.tenantA, perms, wordlistManifest("acme/words", "1.0.0", art), art)
		if code != http.StatusUnprocessableEntity || !strings.Contains(body["_raw"].(string), slugA) {
			t.Fatalf("other namespace: %d %v", code, body)
		}
		if code, _ := h.publish(h.userA1, h.tenantA, perms, wordlistManifest("openctem/words", "1.0.0", art), art); code != http.StatusUnprocessableEntity {
			t.Fatalf("reserved namespace: %d", code)
		}
		if code, _ := h.publish(h.userA1, h.tenantA, perms, wordlistManifest(idA, "1.0.0", art), append(art, 0)); code != http.StatusUnprocessableEntity {
			t.Fatalf("artifact not matching its digest: %d", code)
		}
	})

	t.Run("publish, install, isolation, revoke", func(t *testing.T) {
		code, body := h.publish(h.userA1, h.tenantA, perms, wordlistManifest(idA, "1.0.0", art), art)
		if code != http.StatusCreated || !strings.Contains(body["_raw"].(string), `"origin":"organization"`) {
			t.Fatalf("publish: %d %v", code, body)
		}
		if code, _ := h.publish(h.userA1, h.tenantA, perms, wordlistManifest(idA, "1.0.0", art), art); code != http.StatusConflict {
			t.Fatalf("same version twice: %d", code)
		}
		if n := h.count(`SELECT COUNT(*) FROM content_packs WHERE tenant_id = $1`, h.tenantA.String()); n != 1 {
			t.Fatalf("A has %d content packs", n)
		}
		if code, _ := h.a1(http.MethodPost, "/installs", map[string]any{"package_id": idA, "version": "1.0.0"}); code != http.StatusCreated {
			t.Fatalf("install own private package: %d", code)
		}
		if code, _ := h.do(h.userB, h.tenantB, ccAllPerms, http.MethodGet, "/packages/"+idA, nil); code != http.StatusNotFound {
			t.Fatalf("B sees A's private package: %d", code)
		}
		if code, _ := h.do(h.userB, h.tenantB, ccAllPerms, http.MethodPost, "/installs", map[string]any{"package_id": idA, "version": "1.0.0"}); code != http.StatusNotFound {
			t.Fatalf("B installs A's private package: %d", code)
		}
		_, list := h.do(h.userB, h.tenantB, ccAllPerms, http.MethodGet, "/packages?q=words", nil)
		if fmt.Sprint(list["total"]) != "0" {
			t.Fatalf("B lists A's private package: %v", list)
		}
		if code, _ := h.do(h.userB, h.tenantB, perms, http.MethodPost, "/private-packages/"+idA+"/1.0.0/revoke", map[string]any{"reason": "x"}); code != http.StatusNotFound {
			t.Fatalf("B revokes A's package: %d", code)
		}
		if code, _ := h.do(h.userA1, h.tenantA, perms, http.MethodPost, "/private-packages/"+idA+"/1.0.0/revoke", map[string]any{"reason": "leaked words"}); code != http.StatusOK {
			t.Fatalf("revoke: %d", code)
		}
		_, view := h.a1(http.MethodGet, "/packages/"+idA, nil)
		if status(view, "install", "status") != "revoked" {
			t.Fatalf("installation after revoke: %v", view)
		}
	})

	t.Run("instance package: every organization sees it, a bundle cannot take its id", func(t *testing.T) {
		art2 := wordlistArchive(t, "guest\n")
		p, err := h.svc.PublishInstance(ctx, catalogapp.PublishInput{ManifestRaw: wordlistManifest("corp/words", "2.0.0", art2), Artifact: art2}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if p.Origin != contentpkg.OriginInstance || p.PlatformPackID == nil {
			t.Fatalf("instance package: %+v", p)
		}
		for _, u := range []struct{ user, tenant shared.ID }{{h.userA1, h.tenantA}, {h.userB, h.tenantB}} {
			if code, _ := h.do(u.user, u.tenant, ccAllPerms, http.MethodGet, "/packages/corp/words", nil); code != http.StatusOK {
				t.Fatalf("instance package not visible: %d", code)
			}
		}
		// The instance cannot shadow an organization's package, nor publish
		// into an organization's namespace.
		if _, err := h.svc.PublishInstance(ctx, catalogapp.PublishInput{ManifestRaw: wordlistManifest(idA, "9.0.0", art2), Artifact: art2}, nil); !errors.Is(err, dom.ErrIDTaken) {
			t.Fatalf("instance package with an organization's id: %v", err)
		}
		if _, err := h.svc.PublishInstance(ctx, catalogapp.PublishInput{ManifestRaw: wordlistManifest(slugA+"/other", "1.0.0", art2), Artifact: art2}, nil); !errors.Is(err, dom.ErrNamespaceTaken) {
			t.Fatalf("instance package in an organization's namespace: %v", err)
		}
		// A signed bundle cannot take an id the instance owns.
		taken := extraRulesCC(h.now)
		taken.ManifestRaw = bytes.Replace(taken.ManifestRaw, []byte("id: acme/extra-rules"), []byte("id: corp/words"), 1)
		raw := h.bundle(ccBundle{seq: 30, rvSeq: 30, pkgs: []contentpkg.PackageInput{taken}})
		if _, err := h.svc.Import(ctx, bytes.NewReader(raw), nil); !errors.Is(err, shared.ErrConflict) {
			t.Fatalf("bundle with an instance id: %v", err)
		}
		if _, err := h.svc.RevokeInstance(ctx, "corp/words", "9.9.9", "x"); !errors.Is(err, shared.ErrNotFound) {
			t.Fatalf("revoke a missing instance version: %v", err)
		}
		if _, err := h.svc.RevokeInstance(ctx, "corp/words", "2.0.0", "superseded"); err != nil {
			t.Fatal(err)
		}
	})
}
