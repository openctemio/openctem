package contentpack

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	dom "github.com/openctemio/openctem/api/pkg/domain/contentpack"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// memPlatformRepo is an in-memory dom.PlatformRepository for ingest tests
// (channels are covered against Postgres).
type memPlatformRepo struct {
	mu    sync.Mutex
	blobs map[string]*dom.Blob
	packs map[string]*dom.PlatformPack
}

func (m *memPlatformRepo) GetBlob(_ context.Context, d string) (*dom.Blob, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if b, ok := m.blobs[d]; ok {
		return b, nil
	}
	return nil, dom.ErrNotFound
}

func (m *memPlatformRepo) CreateBlob(_ context.Context, b *dom.Blob) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.blobs[b.Digest]; ok {
		return false, nil
	}
	m.blobs[b.Digest] = b
	return true, nil
}

func (m *memPlatformRepo) Create(_ context.Context, p *dom.PlatformPack) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, o := range m.packs {
		if o.Name == p.Name && o.Version == p.Version {
			return dom.ErrExists
		}
	}
	m.packs[p.ID.String()] = p
	return nil
}

func (m *memPlatformRepo) GetByID(_ context.Context, id shared.ID) (*dom.PlatformPack, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if p, ok := m.packs[id.String()]; ok {
		return p, nil
	}
	return nil, dom.ErrNotFound
}

func (m *memPlatformRepo) List(context.Context, dom.Filter, int, int) ([]*dom.PlatformPack, int, error) {
	return nil, 0, nil
}

func (m *memPlatformRepo) Revoke(context.Context, shared.ID, string, time.Time) ([]dom.ChannelPointer, error) {
	return nil, nil
}

func (m *memPlatformRepo) SetChannel(context.Context, shared.ID, dom.Channel, time.Time) (*dom.ChannelPointer, error) {
	return nil, nil
}

func (m *memPlatformRepo) Channels(context.Context) ([]dom.ChannelPointer, error) { return nil, nil }

func newPlatformService(t *testing.T) (*PlatformService, *memPlatformRepo, *memStore) {
	t.Helper()
	signer, _ := dom.NewSigner(bytes.Repeat([]byte{5}, 32))
	repo := &memPlatformRepo{blobs: map[string]*dom.Blob{}, packs: map[string]*dom.PlatformPack{}}
	store := &memStore{objects: map[string][]byte{}}
	return NewPlatformService(repo, store, signer, logger.NewNop()), repo, store
}

func tarBytes(t *testing.T, files map[string]string) []byte {
	t.Helper()
	b, _ := io.ReadAll(tarOf(t, files))
	return b
}

// An upstream release: templates that fail lint (refused protocols, YAML
// that is not a template) are left out of the pack, which sensors receive
// without them; the pack is signed with the platform key, not a tenant's.
func TestPlatformUploadExcludesFailingFiles(t *testing.T) {
	svc, _, store := newPlatformService(t)
	p, err := svc.Upload(context.Background(), PlatformInput{Name: "nuclei-templates", Version: "10.4.9", Kind: dom.KindNucleiTemplates},
		bytes.NewReader(tarBytes(t, map[string]string{
			"http/banner.yaml":           passiveTemplate,
			"code/run.yaml":              codeTemplate,
			".github/workflows/ci.yml":   "on: push\njobs: {}\n",
			"helpers/payloads/users.txt": "admin\n",
		})))
	if err != nil {
		t.Fatal(err)
	}
	if p.Lint.Excluded != 2 || p.FileCount != 2 || p.Lint.Items != 1 || len(p.Lint.Errors) != 0 {
		t.Fatalf("pack %+v lint %+v", p.Pack, p.Lint)
	}
	for k, data := range store.objects {
		if !strings.HasPrefix(k, platformNamespace+"/") {
			t.Fatalf("stored outside the platform namespace: %s", k)
		}
		a, err := dom.ReadPlatformCanonical(data, p.Digest)
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range a.Files {
			if f.Path == "code/run.yaml" || strings.HasPrefix(f.Path, ".github") {
				t.Fatalf("an excluded file is in the pack: %s", f.Path)
			}
		}
	}
	key, _, _ := svc.SigningKey()
	pub, _ := base64.StdEncoding.DecodeString(key)
	st, err := dom.Verify(p.Signature, pub)
	if err != nil || st.Scope != "platform" || st.TenantID != "" || st.Digest != p.Digest {
		t.Fatalf("statement %+v %v", st, err)
	}
	// SECURITY: a tenant's key never verifies a platform pack.
	signer, _ := dom.NewSigner(bytes.Repeat([]byte{5}, 32))
	tpub, _, _ := signer.PublicKey(shared.NewID().String())
	if _, err := dom.Verify(p.Signature, tpub); err == nil {
		t.Fatal("a tenant key verified a platform pack")
	}
	// SECURITY: a tenant statement cannot claim the platform scope.
	if _, err := signer.Sign(dom.Statement{Scope: "platform", TenantID: "t", PackID: "p", Digest: p.Digest}); err == nil {
		t.Fatal("a tenant statement carried the platform scope")
	}
}

// Import: the fetched bytes must match the digest the administrator gave
// before anything is parsed; only https URLs without credentials.
func TestPlatformImportChecksTheDigest(t *testing.T) {
	svc, _, _ := newPlatformService(t)
	release := tarBytes(t, map[string]string{"http/banner.yaml": passiveTemplate})
	sum := sha256.Sum256(release)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	var fetched []string
	svc.fetch = func(_ context.Context, u string) (io.ReadCloser, error) {
		fetched = append(fetched, u)
		return io.NopCloser(bytes.NewReader(release)), nil
	}
	in := PlatformInput{Name: "nuclei-templates", Version: "1", Kind: dom.KindNucleiTemplates}
	p, err := svc.Import(context.Background(), in, "https://example.org/r.tar.gz", digest)
	if err != nil || p.Source != dom.SourceHTTPS || p.SourceDigest != digest || p.SourceRef != "https://example.org/r.tar.gz" {
		t.Fatalf("import: %+v %v", p, err)
	}
	in.Version = "2"
	_, err = svc.Import(context.Background(), in, "https://example.org/r.tar.gz", "sha256:"+strings.Repeat("0", 64))
	var de *shared.DomainError
	if !errors.As(err, &de) || de.Code != "CONTENT_DIGEST_MISMATCH" {
		t.Fatalf("mismatch: %v", err)
	}
	for _, u := range []string{"http://example.org/r.tar.gz", "https://user:pw@example.org/r", "file:///etc/passwd", "https:///x"} {
		if _, err := svc.Import(context.Background(), in, u, digest); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%s: %v", u, err)
		}
	}
	if len(fetched) != 2 {
		t.Fatalf("fetched %d times (a refused url was fetched)", len(fetched))
	}
	if _, err := svc.Import(context.Background(), in, "https://example.org/r", "md5:x"); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("bad digest: %v", err)
	}
}

// SECURITY: the real fetcher refuses private and loopback addresses.
func TestSafeFetchRefusesPrivateAddresses(t *testing.T) {
	for _, u := range []string{"https://127.0.0.1/x", "https://169.254.169.254/latest/meta-data", "https://10.0.0.1/x"} {
		if _, err := safeFetch(context.Background(), u); err == nil {
			t.Errorf("%s fetched", u)
		}
	}
}

const lfiTemplate = `id: org-lfi
info:
  name: LFI
  severity: high
http:
  - method: GET
    path:
      - "{{BaseURL}}/?file=../../../../etc/passwd"
    matchers:
      - type: regex
        regex: ["root:.*:0:0:"]
`

// An attack payload in a request (/etc/passwd) refuses a tenant template
// but makes an upstream template T2; a code-protocol template is refused in
// both.
func TestUpstreamPayloadsAreT2(t *testing.T) {
	files := []dom.File{{Path: "lfi.yaml", Data: []byte(lfiTemplate)}}
	if rep := Lint(context.Background(), dom.KindNucleiTemplates, files); len(rep.Errors) == 0 {
		t.Fatal("a tenant template with attack payloads was accepted")
	}
	rep, excl := LintExcluding(context.Background(), dom.KindNucleiTemplates, append(files, dom.File{Path: "code.yaml", Data: []byte(codeTemplate)}))
	if len(rep.Errors) != 0 || rep.Tier != dom.TierT2 || rep.Items != 1 || !excl["code.yaml"] || excl["lfi.yaml"] {
		t.Fatalf("upstream: %+v %v", rep, excl)
	}
}
