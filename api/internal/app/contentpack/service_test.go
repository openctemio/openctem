package contentpack

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	dom "github.com/openctemio/openctem/api/pkg/domain/contentpack"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// memRepo is an in-memory, tenant-scoped dom.Repository.
type memRepo struct {
	mu    sync.Mutex
	blobs map[string]*dom.Blob // tenant|digest
	packs map[string]*dom.Pack // id
}

func newMemRepo() *memRepo {
	return &memRepo{blobs: map[string]*dom.Blob{}, packs: map[string]*dom.Pack{}}
}

func (m *memRepo) GetBlob(_ context.Context, tid shared.ID, d string) (*dom.Blob, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if b, ok := m.blobs[tid.String()+"|"+d]; ok {
		c := *b
		return &c, nil
	}
	return nil, dom.ErrNotFound
}

func (m *memRepo) CreateBlob(_ context.Context, b *dom.Blob) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := b.TenantID.String() + "|" + b.Digest
	if _, ok := m.blobs[k]; ok {
		return false, nil
	}
	c := *b
	m.blobs[k] = &c
	return true, nil
}

func (m *memRepo) Create(_ context.Context, p *dom.Pack) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.blobs[p.TenantID.String()+"|"+p.Digest]; !ok {
		return errors.New("foreign key: no blob")
	}
	for _, o := range m.packs {
		if o.TenantID == p.TenantID && o.Name == p.Name && o.Version == p.Version {
			return dom.ErrExists
		}
	}
	c := *p
	m.packs[p.ID.String()] = &c
	return nil
}

func (m *memRepo) GetByID(_ context.Context, tid, id shared.ID) (*dom.Pack, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if p, ok := m.packs[id.String()]; ok && p.TenantID == tid {
		c := *p
		return &c, nil
	}
	return nil, dom.ErrNotFound
}

func (m *memRepo) List(_ context.Context, tid shared.ID, f dom.Filter, limit, offset int) ([]*dom.Pack, int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*dom.Pack
	for _, p := range m.packs {
		if p.TenantID == tid && (f.Kind == "" || p.Kind == f.Kind) && (f.Status == "" || p.Status == f.Status) {
			out = append(out, p)
		}
	}
	return out, len(out), nil
}

func (m *memRepo) Revoke(_ context.Context, tid, id shared.ID, by *shared.ID, reason string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.packs[id.String()]
	if !ok || p.TenantID != tid {
		return dom.ErrNotFound
	}
	if p.Status != dom.StatusActive {
		return dom.ErrNotActive
	}
	p.Status, p.RevokedAt, p.RevokedBy, p.RevokeReason = dom.StatusRevoked, &at, by, reason
	return nil
}

func (m *memRepo) Usage(_ context.Context, tid shared.ID) (int, int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n, b := 0, int64(0)
	for _, p := range m.packs {
		if p.TenantID == tid {
			n++
		}
	}
	for _, bl := range m.blobs {
		if bl.TenantID == tid {
			b += bl.SizeBytes
		}
	}
	return n, b, nil
}

// memStore is a tenant-namespaced Storage.
type memStore struct {
	mu      sync.Mutex
	objects map[string][]byte // tenant/key
	uploads int
}

func (s *memStore) Upload(_ context.Context, tenantID, filename, _ string, r io.Reader) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := io.ReadAll(r)
	if err != nil {
		return "", err
	}
	s.uploads++
	key := fmt.Sprintf("%d_%s", s.uploads, filename)
	s.objects[tenantID+"/"+key] = data
	return key, nil
}

func (s *memStore) Download(_ context.Context, tenantID, key string) (io.ReadCloser, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.objects[tenantID+"/"+key]
	if !ok {
		return nil, "", errors.New("not found")
	}
	return io.NopCloser(bytes.NewReader(d)), "application/x-tar", nil
}

func (s *memStore) Delete(_ context.Context, tenantID, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.objects, tenantID+"/"+key)
	return nil
}

type recAudit struct{ events []auditapp.AuditEvent }

func (r *recAudit) LogEvent(_ context.Context, _ auditapp.AuditContext, e auditapp.AuditEvent) error {
	r.events = append(r.events, e)
	return nil
}

func tarOf(t *testing.T, files map[string]string) io.Reader {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for name, data := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(data))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(data)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return &buf
}

const passiveTemplate = `id: org-banner
info:
  name: Org banner
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: word
        words: ["acme"]
`

const oobTemplate = `id: org-oob
info:
  name: Org OOB
  severity: high
http:
  - method: GET
    path:
      - "{{BaseURL}}/?u={{interactsh-url}}"
    matchers:
      - type: word
        part: interactsh_protocol
        words: ["dns"]
`

const codeTemplate = `id: org-code
info:
  name: runs code
  severity: high
code:
  - engine: [sh]
    source: id
`

func newTestService(t *testing.T) (*Service, *memRepo, *memStore, *recAudit) {
	t.Helper()
	signer, err := dom.NewSigner(bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	repo, store, aud := newMemRepo(), &memStore{objects: map[string][]byte{}}, &recAudit{}
	return NewService(repo, store, signer, aud, logger.NewNop()), repo, store, aud
}

var (
	tenantA = shared.NewID().String()
	tenantB = shared.NewID().String()
)

func TestUploadLintsSignsAndStores(t *testing.T) {
	svc, _, store, aud := newTestService(t)
	ctx := context.Background()
	p, err := svc.Upload(ctx, UploadInput{
		TenantID: tenantA, Name: "org-custom", Version: "1.0.0", Kind: dom.KindNucleiTemplates,
		Archive: tarOf(t, map[string]string{"http/banner.yaml": passiveTemplate, "http/oob.yaml": oobTemplate, "payloads/users.txt": "admin\n"}),
	}, auditapp.AuditContext{TenantID: tenantA})
	if err != nil {
		t.Fatal(err)
	}
	if p.Tier != dom.TierT2 || p.Lint.Items != 2 || p.FileCount != 3 || p.Status != dom.StatusActive {
		t.Fatalf("pack %+v lint %+v", p, p.Lint)
	}
	// The signature verifies with the tenant's published key and binds the
	// digest of what was stored.
	keyB64, _, err := svc.SigningKey(tenantA)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := base64.StdEncoding.DecodeString(keyB64)
	st, err := dom.Verify(p.Signature, pub)
	if err != nil || st.Digest != p.Digest || st.TenantID != tenantA || st.Tier != dom.TierT2 {
		t.Fatalf("statement %+v %v", st, err)
	}
	got, data, err := svc.Archive(ctx, tenantA, p.ID.String())
	if err != nil || got.Digest != p.Digest {
		t.Fatalf("archive: %v", err)
	}
	if _, err := dom.ReadCanonical(data, p.Digest); err != nil {
		t.Fatal(err)
	}
	if len(aud.events) != 1 || aud.events[0].Action != auditdom.ActionContentPackCreated {
		t.Fatalf("audit %+v", aud.events)
	}

	// The same bytes under a new version reuse the blob; the same name and
	// version is a conflict.
	if _, err := svc.Upload(ctx, UploadInput{TenantID: tenantA, Name: "org-custom", Version: "1.0.1", Kind: dom.KindNucleiTemplates,
		Archive: tarOf(t, map[string]string{"payloads/users.txt": "admin\n", "http/oob.yaml": oobTemplate, "http/banner.yaml": passiveTemplate})}, auditapp.AuditContext{}); err != nil {
		t.Fatal(err)
	}
	if store.uploads != 1 {
		t.Fatalf("stored %d objects for one digest", store.uploads)
	}
	if _, err := svc.Upload(ctx, UploadInput{TenantID: tenantA, Name: "org-custom", Version: "1.0.0", Kind: dom.KindNucleiTemplates,
		Archive: tarOf(t, map[string]string{"a.yaml": passiveTemplate})}, auditapp.AuditContext{}); !errors.Is(err, dom.ErrExists) {
		t.Fatalf("duplicate version: %v", err)
	}
}

// SECURITY: another tenant never reaches a pack, by id, list or archive,
// and the same bytes are a separate blob in its own namespace.
func TestPacksAreTenantIsolated(t *testing.T) {
	svc, _, store, _ := newTestService(t)
	ctx := context.Background()
	p, err := svc.Upload(ctx, UploadInput{TenantID: tenantA, Name: "org", Version: "1", Kind: dom.KindWordlist,
		Archive: tarOf(t, map[string]string{"words.txt": "a\nb\n"})}, auditapp.AuditContext{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Get(ctx, tenantB, p.ID.String()); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant get: %v", err)
	}
	if _, _, err := svc.Archive(ctx, tenantB, p.ID.String()); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant archive: %v", err)
	}
	if _, err := svc.Revoke(ctx, tenantB, p.ID.String(), "x", auditapp.AuditContext{}); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant revoke: %v", err)
	}
	if list, _, _ := svc.List(ctx, ListInput{TenantID: tenantB}); len(list) != 0 {
		t.Fatal("cross-tenant list")
	}
	pb, err := svc.Upload(ctx, UploadInput{TenantID: tenantB, Name: "org", Version: "1", Kind: dom.KindWordlist,
		Archive: tarOf(t, map[string]string{"words.txt": "a\nb\n"})}, auditapp.AuditContext{})
	if err != nil {
		t.Fatal(err)
	}
	if pb.Digest != p.Digest || store.uploads != 2 {
		t.Fatalf("tenants share a blob: uploads %d", store.uploads)
	}
	ka, _, _ := svc.SigningKey(tenantA)
	kb, _, _ := svc.SigningKey(tenantB)
	pubB, _ := base64.StdEncoding.DecodeString(kb)
	if ka == kb {
		t.Fatal("tenants share a signing key")
	}
	if _, err := dom.Verify(p.Signature, pubB); err == nil {
		t.Fatal("tenant A's pack verifies with tenant B's key")
	}
}

// SECURITY: content that runs code is refused, credentials block a pack
// until acknowledged, and nothing is stored for a refused pack.
func TestUploadRefusals(t *testing.T) {
	svc, _, store, aud := newTestService(t)
	ctx := context.Background()
	_, err := svc.Upload(ctx, UploadInput{TenantID: tenantA, Name: "bad", Version: "1", Kind: dom.KindNucleiTemplates,
		Archive: tarOf(t, map[string]string{"code.yaml": codeTemplate})}, auditapp.AuditContext{})
	var de *shared.DomainError
	if !errors.As(err, &de) || de.Code != "CONTENT_LINT_FAILED" || !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("code template: %v", err)
	}
	if rep, ok := de.Details.(dom.LintReport); !ok || len(rep.Errors) == 0 {
		t.Fatalf("details %+v", de.Details)
	}

	secret := "words\nAKIAABCDEFGHIJKLMNOP\n"
	_, err = svc.Upload(ctx, UploadInput{TenantID: tenantA, Name: "leaky", Version: "1", Kind: dom.KindWordlist,
		Archive: tarOf(t, map[string]string{"w.txt": secret})}, auditapp.AuditContext{})
	if !errors.As(err, &de) || de.Code != "CONTENT_SECRETS_FOUND" {
		t.Fatalf("secret: %v", err)
	}
	if rep := de.Details.(dom.LintReport); len(rep.Secrets) != 1 || strings.Contains(fmt.Sprint(rep), "AKIA") {
		t.Fatalf("secret report leaks or misses: %+v", rep)
	}
	if store.uploads != 0 || len(aud.events) != 0 {
		t.Fatal("a refused pack was stored or audited as created")
	}
	p, err := svc.Upload(ctx, UploadInput{TenantID: tenantA, Name: "leaky", Version: "1", Kind: dom.KindWordlist,
		Archive: tarOf(t, map[string]string{"w.txt": secret}), AcknowledgeSecrets: true}, auditapp.AuditContext{})
	if err != nil || !p.Lint.SecretsAcknowledged {
		t.Fatalf("acknowledged: %v", err)
	}
	if aud.events[0].Severity != auditdom.SeverityHigh {
		t.Fatal("acknowledged secrets not audited as high")
	}

	for name, in := range map[string]UploadInput{
		"unknown kind":    {Name: "a", Version: "1", Kind: "templates"},
		"bad name":        {Name: "../a", Version: "1", Kind: dom.KindWordlist},
		"bad version":     {Name: "a", Version: "1 2", Kind: dom.KindWordlist},
		"symlink archive": {Name: "a", Version: "1", Kind: dom.KindWordlist},
		"empty nuclei":    {Name: "a", Version: "1", Kind: dom.KindNucleiTemplates},
		"binary wordlist": {Name: "a", Version: "1", Kind: dom.KindWordlist},
	} {
		in.TenantID = tenantA
		switch name {
		case "symlink archive":
			var buf bytes.Buffer
			tw := tar.NewWriter(&buf)
			_ = tw.WriteHeader(&tar.Header{Name: "l", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"})
			_ = tw.Close()
			in.Archive = &buf
		case "empty nuclei":
			in.Archive = tarOf(t, map[string]string{"README.md": "hi"})
		case "binary wordlist":
			in.Archive = tarOf(t, map[string]string{"w.bin": "a\x00b"})
		default:
			in.Archive = tarOf(t, map[string]string{"w.txt": "a"})
		}
		if _, err := svc.Upload(ctx, in, auditapp.AuditContext{}); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%s: %v", name, err)
		}
	}

	// No signing key: nothing is stored unsigned.
	unsigned := NewService(newMemRepo(), store, nil, nil, logger.NewNop())
	if _, err := unsigned.Upload(ctx, UploadInput{TenantID: tenantA, Name: "a", Version: "1", Kind: dom.KindWordlist,
		Archive: tarOf(t, map[string]string{"w.txt": "a"})}, auditapp.AuditContext{}); !errors.Is(err, dom.ErrSigningKey) {
		t.Fatalf("unsigned: %v", err)
	}
}

// SECURITY: tampered storage is never served.
func TestArchiveRefusesTamperedStorage(t *testing.T) {
	svc, _, store, _ := newTestService(t)
	ctx := context.Background()
	p, err := svc.Upload(ctx, UploadInput{TenantID: tenantA, Name: "w", Version: "1", Kind: dom.KindWordlist,
		Archive: tarOf(t, map[string]string{"w.txt": "a\n"})}, auditapp.AuditContext{})
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range store.objects {
		v[600] ^= 1
		store.objects[k] = v
	}
	if _, _, err := svc.Archive(ctx, tenantA, p.ID.String()); !errors.Is(err, shared.ErrInternal) {
		t.Fatalf("tampered archive: %v", err)
	}
}

func TestRevoke(t *testing.T) {
	svc, _, _, aud := newTestService(t)
	ctx := context.Background()
	p, err := svc.Upload(ctx, UploadInput{TenantID: tenantA, Name: "w", Version: "1", Kind: dom.KindWordlist,
		Archive: tarOf(t, map[string]string{"w.txt": "a\n"})}, auditapp.AuditContext{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Revoke(ctx, tenantA, p.ID.String(), " ", auditapp.AuditContext{}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("no reason: %v", err)
	}
	actor := shared.NewID().String()
	r, err := svc.Revoke(ctx, tenantA, p.ID.String(), "bad template", auditapp.AuditContext{ActorID: actor})
	if err != nil || r.Status != dom.StatusRevoked || r.RevokedBy == nil || r.RevokedBy.String() != actor {
		t.Fatalf("revoke: %+v %v", r, err)
	}
	if _, err := svc.Revoke(ctx, tenantA, p.ID.String(), "again", auditapp.AuditContext{}); !errors.Is(err, dom.ErrNotActive) {
		t.Fatalf("revoke twice: %v", err)
	}
	if last := aud.events[len(aud.events)-1]; last.Action != auditdom.ActionContentPackRevoked {
		t.Fatalf("audit %+v", last)
	}
}

func TestClassifyNuclei(t *testing.T) {
	cases := map[string]dom.Tier{
		passiveTemplate: dom.TierT0,
		oobTemplate:     dom.TierT2,
		"id: a\ninfo: {name: a, severity: info}\ndns:\n  - name: \"{{FQDN}}\"\n    type: A\n":                                         dom.TierT1,
		"id: a\ninfo: {name: a, severity: info}\nhttp:\n  - method: DELETE\n    path: [\"{{BaseURL}}/x\"]\n":                          dom.TierT2,
		"id: a\ninfo: {name: a, severity: info}\nhttp:\n  - raw:\n      - \"POST /login HTTP/1.1\\nHost: x\\n\\nuser=a\"\n":           dom.TierT2,
		"id: a\ninfo: {name: a, severity: info}\nhttp:\n  - race: true\n    race_count: 10\n    path: [\"{{BaseURL}}\"]\n":            dom.TierT2,
		"id: a\ninfo: {name: a, severity: info}\nhttp:\n  - method: GET\n    path: [\"{{BaseURL}}/{{p}}\"]\n    payloads: {p: [a]}\n": dom.TierT1,
	}
	for src, want := range cases {
		rep := Lint(context.Background(), dom.KindNucleiTemplates, []dom.File{{Path: "t.yaml", Data: []byte(src)}})
		if len(rep.Errors) > 0 || rep.Tier != want {
			t.Errorf("tier %s want %s (errors %+v) for\n%s", rep.Tier, want, rep.Errors, src)
		}
	}
	rep := Lint(context.Background(), "x-acme/fingerprints", []dom.File{{Path: "f.json", Data: []byte("{}")}})
	if rep.Tier != dom.TierT1 || len(rep.Errors) != 0 {
		t.Fatalf("namespaced kind: %+v", rep)
	}
}
