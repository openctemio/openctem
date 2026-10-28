package contentpack

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	dom "github.com/openctemio/openctem/api/pkg/domain/contentpack"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// chanPlatformRepo adds channels and revocation to memPlatformRepo.
type chanPlatformRepo struct {
	*memPlatformRepo
	mu       sync.Mutex
	channels map[string]dom.ChannelPointer // name|channel
	revoked  map[string]bool
}

func (r *chanPlatformRepo) SetChannel(_ context.Context, id shared.ID, ch dom.Channel, at time.Time) (*dom.ChannelPointer, error) {
	p, err := r.memPlatformRepo.GetByID(context.Background(), id)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := dom.ChannelPointer{Name: p.Name, Channel: ch, PackID: p.ID, Version: p.Version, Digest: p.Digest, UpdatedAt: at}
	r.channels[p.Name+"|"+string(ch)] = cp
	return &cp, nil
}

func (r *chanPlatformRepo) Channels(context.Context) ([]dom.ChannelPointer, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []dom.ChannelPointer
	for _, c := range r.channels {
		out = append(out, c)
	}
	return out, nil
}

func (r *chanPlatformRepo) List(_ context.Context, f dom.Filter, _, _ int) ([]*dom.PlatformPack, int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []*dom.PlatformPack
	for _, p := range r.memPlatformRepo.packs {
		if f.Status == dom.StatusRevoked && r.revoked[p.ID.String()] {
			out = append(out, p)
		}
	}
	return out, len(out), nil
}

func (r *chanPlatformRepo) Revoke(_ context.Context, id shared.ID, _ string, _ time.Time) ([]dom.ChannelPointer, error) {
	p, err := r.memPlatformRepo.GetByID(context.Background(), id)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.revoked[id.String()] = true
	p.Status = dom.StatusRevoked
	for k, c := range r.channels {
		if c.PackID == id {
			delete(r.channels, k)
		}
	}
	return nil, nil
}

type deliveryFixture struct {
	d        *Delivery
	platform *PlatformService
	tenants  *Service
	clock    *time.Time
}

func newDeliveryFixture(t *testing.T) *deliveryFixture {
	t.Helper()
	signer, _ := dom.NewSigner(bytes.Repeat([]byte{5}, 32))
	prepo := &chanPlatformRepo{
		memPlatformRepo: &memPlatformRepo{blobs: map[string]*dom.Blob{}, packs: map[string]*dom.PlatformPack{}},
		channels:        map[string]dom.ChannelPointer{}, revoked: map[string]bool{},
	}
	store := &memStore{objects: map[string][]byte{}}
	platform := NewPlatformService(prepo, store, signer, logger.NewNop())
	tenants := NewService(newMemRepo(), &memStore{objects: map[string][]byte{}}, signer, nil, logger.NewNop())
	d := NewDelivery(tenants, platform)
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	d.now = func() time.Time { return now }
	return &deliveryFixture{d: d, platform: platform, tenants: tenants, clock: &now}
}

func (f *deliveryFixture) platformPack(t *testing.T, name, version string, files map[string]string, promote bool) *dom.PlatformPack {
	t.Helper()
	// A platform wordlist pack must pass the manifest lint: the list is the one
	// the caller gave under dns/labels.txt, wrapped with its manifest and NOTICE.
	packFiles := map[string]string{}
	for path, content := range manifestPack(files["dns/labels.txt"], func(m *WordlistManifest) { m.Pack = name; m.Release = version }) {
		packFiles[path] = string(content)
	}
	p, err := f.platform.Upload(context.Background(), PlatformInput{Name: name, Version: version, Kind: dom.KindWordlist}, bytes.NewReader(tarBytes(t, packFiles)))
	if err != nil {
		t.Fatal(err)
	}
	if promote {
		if _, err := f.platform.MoveChannel(context.Background(), p.ID.String(), dom.ChannelStable); err != nil {
			t.Fatal(err)
		}
	}
	return p
}

// The desired set of a shared sensor is the platform's stable packs only: an
// organization's pack is not in it, not deliverable to it and not served to
// it by digest, however the sensor asks. An organization's own sensor still
// gets both.
func TestInstanceScopeHoldsPlatformPacksOnly(t *testing.T) {
	f := newDeliveryFixture(t)
	ctx := context.Background()
	plat := f.platformPack(t, "wordlists-s", "1", map[string]string{"dns/labels.txt": "www\nmail\n"}, true)
	mine, err := f.tenants.Upload(ctx, UploadInput{TenantID: tenantA, Name: "org-labels", Version: "1", Kind: dom.KindWordlist,
		Archive: tarOf(t, map[string]string{"dns/own.txt": "internal\n"})}, auditapp.AuditContext{TenantID: tenantA})
	if err != nil {
		t.Fatal(err)
	}

	digests := func(scope string) map[string]string {
		doc, _, err := f.d.Desired(ctx, scope)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]string{}
		for _, p := range doc.Packs {
			out[p.Digest] = p.Scope
		}
		return out
	}
	if got := digests(InstanceScope); len(got) != 1 || got[plat.Digest] != ScopePlatform {
		t.Fatalf("instance desired set = %v, want only the platform pack", got)
	}
	if got := digests(tenantA); got[plat.Digest] != ScopePlatform || got[mine.Digest] != ScopeTenant || len(got) != 2 {
		t.Fatalf("organization desired set = %v", got)
	}
	if got := digests(tenantB); len(got) != 1 || got[plat.Digest] == "" {
		t.Fatalf("another organization's desired set = %v", got)
	}

	for scope, want := range map[string]map[string]bool{
		InstanceScope: {plat.Digest: true, mine.Digest: false},
		tenantA:       {plat.Digest: true, mine.Digest: true},
		tenantB:       {plat.Digest: true, mine.Digest: false},
	} {
		for digest, ok := range want {
			got, err := f.d.Deliverable(ctx, scope, digest)
			if err != nil || got != ok {
				t.Errorf("Deliverable(%.8s, %.19s) = %v, %v; want %v", scope, digest, got, err, ok)
			}
		}
	}

	// Served: the platform pack, never the organization's.
	if _, err := f.d.Archive(ctx, InstanceScope, plat.Digest); err != nil {
		t.Errorf("platform archive for a shared sensor: %v", err)
	}
	for name, call := range map[string]func() error{
		"archive": func() error { _, err := f.d.Archive(ctx, InstanceScope, mine.Digest); return err },
		"index":   func() error { _, err := f.d.Index(ctx, InstanceScope, mine.Digest); return err },
		"file":    func() error { _, err := f.d.File(ctx, InstanceScope, mine.Digest, "0000"); return err },
		"other":   func() error { _, err := f.d.Archive(ctx, tenantB, mine.Digest); return err },
	} {
		if err := call(); !errors.Is(err, shared.ErrNotFound) {
			t.Errorf("%s: tenant pack for the wrong scope: %v, want not found", name, err)
		}
	}
	if _, _, err := f.d.Desired(ctx, "not-a-scope"); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("a scope that is neither an organization nor the instance: %v", err)
	}
}

// The content version is the desired set's ETag: it is stable while nothing
// changes and moves when a pack is promoted or revoked.
func TestVersionChangesOnPromotionAndRevocation(t *testing.T) {
	f := newDeliveryFixture(t)
	ctx := context.Background()
	v1 := f.platformPack(t, "wordlists-s", "1", map[string]string{"dns/labels.txt": "www\n"}, true)
	version := func(scope string) string {
		*f.clock = f.clock.Add(desiredTTL + time.Second) // past the memo
		v, err := f.d.Version(ctx, scope)
		if err != nil || v == "" {
			t.Fatalf("version(%s) = %q, %v", scope, v, err)
		}
		return v
	}
	base := version(InstanceScope)
	if again := version(InstanceScope); again != base {
		t.Fatalf("version moved with no change: %s -> %s", base, again)
	}
	if _, etag, _ := f.d.Desired(ctx, InstanceScope); etag != base {
		t.Errorf("the version %s is not the desired document's ETag %s", base, etag)
	}
	// Uploaded but not promoted: not in the set, the version holds.
	v2 := f.platformPack(t, "wordlists-s", "2", map[string]string{"dns/labels.txt": "www\nmail\n"}, false)
	if got := version(InstanceScope); got != base {
		t.Fatalf("an unpromoted pack changed the version")
	}
	// Promotion to stable moves it, for the instance and for organizations.
	if _, err := f.platform.MoveChannel(ctx, v2.ID.String(), dom.ChannelStable); err != nil {
		t.Fatal(err)
	}
	promoted := version(InstanceScope)
	if promoted == base {
		t.Fatal("promoting a pack to stable did not change the content version")
	}
	if version(tenantA) == base {
		t.Error("an organization's content version did not change with the promotion")
	}
	// Revocation moves it again (the revoked digest joins the set).
	if _, _, err := f.platform.Revoke(ctx, v2.ID.String(), "bad list"); err != nil {
		t.Fatal(err)
	}
	if got := version(InstanceScope); got == promoted {
		t.Fatal("revoking a pack did not change the content version")
	}
	_ = v1
}

func TestPlatformStableResolvesByName(t *testing.T) {
	f := newDeliveryFixture(t)
	ctx := context.Background()
	p := f.platformPack(t, "wordlists-s", "1", map[string]string{"dns/labels.txt": "www\n"}, true)
	f.platformPack(t, "wordlists-m", "1", map[string]string{"dns/labels.txt": "www\nmail\n"}, false) // not promoted
	got, err := f.d.PlatformStable(ctx, "wordlists-s")
	if err != nil || got.Digest != p.Digest || got.Kind != dom.KindWordlist || got.Scope != ScopePlatform || len(got.Signature) == 0 {
		t.Fatalf("stable pack = %+v, %v", got, err)
	}
	if _, err := f.d.PlatformStable(ctx, "wordlists-m"); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("a pack that is not on stable resolved: %v", err)
	}
	// A tenant pack of the same name is never a platform pack.
	if _, err := f.tenants.Upload(ctx, UploadInput{TenantID: tenantA, Name: "wordlists-m", Version: "1", Kind: dom.KindWordlist,
		Archive: tarOf(t, map[string]string{"dns/x.txt": "x\n"})}, auditapp.AuditContext{TenantID: tenantA}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.d.PlatformStable(ctx, "wordlists-m"); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("a tenant pack resolved as a platform pack: %v", err)
	}
}
