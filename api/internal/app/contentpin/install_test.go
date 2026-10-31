package contentpin

import (
	"bytes"
	"context"
	"errors"
	"io"
	"slices"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/contentpack"
	"github.com/openctemio/openctem/api/internal/app/contentpin/builtin"
	dom "github.com/openctemio/openctem/api/pkg/domain/contentpack"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The embedded seed is the recorded build: each archive matches release.json,
// passes the platform linter with nothing left out, and canonicalises to
// the recorded pack digest. The small pack holds the DNS list coverage reads.
func TestBuiltinPacks_AreTheRecordedBuild(t *testing.T) {
	packs, err := builtin.Packs()
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, p := range packs {
		names = append(names, p.Name)
		arc, err := dom.Canonicalize(bytes.NewReader(p.Archive), dom.PlatformLimits)
		if err != nil {
			t.Fatalf("%s: %v", p.Asset, err)
		}
		if arc.Digest != p.PackDigest {
			t.Fatalf("%s: canonical digest %s, release.json records %s", p.Asset, arc.Digest, p.PackDigest)
		}
		rep, excluded := contentpack.LintExcluding(context.Background(), kindWordlist, arc.Files)
		if len(rep.Errors) > 0 || len(excluded) > 0 {
			t.Fatalf("%s: lint errors %v, excluded %v", p.Asset, rep.Errors, excluded)
		}
		if p.Release == "" || len(p.Lines) == 0 {
			t.Fatalf("%s: no release or lines recorded", p.Asset)
		}
	}
	if !slices.Equal(names, []string{"wordlists-s", "wordlists-m"}) {
		t.Fatalf("embedded packs %v, want wordlists-s and wordlists-m", names)
	}
	if packs[0].Lines["dns/labels-s.txt"] < 1000 {
		t.Fatalf("the small pack's DNS list has %d lines", packs[0].Lines["dns/labels-s.txt"])
	}
}

type fakeBuiltinStore struct {
	packs    []*dom.PlatformPack
	channels []dom.ChannelPointer
	uploads  int
	// digest overrides the digest an upload gets (a canonical form that
	// differs from the build's).
	digest string
}

func (f *fakeBuiltinStore) Channels(context.Context) ([]dom.ChannelPointer, error) {
	return f.channels, nil
}

func (f *fakeBuiltinStore) UploadBuiltin(_ context.Context, in contentpack.PlatformInput, r io.Reader, ref string) (*dom.PlatformPack, error) {
	for _, p := range f.packs {
		if p.Name == in.Name && p.Version == in.Version {
			return nil, dom.ErrExists
		}
	}
	data, _ := io.ReadAll(r)
	arc, err := dom.Canonicalize(bytes.NewReader(data), dom.PlatformLimits)
	if err != nil {
		return nil, err
	}
	digest := arc.Digest
	if f.digest != "" {
		digest = f.digest
	}
	f.uploads++
	p := &dom.PlatformPack{Pack: dom.Pack{ID: shared.NewID(), Name: in.Name, Version: in.Version, Kind: in.Kind,
		Digest: digest, Status: dom.StatusActive, Source: dom.SourceUpload, SourceRef: ref}}
	f.packs = append(f.packs, p)
	return p, nil
}

func (f *fakeBuiltinStore) List(_ context.Context, fl dom.Filter, _, _ int) ([]*dom.PlatformPack, int, error) {
	var out []*dom.PlatformPack
	for _, p := range f.packs {
		if p.Name == fl.Name && (fl.Status == "" || p.Status == fl.Status) {
			out = append(out, p)
		}
	}
	return out, len(out), nil
}

func (f *fakeBuiltinStore) MoveChannel(_ context.Context, id string, ch dom.Channel) (*dom.ChannelPointer, error) {
	for _, p := range f.packs {
		if p.ID.String() == id {
			f.channels = slices.DeleteFunc(f.channels, func(c dom.ChannelPointer) bool { return c.Name == p.Name && c.Channel == ch })
			cp := dom.ChannelPointer{Name: p.Name, Channel: ch, PackID: p.ID, Version: p.Version, Digest: p.Digest}
			f.channels = append(f.channels, cp)
			return &cp, nil
		}
	}
	return nil, dom.ErrNotFound
}

func (f *fakeBuiltinStore) stable(name string) *dom.ChannelPointer {
	for i, c := range f.channels {
		if c.Name == name && c.Channel == dom.ChannelStable {
			return &f.channels[i]
		}
	}
	return nil
}

// A fresh platform gets both packs on stable, recorded as built-in uploads;
// a second start changes nothing.
func TestInstallBuiltin_FreshPlatform(t *testing.T) {
	store := &fakeBuiltinStore{}
	set, err := InstallBuiltin(context.Background(), store, quiet())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(set, []string{"wordlists-s", "wordlists-m"}) {
		t.Fatalf("set %v", set)
	}
	for _, name := range set {
		c := store.stable(name)
		if c == nil || c.Version == "" {
			t.Fatalf("%s has no stable channel", name)
		}
	}
	if store.packs[0].SourceRef != "builtin:wordlists-s-"+store.packs[0].Version+".tar.gz" || store.packs[0].Kind != kindWordlist {
		t.Fatalf("pack recorded as %+v", store.packs[0].Pack)
	}
	again, err := InstallBuiltin(context.Background(), store, quiet())
	if err != nil || len(again) != 0 || store.uploads != 2 {
		t.Fatalf("second start: set %v, err %v, uploads %d", again, err, store.uploads)
	}
}

// An administrator's stable channel (a newer import, or a deliberate older
// release) is never moved by the seed.
func TestInstallBuiltin_KeepsAdministratorsStable(t *testing.T) {
	admin := &dom.PlatformPack{Pack: dom.Pack{ID: shared.NewID(), Name: "wordlists-s", Version: "2099.1.1", Kind: kindWordlist, Status: dom.StatusActive}}
	store := &fakeBuiltinStore{packs: []*dom.PlatformPack{admin},
		channels: []dom.ChannelPointer{{Name: "wordlists-s", Channel: dom.ChannelStable, PackID: admin.ID, Version: admin.Version}}}
	set, err := InstallBuiltin(context.Background(), store, quiet())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(set, []string{"wordlists-m"}) {
		t.Fatalf("set %v, want only the pack without a stable channel", set)
	}
	if c := store.stable("wordlists-s"); c == nil || c.PackID != admin.ID {
		t.Fatalf("the administrator's stable channel moved: %+v", c)
	}
}

// Another replica ingested the release first: the pack is found by name and
// version and stable points at it. A revoked release is not reinstated.
func TestInstallBuiltin_ExistingAndRevokedReleases(t *testing.T) {
	packs, err := builtin.Packs()
	if err != nil {
		t.Fatal(err)
	}
	other := &dom.PlatformPack{Pack: dom.Pack{ID: shared.NewID(), Name: "wordlists-s", Version: packs[0].Release,
		Kind: kindWordlist, Digest: packs[0].PackDigest, Status: dom.StatusActive}}
	revoked := &dom.PlatformPack{Pack: dom.Pack{ID: shared.NewID(), Name: "wordlists-m", Version: packs[1].Release,
		Kind: kindWordlist, Digest: packs[1].PackDigest, Status: dom.StatusRevoked}}
	store := &fakeBuiltinStore{packs: []*dom.PlatformPack{other, revoked}}
	set, err := InstallBuiltin(context.Background(), store, quiet())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(set, []string{"wordlists-s"}) || store.uploads != 0 {
		t.Fatalf("set %v uploads %d", set, store.uploads)
	}
	if c := store.stable("wordlists-s"); c == nil || c.PackID != other.ID {
		t.Fatalf("stable %+v, want the existing pack", c)
	}
	if store.stable("wordlists-m") != nil {
		t.Fatal("a revoked release was put back on stable")
	}
}

// A pack whose ingested digest is not the recorded one is not offered.
func TestInstallBuiltin_DigestMismatchRefused(t *testing.T) {
	store := &fakeBuiltinStore{digest: "sha256:" + string(bytes.Repeat([]byte("0"), 64))}
	_, err := InstallBuiltin(context.Background(), store, quiet())
	if err == nil {
		t.Fatal("a pack with another digest was put on stable")
	}
	if store.stable("wordlists-s") != nil {
		t.Fatal("stable set despite the mismatch")
	}
}

var _ BuiltinStore = (*contentpack.PlatformService)(nil)

func TestInstallBuiltin_StoreErrorsSurface(t *testing.T) {
	if _, err := installPacks(context.Background(), &errStore{}, nil, quiet()); !errors.Is(err, errBoom) {
		t.Fatalf("err %v", err)
	}
}

var errBoom = errors.New("boom")

type errStore struct{ fakeBuiltinStore }

func (*errStore) Channels(context.Context) ([]dom.ChannelPointer, error) { return nil, errBoom }
