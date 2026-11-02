package contentpin

// The built-in wordlist seed (docs/architecture/wordlists.md, research 344
// D1). At start the API installs each embedded pack whose name has no stable
// channel yet, so the platform always has a list for subdomain enumeration
// without an import or internet access.
//
// Threat model. The seed is the reproducible build of the pinned upstream
// files (builtin.Packs checks each archive against its recorded sha256) and
// goes through the same canonicalisation, lint and platform signature as an
// administrator's upload. It never replaces a stable channel that exists:
// an administrator's import, or choice of an older release, stands. Platform
// packs are public to every organization, so nothing tenant-specific is
// involved.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/openctemio/openctem/api/internal/app/contentpack"
	"github.com/openctemio/openctem/api/internal/app/contentpin/builtin"
	dom "github.com/openctemio/openctem/api/pkg/domain/contentpack"
)

// kindWordlist is the content kind of a wordlist pack.
const kindWordlist = "wordlist"

// errBuiltinWithdrawn: the embedded release is in the store but revoked.
var errBuiltinWithdrawn = errors.New("builtin wordlist release revoked")

// BuiltinStore is what installing the seed needs of the platform pack store
// (contentpack.PlatformService).
type BuiltinStore interface {
	Channels(ctx context.Context) ([]dom.ChannelPointer, error)
	UploadBuiltin(ctx context.Context, in contentpack.PlatformInput, archive io.Reader, ref string) (*dom.PlatformPack, error)
	List(ctx context.Context, f dom.Filter, limit, offset int) ([]*dom.PlatformPack, int, error)
	MoveChannel(ctx context.Context, id string, channel dom.Channel) (*dom.ChannelPointer, error)
}

// InstallBuiltin installs the embedded wordlist packs whose names have no
// stable channel and points stable at them. It returns the names it set. It
// is idempotent and safe when several API replicas start together: the
// second to ingest finds the pack by name and version.
func InstallBuiltin(ctx context.Context, store BuiltinStore, log *slog.Logger) ([]string, error) {
	if log == nil {
		log = slog.Default()
	}
	packs, err := builtin.Packs()
	if err != nil {
		return nil, err
	}
	return installPacks(ctx, store, packs, log)
}

func installPacks(ctx context.Context, store BuiltinStore, packs []builtin.Pack, log *slog.Logger) ([]string, error) {
	chans, err := store.Channels(ctx)
	if err != nil {
		return nil, fmt.Errorf("read channels: %w", err)
	}
	stable := map[string]bool{}
	for _, c := range chans {
		if c.Channel == dom.ChannelStable {
			stable[c.Name] = true
		}
	}
	set := make([]string, 0, len(packs))
	for _, p := range packs {
		if stable[p.Name] {
			continue
		}
		pack, err := ingestBuiltin(ctx, store, p)
		if errors.Is(err, errBuiltinWithdrawn) {
			log.Warn("built-in wordlist pack not installed: an administrator revoked this release", "pack", p.Name, "version", p.Release)
			continue
		}
		if err != nil {
			return set, err
		}
		if pack.Digest != p.PackDigest {
			// The platform's canonical form differs from the build's: the
			// pack is not the recorded release, so it is not offered.
			return set, fmt.Errorf("builtin %s: ingested digest %s, release records %s", p.Asset, pack.Digest, p.PackDigest)
		}
		if _, err := store.MoveChannel(ctx, pack.ID.String(), dom.ChannelStable); err != nil {
			return set, fmt.Errorf("builtin %s: move stable: %w", p.Asset, err)
		}
		log.Info("built-in wordlist pack installed", "pack", p.Name, "version", p.Release, "digest", pack.Digest)
		set = append(set, p.Name)
	}
	return set, nil
}

func ingestBuiltin(ctx context.Context, store BuiltinStore, p builtin.Pack) (*dom.PlatformPack, error) {
	in := contentpack.PlatformInput{Name: p.Name, Version: p.Release, Kind: kindWordlist}
	pack, err := store.UploadBuiltin(ctx, in, bytes.NewReader(p.Archive), "builtin:"+p.Asset)
	if err == nil {
		return pack, nil
	}
	if !errors.Is(err, dom.ErrExists) {
		return nil, fmt.Errorf("builtin %s: %w", p.Asset, err)
	}
	// Ingested before (by another replica, or an administrator uploaded the
	// same release): use that pack when it is active.
	got, _, lerr := store.List(ctx, dom.Filter{Name: p.Name, Kind: kindWordlist, Status: dom.StatusActive}, 100, 0)
	if lerr != nil {
		return nil, fmt.Errorf("builtin %s: %w", p.Asset, lerr)
	}
	for _, g := range got {
		if g.Version == p.Release {
			return g, nil
		}
	}
	// The release exists but is revoked: an administrator withdrew it.
	return nil, errBuiltinWithdrawn
}
