package contentrule

// The built-in rule packs (docs/architecture/rule-packs.md). At start the
// API installs each embedded pack whose name has no stable channel yet and
// points stable at it, so detection rules work on a fresh install with no
// import. An administrator's import, or choice of another release, stands:
// a stable channel that exists is never moved. The packs go through the
// same canonical form, lint and platform signature as an upload.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/openctemio/openctem/api/internal/app/contentpack"
	"github.com/openctemio/openctem/api/internal/app/contentpin"
	"github.com/openctemio/openctem/api/internal/app/contentrule/builtin"
	dom "github.com/openctemio/openctem/api/pkg/domain/contentpack"
)

// InstallBuiltin installs the embedded rule packs whose names have no
// stable channel and returns the names it set. Idempotent and safe when
// several replicas start together.
func InstallBuiltin(ctx context.Context, store contentpin.BuiltinStore, log *slog.Logger) ([]string, error) {
	if log == nil {
		log = slog.Default()
	}
	packs, err := builtin.Packs()
	if err != nil {
		return nil, err
	}
	return installPacks(ctx, store, packs, log)
}

func installPacks(ctx context.Context, store contentpin.BuiltinStore, packs []builtin.Pack, log *slog.Logger) ([]string, error) {
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
		pack, err := ingest(ctx, store, p)
		if errors.Is(err, errWithdrawn) {
			log.Warn("built-in rule pack not installed: an administrator revoked this release", "pack", p.Name, "version", p.Release)
			continue
		}
		if err != nil {
			return set, err
		}
		if _, err := store.MoveChannel(ctx, pack.ID.String(), dom.ChannelStable); err != nil {
			return set, fmt.Errorf("builtin %s: move stable: %w", p.Name, err)
		}
		log.Info("built-in rule pack installed", "pack", p.Name, "version", p.Release, "digest", pack.Digest)
		set = append(set, p.Name)
	}
	return set, nil
}

var errWithdrawn = errors.New("builtin rule pack release revoked")

func ingest(ctx context.Context, store contentpin.BuiltinStore, p builtin.Pack) (*dom.PlatformPack, error) {
	archive, err := p.Archive()
	if err != nil {
		return nil, fmt.Errorf("builtin %s: %w", p.Name, err)
	}
	in := contentpack.PlatformInput{Name: p.Name, Version: p.Release, Kind: p.Kind}
	pack, err := store.UploadBuiltin(ctx, in, bytes.NewReader(archive), "builtin:"+p.Name+"-"+p.Release)
	if err == nil {
		return pack, nil
	}
	if !errors.Is(err, dom.ErrExists) {
		return nil, fmt.Errorf("builtin %s: %w", p.Name, err)
	}
	got, _, lerr := store.List(ctx, dom.Filter{Name: p.Name, Kind: p.Kind, Status: dom.StatusActive}, 100, 0)
	if lerr != nil {
		return nil, fmt.Errorf("builtin %s: %w", p.Name, lerr)
	}
	for _, g := range got {
		if g.Version == p.Release {
			return g, nil
		}
	}
	return nil, errWithdrawn
}
