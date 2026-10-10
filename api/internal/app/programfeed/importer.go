// Package programfeed imports the signed public program feed into the
// platform catalog and brings every subscribed program up to date
// (RFC-065 §16, docs/architecture/bounty-programs.md). The platform never
// calls the bug-bounty platforms: a collector publishes the feed and the
// importer only verifies and applies it.
package programfeed

import (
	"context"
	"errors"
	"fmt"
	"time"

	bp "github.com/openctemio/openctem/api/pkg/domain/bountyprogram"
	"github.com/openctemio/openctem/api/pkg/logger"
	feed "github.com/openctemio/openctem/api/pkg/programfeed"
)

// BundleSource hands the importer a bundle directory (a mirror or an
// uploaded bundle); cleanup removes what it fetched.
type BundleSource interface {
	Fetch(ctx context.Context) (dir string, cleanup func(), err error)
}

// DirSource is a bundle already on disk (an air-gapped upload, a mirror
// synced by the operator).
type DirSource string

// Fetch returns the directory.
func (d DirSource) Fetch(context.Context) (string, func(), error) {
	if d == "" {
		return "", nil, errors.New("no program feed directory configured")
	}
	return string(d), func() {}, nil
}

// Subscriptions applies a catalog change to a subscribed program
// (*bountyprogram.Service).
type Subscriptions interface {
	ApplyFeedChange(ctx context.Context, ref bp.ProgramRef) (string, error)
}

// Importer verifies and applies the program feed.
type Importer struct {
	source     BundleSource
	catalog    bp.CatalogRepository
	subs       Subscriptions
	parser     feed.RecordParser
	pinnedRoot string
	log        *logger.Logger
	now        func() time.Time
}

// NewImporter wires the importer. pinnedRoot is the key id of the feed's
// offline root (PROGRAMFEED_ROOT_KEY_ID); without it nothing is imported.
func NewImporter(source BundleSource, catalog bp.CatalogRepository, subs Subscriptions, pinnedRoot string, log *logger.Logger) *Importer {
	if log == nil {
		log = logger.NewNop()
	}
	return &Importer{source: source, catalog: catalog, subs: subs, parser: feed.V1{}, pinnedRoot: pinnedRoot,
		log: log.With("service", "program-feed"), now: func() time.Time { return time.Now().UTC() }}
}

// Result is what one import did.
type Result struct {
	Sequence uint64
	// Delta: the delta was applied (otherwise the snapshot).
	Delta    bool
	Programs int
	Changes  int
	// Subscribers counts subscribed programs by outcome.
	Subscribers map[string]int
}

// Import fetches, verifies and applies the newest bundle. A bundle that is
// not newer than the applied one is not an error (nothing to do).
func (i *Importer) Import(ctx context.Context) (*Result, error) {
	if i.pinnedRoot == "" {
		return nil, errors.New("program feed root key id is not configured")
	}
	state, err := i.catalog.FeedState(ctx)
	if err != nil {
		return nil, err
	}
	dir, cleanup, err := i.source.Fetch(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetch program feed: %w", err)
	}
	defer cleanup()
	v, err := feed.VerifyDir(dir, feed.Options{PinnedRoot: i.pinnedRoot, MinKeySetVersion: state.KeySetVersion,
		AppliedSequence: state.AppliedSequence, Now: i.now()})
	if errors.Is(err, feed.ErrNotNewer) {
		return &Result{Sequence: state.AppliedSequence}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("program feed refused: %w", err)
	}
	programs, feedChanges, err := v.Read(i.parser)
	if err != nil {
		return nil, fmt.Errorf("program feed refused: %w", err)
	}
	apply := bp.FeedApply{State: bp.FeedState{AppliedSequence: v.Latest.Sequence, KeySetVersion: v.KeySet.Version},
		Snapshot: !v.IsDelta(), Programs: programs}
	for _, c := range feedChanges {
		if c.Kind == bp.FeedChangeDropped {
			apply.Dropped = append(apply.Dropped, c.Program)
		}
	}
	changes, err := i.catalog.Apply(ctx, apply)
	if err != nil {
		return nil, err
	}
	res := &Result{Sequence: v.Latest.Sequence, Delta: v.IsDelta(), Programs: len(programs), Changes: len(changes)}
	res.Subscribers = i.Reconcile(ctx)
	i.log.Info("program feed imported", "sequence", res.Sequence, "programs", res.Programs, "changes", res.Changes)
	return res, nil
}

// OutcomeFailed counts subscribed programs whose update failed.
const OutcomeFailed = "failed"

// reconcileBatches bounds one reconcile pass (batches of 200).
const reconcileBatches = 25

// Reconcile brings every subscribed program that differs from its catalog
// program up to date. It runs after each import and on every tick, so a
// program whose update failed is retried until it succeeds.
func (i *Importer) Reconcile(ctx context.Context) map[string]int {
	out := map[string]int{}
	failed := map[string]bool{}
	for range reconcileBatches {
		refs, err := i.catalog.StaleSubscriptions(ctx, 200)
		if err != nil {
			i.log.Warn("program feed: subscriptions not read", "error", err)
			return out
		}
		progressed := false
		for _, ref := range refs {
			key := ref.TenantID.String() + "/" + ref.ProgramID.String()
			if failed[key] {
				continue
			}
			outcome, err := i.subs.ApplyFeedChange(ctx, ref)
			if err != nil || outcome == "" {
				// "" with no error: nothing to do for it (ended, unlinked).
				if err != nil {
					i.log.Warn("program feed: subscribed program not updated", "program_id", ref.ProgramID.String(), "error", err)
				}
				failed[key] = true
				out[OutcomeFailed]++
				continue
			}
			out[outcome]++
			progressed = true
		}
		if !progressed {
			break
		}
	}
	return out
}
