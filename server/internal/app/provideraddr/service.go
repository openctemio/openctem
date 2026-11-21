// Package provideraddr runs the one-time provider-address move for one
// organization (docs/architecture/provider-address-move.md, runbook
// docs/operations/provider-address-move.md).
//
// A dry run (the default) reads everything and writes only its run row with
// the counts. An apply runs the same plan batch by batch: each batch is one
// transaction under the organization's advisory lock, with bounded lock waits
// and statements, and moves the run's cursor, so an interrupted apply
// resumes where it stopped and a second apply changes nothing. A restore
// puts back what an apply changed, item by item, unless the address changed
// since. The move never runs by itself: an operator starts it.
package provideraddr

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/server/pkg/domain/audit"
	"github.com/openctemio/openctem/server/pkg/domain/edgeaddr"
	pa "github.com/openctemio/openctem/server/pkg/domain/provideraddr"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// DefaultBatchSize is the number of address assets read per batch.
const DefaultBatchSize = 500

// DefaultMaxShared is the number of shared addresses one batch changes at
// most: measured, a batch of 150 dense provider addresses commits in about
// half a second.
const DefaultMaxShared = 150

// RestoreBatch is the number of journal items one restore batch puts back:
// each item is restored on its own (its address is checked first), so a
// batch of 50 commits in under a second (measured: about 16 ms per item).
const RestoreBatch = 50

// maxAttempts bounds the retries of a batch that hit a lock wait, a time
// limit or a serialization conflict.
const maxAttempts = 5

// Store is the move's storage (postgres.ProviderAddressMoveRepository).
type Store interface {
	StartRun(ctx context.Context, tenantID shared.ID, mode pa.Mode, datasetVersion, actor string, initial pa.Counts) (*pa.Run, error)
	FinishRun(ctx context.Context, tenantID shared.ID, runID, state string, finalize func(pa.Counts), runErr string) (pa.Counts, error)
	SaveDryRun(ctx context.Context, tenantID shared.ID, datasetVersion, actor string, counts pa.Counts, startedAt time.Time) (string, error)
	LoadScopeEntries(ctx context.Context, tenantID shared.ID) ([]pa.ScopeEntry, error)
	InventoryCount(ctx context.Context, tenantID shared.ID) (int, error)
	ProcessBatch(ctx context.Context, req pa.BatchRequest) (pa.BatchResult, error)
	ListAppliedItems(ctx context.Context, tenantID shared.ID, after string, limit int) ([]pa.AppliedItem, error)
	RestoreBatch(ctx context.Context, req pa.RestoreRequest) (pa.RestoreResult, error)
	NoticeCounts(ctx context.Context, tenantID shared.ID) (addresses, names int, providers []string, err error)
	SendNotice(ctx context.Context, tenantID shared.ID, runID string, n pa.Notice) (bool, error)
}

// Auditor writes the organization's audit entry of a run.
type Auditor func(ctx context.Context, tenantID shared.ID, action audit.Action, counts map[string]int) error

// DashboardRefresher asks for one rebuild of the organization's dashboards.
type DashboardRefresher interface {
	RequestRebuild(ctx context.Context, tenantID shared.ID, interval time.Duration) (time.Time, error)
}

// Options control a run.
type Options struct {
	Mode       pa.Mode // dry_run (default), apply or restore
	BatchSize  int
	MaxShared  int // shared addresses per batch at most (default DefaultMaxShared)
	MaxBatches int // stop after this many batches (0 = until done); an apply or restore resumes later
	Classifier *edgeaddr.Classifier
	Actor      string
	// Progress, when set, is told about every committed (or planned) batch.
	Progress func(batch, read int, took time.Duration)
}

// Report is the outcome of a run for one organization.
type Report struct {
	TenantID       string    `json:"tenant_id"`
	Mode           pa.Mode   `json:"mode"`
	RunID          string    `json:"run_id"`
	JobVersion     int       `json:"job_version"`
	DatasetVersion string    `json:"dataset_version"`
	Resumed        bool      `json:"resumed"`
	Completed      bool      `json:"completed"`
	Batches        int       `json:"batches"`
	Scanned        int       `json:"address_assets_read"`
	NoticeSent     bool      `json:"notice_sent"`
	Counts         pa.Counts `json:"counts"`
	Duration       string    `json:"duration"`

	started time.Time
}

// Service runs the move.
type Service struct {
	store     Store
	audit     Auditor
	dashboard DashboardRefresher
	now       func() time.Time
	sleep     func(time.Duration)
}

// NewService creates the move. audit and dashboard may be nil (tests).
func NewService(store Store, auditor Auditor, dashboard DashboardRefresher) *Service {
	return &Service{store: store, audit: auditor, dashboard: dashboard, now: time.Now, sleep: time.Sleep}
}

// Run runs the move for one organization.
func (s *Service) Run(ctx context.Context, tenantID shared.ID, opts Options) (*Report, error) {
	if tenantID.IsZero() {
		return nil, fmt.Errorf("provider addresses: an organization is required")
	}
	if opts.Classifier == nil {
		opts.Classifier = edgeaddr.Default()
	}
	if opts.BatchSize <= 0 {
		opts.BatchSize = DefaultBatchSize
	}
	if opts.Mode == "" {
		opts.Mode = pa.ModeDryRun
	}
	if opts.MaxShared <= 0 {
		opts.MaxShared = DefaultMaxShared
	}
	if opts.Actor == "" {
		opts.Actor = "provider-addresses"
	}
	start := s.now()
	rep := &Report{TenantID: tenantID.String(), Mode: opts.Mode, JobVersion: pa.JobVersion,
		DatasetVersion: opts.Classifier.Version(), Counts: pa.Counts{}, started: start}
	var err error
	switch opts.Mode {
	case pa.ModeDryRun, pa.ModeApply:
		err = s.move(ctx, tenantID, opts, rep)
	case pa.ModeRestore:
		err = s.restore(ctx, tenantID, opts, rep)
	default:
		return nil, fmt.Errorf("provider addresses: unknown mode %q", opts.Mode)
	}
	rep.Duration = s.now().Sub(start).Round(time.Millisecond).String()
	return rep, err
}

// withRetry runs a batch, retrying transient conflicts with a short backoff.
func (s *Service) withRetry(ctx context.Context, f func() error) error {
	var err error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if err = f(); err == nil || !errors.Is(err, pa.ErrTransient) {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		s.sleep(time.Duration(attempt) * 200 * time.Millisecond)
	}
	return err
}

// move is the dry run and the apply: one plan, so the same counts.
func (s *Service) move(ctx context.Context, tenantID shared.ID, opts Options, rep *Report) error {
	apply := opts.Mode == pa.ModeApply
	scope, err := s.store.LoadScopeEntries(ctx, tenantID)
	if err != nil {
		return err
	}
	entries := pa.NewEntries(scope, opts.Classifier)
	inventory, err := s.store.InventoryCount(ctx, tenantID)
	if err != nil {
		return err
	}
	initial := pa.Counts{}
	initial.Merge(entries.Card)
	initial[pa.CountInventoryBefore] = inventory

	var run *pa.Run
	counts := pa.Counts{}
	if apply {
		run, err = s.store.StartRun(ctx, tenantID, pa.ModeApply, opts.Classifier.Version(), opts.Actor, initial)
		if err != nil {
			return err
		}
		rep.RunID, rep.Resumed = run.ID, run.Resumed
		counts.Merge(run.Counts)
	} else {
		counts.Merge(initial)
	}

	// Addresses an earlier pass moved whose range the dataset no longer
	// lists: restored (A4), or counted by a dry run.
	reclassified, err := s.reclassify(ctx, tenantID, opts, apply)
	if err != nil {
		return err
	}
	counts.Add(pa.CountReclassified, reclassified)

	sim := pa.NewSimulation()
	cursor := ""
	for opts.MaxBatches <= 0 || rep.Batches < opts.MaxBatches {
		req := pa.BatchRequest{TenantID: tenantID, Apply: apply, After: cursor, Limit: opts.BatchSize, MaxShared: opts.MaxShared,
			Classifier: opts.Classifier, Entries: entries, Sim: sim, Now: s.now().UTC()}
		if apply {
			req.RunID = run.ID
		}
		var res pa.BatchResult
		began := s.now()
		err := s.withRetry(ctx, func() error {
			var e error
			res, e = s.store.ProcessBatch(ctx, req)
			return e
		})
		if err != nil {
			if apply && errors.Is(err, pa.ErrFindingStatusChanged) {
				_, _ = s.store.FinishRun(ctx, tenantID, run.ID, pa.StateFailed, nil, err.Error())
			}
			rep.Counts = counts
			return err
		}
		rep.Batches++
		rep.Scanned += res.Scanned
		counts.Merge(res.Counts)
		if opts.Progress != nil {
			opts.Progress(rep.Batches, res.Scanned, s.now().Sub(began))
		}
		cursor = res.Cursor
		if res.Done {
			rep.Completed = true
			break
		}
	}
	closing := func(c pa.Counts) {
		c[pa.CountFindingStatusChanges] = 0
		c[pa.CountInventoryAfterExpected] = c[pa.CountInventoryBefore] - c[pa.CountInventoryRemoved]
	}
	closing(counts)
	rep.Counts = counts
	if !apply {
		id, err := s.store.SaveDryRun(ctx, tenantID, opts.Classifier.Version(), opts.Actor, counts, rep.started)
		rep.RunID = id
		return err
	}
	if !rep.Completed {
		return nil // stopped by MaxBatches: the run stays open and resumes
	}
	final, err := s.store.FinishRun(ctx, tenantID, run.ID, pa.StateDone, func(c pa.Counts) {
		c.Add(pa.CountReclassified, reclassified)
		closing(c)
	}, "")
	if err != nil {
		return err
	}
	counts = final
	rep.Counts = final
	if s.audit != nil {
		if err := s.audit(ctx, tenantID, audit.ActionAssetProviderAddressesMoved, counts); err != nil {
			return err
		}
	}
	if s.dashboard != nil {
		// Archiving already marked the dashboards dirty; one full refresh
		// settles the totals. Too soon means one is already queued.
		_, _ = s.dashboard.RequestRebuild(ctx, tenantID, 0)
	}
	addresses, names, providers, err := s.store.NoticeCounts(ctx, tenantID)
	if err != nil {
		return err
	}
	if addresses > 0 {
		n := pa.NewNotice(addresses, names, counts[pa.CountCardEntriesExact]+counts[pa.CountCardEntriesRange], providers)
		sent, err := s.store.SendNotice(ctx, tenantID, run.ID, n)
		if err != nil {
			return err
		}
		rep.NoticeSent = sent
	}
	return nil
}

// reclassify finds applied items whose address the current dataset no
// longer holds as shared, and restores them on apply (outcome
// reclassified; attribution never confirmed). A dry run only counts them.
func (s *Service) reclassify(ctx context.Context, tenantID shared.ID, opts Options, apply bool) (int, error) {
	n, after := 0, ""
	for {
		items, err := s.store.ListAppliedItems(ctx, tenantID, after, opts.BatchSize)
		if err != nil {
			return n, err
		}
		var ids []string
		for _, it := range items {
			if _, isShared := opts.Classifier.SharedFrontEnd(it.Address); !isShared {
				ids = append(ids, it.ID)
			}
		}
		if !apply {
			n += len(ids)
		}
		for apply && len(ids) > 0 {
			chunk := ids[:min(len(ids), RestoreBatch)]
			ids = ids[len(chunk):]
			var res pa.RestoreResult
			err := s.withRetry(ctx, func() error {
				var e error
				res, e = s.store.RestoreBatch(ctx, pa.RestoreRequest{TenantID: tenantID, ItemIDs: chunk, Limit: len(chunk),
					Outcome: pa.OutcomeReclassified})
				return e
			})
			if err != nil {
				return n, err
			}
			n += res.Restored
		}
		if len(items) < opts.BatchSize {
			return n, nil
		}
		after = items[len(items)-1].ID
	}
}

// restore puts back every applied item of the organization.
func (s *Service) restore(ctx context.Context, tenantID shared.ID, opts Options, rep *Report) error {
	run, err := s.store.StartRun(ctx, tenantID, pa.ModeRestore, opts.Classifier.Version(), opts.Actor, pa.Counts{})
	if err != nil {
		return err
	}
	rep.RunID, rep.Resumed = run.ID, run.Resumed
	counts := pa.Counts{}
	counts.Merge(run.Counts)
	for {
		if opts.MaxBatches > 0 && rep.Batches >= opts.MaxBatches {
			rep.Counts = counts
			return nil
		}
		var res pa.RestoreResult
		began := s.now()
		err := s.withRetry(ctx, func() error {
			var e error
			res, e = s.store.RestoreBatch(ctx, pa.RestoreRequest{TenantID: tenantID, RunID: run.ID, Limit: min(opts.BatchSize, RestoreBatch),
				Outcome: pa.OutcomeRestored})
			return e
		})
		if err != nil {
			rep.Counts = counts
			return err
		}
		rep.Batches++
		counts.Add(pa.CountRestored, res.Restored)
		counts.Add(pa.CountChanged, res.Changed)
		if opts.Progress != nil {
			opts.Progress(rep.Batches, res.Restored+res.Changed, s.now().Sub(began))
		}
		if res.Done {
			break
		}
	}
	rep.Completed = true
	final, err := s.store.FinishRun(ctx, tenantID, run.ID, pa.StateDone, nil, "")
	if err != nil {
		return err
	}
	counts = final
	rep.Counts = final
	if s.audit != nil {
		if err := s.audit(ctx, tenantID, audit.ActionAssetProviderAddressesRestored, counts); err != nil {
			return err
		}
	}
	if s.dashboard != nil {
		_, _ = s.dashboard.RequestRebuild(ctx, tenantID, 0)
	}
	return nil
}
