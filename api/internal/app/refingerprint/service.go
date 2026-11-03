// Package refingerprint re-keys stored findings to the current identity
// recipe (RFC-043 §6).
// https://github.com/openctemio/openctem/blob/develop/api/docs/rfcs/RFC-043-deduplication-and-identity.md
//
// Per tenant, in batches, resumable and idempotent:
//
//  1. Recompute the current-version key of each older finding from the row,
//     where the row holds every recipe input (vulnerability.IdentityFromStored).
//     Other findings keep their key and are re-keyed when a scan next reports
//     them (their old key is matched as an alias at ingest).
//  2. Re-key it; the old key stays an alias. When another finding owns the new
//     key, the two are one finding: the earliest-created survives through the
//     finding merge (state inherited, references moved, tombstone kept). Never
//     a delete.
//  3. A dry run (the default) changes nothing and reports the findings it
//     would re-key, the pairs it would merge and the ones it cannot recompute.
//
// While an applying run is in progress, scan auto-resolve is paused for the
// tenant (decision D11).
package refingerprint

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// Store is the storage the job needs (implemented by
// postgres.FindingRekeyRepository).
type Store interface {
	ListCandidates(ctx context.Context, tenantID shared.ID, target int, afterID string, limit int) ([]vulnerability.RekeyCandidate, error)
	Holders(ctx context.Context, tenantID shared.ID, keys []string) (map[string]vulnerability.RekeyHolder, error)
	Rekey(ctx context.Context, tenantID shared.ID, findingID, fromFP string, k vulnerability.IdentityKey) (vulnerability.RekeyResult, error)
	StartRun(ctx context.Context, tenantID shared.ID, target int) (*vulnerability.RekeyRun, error)
	SaveProgress(ctx context.Context, tenantID shared.ID, cursorID string, rekeyed, merged, skipped int) error
	FinishRun(ctx context.Context, tenantID shared.ID) error
	ListAtVersion(ctx context.Context, tenantID shared.ID, version int, afterID string, limit int) ([]vulnerability.RekeyCandidate, error)
	Restore(ctx context.Context, tenantID shared.ID, findingID, fromFP string) (vulnerability.RekeyResult, error)
}

// DownTargetVersion is the checkpoint target of a down run: the version the
// findings go back to (2, or 1 for a finding version 2 had no recipe for).
const DownTargetVersion = 2

// DefaultBatchSize is the number of findings read and re-keyed per batch.
const DefaultBatchSize = 500

// Options control a run.
type Options struct {
	// Apply commits the re-keys and merges. False is a dry run.
	Apply bool
	// BatchSize defaults to DefaultBatchSize.
	BatchSize int
	// MaxBatches stops after this many batches (0 = until done). An applying
	// run stopped this way stays open and resumes from its cursor.
	MaxBatches int
}

// MergePair is two findings that are one under the new recipe.
type MergePair struct {
	SurvivorID  string `json:"survivor_id"`
	LoserID     string `json:"loser_id"`
	Fingerprint string `json:"fingerprint"`
}

// Report is the outcome of a run for one tenant.
type Report struct {
	TenantID  string         `json:"tenant_id"`
	Applied   bool           `json:"applied"`
	Resumed   bool           `json:"resumed"`
	Completed bool           `json:"completed"`
	Scanned   int            `json:"scanned"`
	Rekeyed   int            `json:"rekeyed"`
	Merged    int            `json:"merged"`
	Skipped   map[string]int `json:"skipped"`
	Merges    []MergePair    `json:"merges"`
}

// SkippedTotal is the number of findings that keep their key.
func (r *Report) SkippedTotal() int {
	n := 0
	for _, v := range r.Skipped {
		n += v
	}
	return n
}

// Service runs the job.
type Service struct {
	store Store
}

// NewService creates the job.
func NewService(store Store) *Service {
	return &Service{store: store}
}

type planned struct {
	id      string
	created int64
}

// batchTally counts one batch's outcomes, for the report and the checkpoint.
type batchTally struct {
	rekeyed, merged, skipped int
}

func (r *Report) skip(t *batchTally, reason string) {
	r.Skipped[reason]++
	t.skipped++
}

// Run re-keys (or, without Apply, plans the re-key of) one tenant's findings.
func (s *Service) Run(ctx context.Context, tenantID shared.ID, opts Options) (*Report, error) {
	if tenantID.IsZero() {
		return nil, fmt.Errorf("refingerprint: a tenant is required")
	}
	batch := opts.BatchSize
	if batch <= 0 {
		batch = DefaultBatchSize
	}
	target := vulnerability.IdentityVersion
	rep := &Report{TenantID: tenantID.String(), Applied: opts.Apply, Skipped: map[string]int{}}

	cursor := ""
	if opts.Apply {
		run, err := s.store.StartRun(ctx, tenantID, target)
		if err != nil {
			return nil, err
		}
		if run != nil && run.CursorID != "" {
			cursor = run.CursorID
			rep.Resumed = true
		}
	}

	// In a dry run nothing moves, so a later finding that maps to a key an
	// earlier one of this run would take is planned against that one.
	plannedKeys := map[string]planned{}

	for n := 0; opts.MaxBatches <= 0 || n < opts.MaxBatches; n++ {
		cands, err := s.store.ListCandidates(ctx, tenantID, target, cursor, batch)
		if err != nil {
			return nil, err
		}
		if len(cands) == 0 {
			rep.Completed = true
			break
		}
		var t batchTally
		if opts.Apply {
			err = s.applyBatch(ctx, tenantID, cands, rep, &t)
		} else {
			err = s.planBatch(ctx, tenantID, cands, plannedKeys, rep, &t)
		}
		if err != nil {
			return nil, err
		}
		rep.Rekeyed += t.rekeyed
		rep.Merged += t.merged
		cursor = cands[len(cands)-1].ID
		if opts.Apply {
			if err := s.store.SaveProgress(ctx, tenantID, cursor, t.rekeyed, t.merged, t.skipped); err != nil {
				return nil, err
			}
		}
		if len(cands) < batch {
			rep.Completed = true
			break
		}
	}
	if opts.Apply && rep.Completed {
		if err := s.store.FinishRun(ctx, tenantID); err != nil {
			return nil, err
		}
	}
	sort.Slice(rep.Merges, func(i, j int) bool {
		if rep.Merges[i].SurvivorID != rep.Merges[j].SurvivorID {
			return rep.Merges[i].SurvivorID < rep.Merges[j].SurvivorID
		}
		return rep.Merges[i].LoserID < rep.Merges[j].LoserID
	})
	return rep, nil
}

// recompute returns the new key of each candidate, nil where the row cannot
// be recomputed (counted as skipped).
func recompute(cands []vulnerability.RekeyCandidate, rep *Report, t *batchTally) []*vulnerability.IdentityKey {
	keys := make([]*vulnerability.IdentityKey, len(cands))
	for i, c := range cands {
		rep.Scanned++
		k, reason := vulnerability.IdentityFromStored(c.Input)
		if reason != "" {
			rep.skip(t, reason)
			continue
		}
		keys[i] = &k
	}
	return keys
}

// applyBatch re-keys a batch; each finding in its own transaction.
func (s *Service) applyBatch(ctx context.Context, tenantID shared.ID, cands []vulnerability.RekeyCandidate, rep *Report, t *batchTally) error {
	keys := recompute(cands, rep, t)
	for i, c := range cands {
		if keys[i] == nil {
			continue
		}
		res, err := s.store.Rekey(ctx, tenantID, c.ID, c.Fingerprint, *keys[i])
		if err != nil {
			return err
		}
		switch res.Outcome {
		case vulnerability.RekeyOutcomeRekeyed:
			t.rekeyed++
		case vulnerability.RekeyOutcomeMerged:
			t.merged++
			rep.Merges = append(rep.Merges, MergePair{SurvivorID: res.SurvivorID, LoserID: res.LoserID, Fingerprint: keys[i].Fingerprint()})
		default:
			reason := res.Reason
			if reason == "" {
				reason = "changed"
			}
			rep.skip(t, reason)
		}
	}
	return nil
}

// planBatch reports what applyBatch would do, without writing: the same
// survivor rule (earliest created, then lowest id) and the same refusal to
// merge across assets.
func (s *Service) planBatch(ctx context.Context, tenantID shared.ID, cands []vulnerability.RekeyCandidate,
	plannedKeys map[string]planned, rep *Report, t *batchTally,
) error {
	keys := recompute(cands, rep, t)
	fps := make([]string, 0, len(cands))
	for _, k := range keys {
		if k != nil {
			fps = append(fps, k.Fingerprint())
		}
	}
	holders, err := s.store.Holders(ctx, tenantID, fps)
	if err != nil {
		return err
	}
	for i, c := range cands {
		if keys[i] == nil {
			continue
		}
		fp := keys[i].Fingerprint()
		me := planned{id: c.ID, created: c.CreatedAt.UnixNano()}
		other, taken := plannedKeys[fp]
		if !taken {
			if h, ok := holders[fp]; ok && h.ID != c.ID {
				if h.AssetID != keys[i].Field(vulnerability.IdentityFieldAsset) {
					// The real run refuses this one too (data scope).
					rep.skip(t, vulnerability.RekeySkipOtherAsset)
					continue
				}
				other, taken = planned{id: h.ID, created: h.CreatedAt.UnixNano()}, true
			}
		}
		if !taken {
			plannedKeys[fp] = me
			t.rekeyed++
			continue
		}
		survivor, loser := other, me
		if me.created < other.created || (me.created == other.created && me.id < other.id) {
			survivor, loser = me, other
		}
		plannedKeys[fp] = survivor
		t.merged++
		rep.Merges = append(rep.Merges, MergePair{SurvivorID: survivor.id, LoserID: loser.id, Fingerprint: fp})
	}
	return nil
}

// RunDown moves (or, without Apply, counts) one tenant's findings from the
// current version's key back to the key they had before: the down step of
// the version-3 re-key, run with the release's image before rolling back to
// a release that does not know version 3. It uses the same checkpoint (so
// scan auto-resolve is paused while it runs), batching and resume as Run.
// Merges made by the re-key are not undone.
func (s *Service) RunDown(ctx context.Context, tenantID shared.ID, opts Options) (*Report, error) {
	if tenantID.IsZero() {
		return nil, fmt.Errorf("refingerprint: a tenant is required")
	}
	batch := opts.BatchSize
	if batch <= 0 {
		batch = DefaultBatchSize
	}
	rep := &Report{TenantID: tenantID.String(), Applied: opts.Apply, Skipped: map[string]int{}}
	cursor := ""
	if opts.Apply {
		run, err := s.store.StartRun(ctx, tenantID, DownTargetVersion)
		if err != nil {
			return nil, err
		}
		if run != nil && run.CursorID != "" {
			cursor = run.CursorID
			rep.Resumed = true
		}
	}
	for n := 0; opts.MaxBatches <= 0 || n < opts.MaxBatches; n++ {
		cands, err := s.store.ListAtVersion(ctx, tenantID, vulnerability.IdentityVersion, cursor, batch)
		if err != nil {
			return nil, err
		}
		if len(cands) == 0 {
			rep.Completed = true
			break
		}
		var t batchTally
		for _, c := range cands {
			rep.Scanned++
			if !opts.Apply {
				t.rekeyed++
				continue
			}
			res, err := s.store.Restore(ctx, tenantID, c.ID, c.Fingerprint)
			if err != nil {
				return nil, err
			}
			if res.Outcome == vulnerability.RekeyOutcomeRekeyed {
				t.rekeyed++
				continue
			}
			reason := res.Reason
			if reason == "" {
				reason = "changed"
			}
			rep.skip(&t, reason)
		}
		rep.Rekeyed += t.rekeyed
		cursor = cands[len(cands)-1].ID
		if opts.Apply {
			if err := s.store.SaveProgress(ctx, tenantID, cursor, t.rekeyed, 0, t.skipped); err != nil {
				return nil, err
			}
		}
		if len(cands) < batch {
			rep.Completed = true
			break
		}
	}
	if opts.Apply && rep.Completed {
		if err := s.store.FinishRun(ctx, tenantID); err != nil {
			return nil, err
		}
	}
	return rep, nil
}

// Converger is the storage RunAll needs besides Store.
type Converger interface {
	TenantsToRekey(ctx context.Context, target int) ([]shared.ID, error)
	GetRun(ctx context.Context, tenantID shared.ID) (*vulnerability.RekeyRun, error)
}

// RunAll applies the re-key to the current version for every tenant that
// has findings keyed with an older one and has not completed a run to it.
// The server calls it on start, so stored findings follow a recipe change
// without an operator step; ingest also re-keys a finding on its next
// sighting, so a finding the run has not reached yet is never split. report
// is called with each tenant's report. A tenant whose run fails is logged by
// the caller through the returned error; the others still run.
func (s *Service) RunAll(ctx context.Context, c Converger, report func(*Report)) error {
	tenants, err := c.TenantsToRekey(ctx, vulnerability.IdentityVersion)
	if err != nil {
		return err
	}
	var errs []error
	for _, t := range tenants {
		run, err := c.GetRun(ctx, t)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if run != nil && run.Status == vulnerability.RekeyRunCompleted && run.TargetVersion >= vulnerability.IdentityVersion {
			continue
		}
		rep, err := s.Run(ctx, t, Options{Apply: true})
		if err != nil {
			errs = append(errs, fmt.Errorf("tenant %s: %w", t, err))
			continue
		}
		if report != nil {
			report(rep)
		}
	}
	return errors.Join(errs...)
}
