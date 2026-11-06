package threat

// KEV and EPSS delivered by the signed vulnerability release.
//
// The collector publishes both next to each release as a signed side
// manifest (pkg/vulnbundle/intel.go). The importer verifies it and hands the
// parsed streams here. A stream is applied only when its data date is newer
// than the date of the data the platform holds, whichever path (bundle or
// direct fetch) stored it, so a replayed, withheld-and-resent or carried
// older copy never rolls the catalog back. A snapshot far smaller than what
// is stored is refused as truncated, and a KEV snapshot may remove only as
// many entries as a direct sync may (pruneRemovedKEV).
//
// Freshness is recorded per source in the sync status row's metadata so the
// feed status can say which path supplied the data and how current the
// bundle's copy is:
//
//	delivered_via     "bundle" or "direct": the path that stored the data held
//	intel_as_of       data date of the data held (RFC 3339)
//	bundle_fetched_at when the collector last read the source (RFC 3339);
//	                  refreshed even when the data did not change
//	bundle_sequence   release sequence that carried the last bundle copy
//	bundle_error      why the last bundle copy was refused (cleared on success)

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/internal/app/threatsource"
	"github.com/openctemio/openctem/api/pkg/domain/threatintel"
)

// Metadata keys of the sync status row.
const (
	MetaDeliveredVia   = "delivered_via"
	MetaIntelAsOf      = "intel_as_of"
	MetaBundleFetched  = "bundle_fetched_at"
	MetaBundleSequence = "bundle_sequence"
	MetaBundleError    = "bundle_error"
)

// Paths that deliver KEV and EPSS.
const (
	ViaBundle = "bundle"
	ViaDirect = "direct"
)

// bundleShrinkFloor: a snapshot under this share of the stored record count
// is refused as truncated.
const bundleShrinkFloor = 0.90

// Bundle sources, as named in sync status and bundle streams.
const (
	bundleSourceKEV  = "kev"
	bundleSourceEPSS = "epss"
)

// ErrBundleShrunk is returned for a bundle snapshot far smaller than the
// stored catalog.
var ErrBundleShrunk = errors.New("the bundle copy is much smaller than the stored data")

// BundleStream is the signed description of a stream the importer verified.
type BundleStream struct {
	// AsOf is the publisher's data date (KEV dateReleased, EPSS score date).
	AsOf time.Time
	// FetchedAt is when the collector last read the source.
	FetchedAt time.Time
	// Sequence is the release that carried the stream.
	Sequence uint64
}

// BundleOutcome says what applying a stream did.
type BundleOutcome struct {
	// Applied: the data was written. False with a nil error means the
	// stream was not newer (only its freshness was recorded) or the source
	// is switched off.
	Applied bool
	Records int
}

// SetAfterBundleApply registers what runs after a stream was applied (the
// findings sweep and the event log; the same work as after a direct sync).
func (s *IntelService) SetAfterBundleApply(f func(ctx context.Context, source string)) {
	s.afterBundle = f
}

func parseMetaTime(v any) time.Time {
	str, _ := v.(string)
	t, err := time.Parse(time.RFC3339, str)
	if err != nil {
		return time.Time{}
	}
	return t
}

// storedAsOf is the data date of the data the source holds (zero: unknown,
// for data stored before the date was recorded).
func storedAsOf(meta map[string]any) time.Time { return parseMetaTime(meta[MetaIntelAsOf]) }

// newerData: is candidate newer than held, at the precision the source
// publishes (EPSS scores are dated by day; KEV releases by time).
func newerData(source string, candidate, held time.Time) bool {
	if held.IsZero() {
		return true
	}
	if source == bundleSourceEPSS {
		return candidate.UTC().Truncate(24 * time.Hour).After(held.UTC().Truncate(24 * time.Hour))
	}
	return candidate.After(held)
}

// recordBundleSeen stores the freshness of the bundle copy without touching
// the data.
func (s *IntelService) recordBundleSeen(ctx context.Context, source string, st BundleStream, cause error) (*threatintel.SyncStatus, error) {
	status, err := s.repo.SyncStatus().GetBySource(ctx, source)
	if err != nil {
		return nil, fmt.Errorf("failed to get sync status: %w", err)
	}
	meta := status.Metadata()
	if cause == nil {
		meta[MetaBundleFetched] = st.FetchedAt.UTC().Format(time.RFC3339)
		meta[MetaBundleSequence] = st.Sequence
		delete(meta, MetaBundleError)
	} else {
		meta[MetaBundleError] = cause.Error()
	}
	status.SetMetadata(meta)
	return status, nil
}

// BundleWanted reports whether a stream dated asOf would change what the
// source holds: false when the source is switched off or already holds data
// as new or newer (the importer then skips the download and only records
// the stream's freshness with RecordBundleSeen).
func (s *IntelService) BundleWanted(ctx context.Context, source string, asOf time.Time) (bool, error) {
	status, err := s.repo.SyncStatus().GetBySource(ctx, source)
	if err != nil {
		return false, fmt.Errorf("failed to get sync status: %w", err)
	}
	return status.IsEnabled() && newerData(source, asOf, storedAsOf(status.Metadata())), nil
}

// RecordBundleSeen records that the bundle carried a current copy of the
// source (its freshness) without applying it.
func (s *IntelService) RecordBundleSeen(ctx context.Context, source string, st BundleStream) error {
	status, err := s.recordBundleSeen(ctx, source, st, nil)
	if err != nil {
		return err
	}
	return s.repo.SyncStatus().Update(ctx, status)
}

// RecordBundleRefused records why a bundle copy was refused (a stream that
// failed verification or a guard), so the status can say so. The freshness
// of the bundle copy is not refreshed.
func (s *IntelService) RecordBundleRefused(ctx context.Context, source string, cause error) {
	status, err := s.recordBundleSeen(ctx, source, BundleStream{}, cause)
	if err != nil {
		s.logger.Warn("bundle refusal not recorded", "source", source, "error", err)
		return
	}
	if err := s.repo.SyncStatus().Update(ctx, status); err != nil {
		s.logger.Warn("bundle refusal not recorded", "source", source, "error", err)
	}
}

// ApplyBundleKEV applies a verified KEV stream when it is newer than the
// catalog held.
func (s *IntelService) ApplyBundleKEV(ctx context.Context, st BundleStream, entries []*threatintel.KEVEntry, version string) (BundleOutcome, error) {
	const source = bundleSourceKEV
	start := time.Now()
	status, err := s.recordBundleSeen(ctx, source, st, nil)
	if err != nil {
		return BundleOutcome{}, err
	}
	if !status.IsEnabled() {
		return BundleOutcome{}, nil
	}
	meta := status.Metadata()
	if !newerData(source, st.AsOf, storedAsOf(meta)) {
		return BundleOutcome{}, s.repo.SyncStatus().Update(ctx, status)
	}
	total, err := s.repo.KEV().Count(ctx)
	if err != nil {
		return BundleOutcome{}, fmt.Errorf("failed to count the KEV catalog: %w", err)
	}
	if total > 0 && float64(len(entries)) < bundleShrinkFloor*float64(total) {
		return BundleOutcome{}, fmt.Errorf("%w (kev: %d entries, %d stored)", ErrBundleShrunk, len(entries), total)
	}
	const chunkSize = 100
	for i := 0; i < len(entries); i += chunkSize {
		if err := s.repo.KEV().UpsertBatch(ctx, entries[i:min(i+chunkSize, len(entries))]); err != nil {
			return BundleOutcome{}, fmt.Errorf("failed to upsert KEV entries: %w", err)
		}
	}
	s.pruneRemovedKEV(ctx, entries)
	meta[MetaDeliveredVia] = ViaBundle
	meta[MetaIntelAsOf] = st.AsOf.UTC().Format(time.RFC3339)
	if version != "" {
		meta["catalog_version"] = version
	}
	status.SetMetadata(meta)
	status.MarkSyncSuccess(len(entries), int(time.Since(start).Milliseconds()))
	if err := s.repo.SyncStatus().Update(ctx, status); err != nil {
		return BundleOutcome{}, fmt.Errorf("failed to update sync status: %w", err)
	}
	s.invalidateCatalogCounts()
	s.propagateToCatalog(ctx, source)
	s.logger.Info("KEV applied from the bundle", "records", len(entries), "as_of", st.AsOf, "sequence", st.Sequence)
	if s.afterBundle != nil {
		s.afterBundle(ctx, source)
	}
	return BundleOutcome{Applied: true, Records: len(entries)}, nil
}

// ApplyBundleEPSS applies a verified EPSS stream when its score date is
// newer than the scores held.
func (s *IntelService) ApplyBundleEPSS(ctx context.Context, st BundleStream, scores []*threatintel.EPSSScore) (BundleOutcome, error) {
	const source = bundleSourceEPSS
	start := time.Now()
	status, err := s.recordBundleSeen(ctx, source, st, nil)
	if err != nil {
		return BundleOutcome{}, err
	}
	if !status.IsEnabled() {
		return BundleOutcome{}, nil
	}
	meta := status.Metadata()
	if !newerData(source, st.AsOf, storedAsOf(meta)) {
		return BundleOutcome{}, s.repo.SyncStatus().Update(ctx, status)
	}
	total, err := s.repo.EPSS().Count(ctx)
	if err != nil {
		return BundleOutcome{}, fmt.Errorf("failed to count the EPSS scores: %w", err)
	}
	if total > 0 && float64(len(scores)) < bundleShrinkFloor*float64(total) {
		return BundleOutcome{}, fmt.Errorf("%w (epss: %d scores, %d stored)", ErrBundleShrunk, len(scores), total)
	}
	if err := s.repo.EPSS().UpsertBatch(ctx, scores); err != nil {
		return BundleOutcome{}, fmt.Errorf("failed to upsert EPSS scores: %w", err)
	}
	meta[MetaDeliveredVia] = ViaBundle
	meta[MetaIntelAsOf] = st.AsOf.UTC().Format(time.RFC3339)
	status.SetMetadata(meta)
	status.MarkSyncSuccess(len(scores), int(time.Since(start).Milliseconds()))
	if err := s.repo.SyncStatus().Update(ctx, status); err != nil {
		return BundleOutcome{}, fmt.Errorf("failed to update sync status: %w", err)
	}
	s.invalidateCatalogCounts()
	s.propagateToCatalog(ctx, source)
	s.logger.Info("EPSS applied from the bundle", "records", len(scores), "as_of", st.AsOf, "sequence", st.Sequence)
	if s.afterBundle != nil {
		s.afterBundle(ctx, source)
	}
	return BundleOutcome{Applied: true, Records: len(scores)}, nil
}

// markDirect records that a direct fetch stored the data held, with its
// data date (zero: unknown, the date is left as it was).
func markDirect(meta map[string]any, asOf time.Time) {
	meta[MetaDeliveredVia] = ViaDirect
	if !asOf.IsZero() {
		meta[MetaIntelAsOf] = asOf.UTC().Format(time.RFC3339)
	}
}

// How old the bundle copy of a source may be before the direct fetch runs as
// a fallback (when the platform setting prefers the bundle). Age is measured
// from when the collector last read the source (bundle_fetched_at), not from
// the publisher's data date, which can be days old while the data is current.
const (
	KEVBundleStaleAfter  = 6 * time.Hour
	EPSSBundleStaleAfter = 48 * time.Hour
)

// ErrDirectFetchOff is returned by a direct sync when the platform setting
// forbids calling CISA and FIRST (strict-egress installs).
var ErrDirectFetchOff = errors.New("direct fetch of this feed is switched off in the platform settings")

// SourcePolicy is the platform setting that decides where KEV and EPSS come
// from (*threatsource.Service).
type SourcePolicy interface {
	Policy(ctx context.Context) (threatsource.Policy, error)
}

// SetSourcePolicy wires the setting (nil: defaults, the direct fetch runs on
// its schedule).
func (s *IntelService) SetSourcePolicy(p SourcePolicy) { s.policy = p }

// FetchDecision says whether the scheduled direct fetch of a source runs, and
// why (a stable code for the status and the logs).
type FetchDecision struct {
	Run    bool
	Reason string
}

// Reasons of a FetchDecision.
const (
	ReasonDirectPreferred = "direct_preferred"
	ReasonBundleFresh     = "bundle_fresh"
	ReasonBundleStale     = "bundle_stale"
	ReasonBundleMissing   = "bundle_missing"
	ReasonDirectOff       = "direct_fetch_off"
)

func (s *IntelService) sourcePolicy(ctx context.Context) threatsource.Policy {
	p := threatsource.Policy{DirectAllowed: true}
	if s.policy == nil {
		return p
	}
	got, err := s.policy.Policy(ctx)
	if err != nil {
		// The setting cannot be read: behave as before it existed.
		s.logger.Warn("threat intel source setting not read; using the defaults", "error", err)
		return p
	}
	return got
}

// ShouldFetchDirect decides whether the scheduled direct fetch of source
// ("kev" or "epss") runs now:
//
//   - direct fetch off: never;
//   - source "direct" (default): always, as the schedule says;
//   - source "bundle": only when the bundle's copy was last read by the
//     collector longer ago than the source's stale threshold, or never.
func (s *IntelService) ShouldFetchDirect(ctx context.Context, source string) FetchDecision {
	p := s.sourcePolicy(ctx)
	if !p.DirectAllowed {
		return FetchDecision{Reason: ReasonDirectOff}
	}
	if !p.PreferBundle {
		return FetchDecision{Run: true, Reason: ReasonDirectPreferred}
	}
	status, err := s.repo.SyncStatus().GetBySource(ctx, source)
	if err != nil {
		// Unknown state: fetch (a stale feed is worse than a redundant call).
		return FetchDecision{Run: true, Reason: ReasonBundleMissing}
	}
	fetched := parseMetaTime(status.Metadata()[MetaBundleFetched])
	if fetched.IsZero() {
		return FetchDecision{Run: true, Reason: ReasonBundleMissing}
	}
	limit := KEVBundleStaleAfter
	if source == bundleSourceEPSS {
		limit = EPSSBundleStaleAfter
	}
	if s.now().Sub(fetched) > limit {
		return FetchDecision{Run: true, Reason: ReasonBundleStale}
	}
	return FetchDecision{Reason: ReasonBundleFresh}
}

// BundleReadiness is how the signed release is doing for one source: what an
// administrator checks before letting the release supply the feed.
type BundleReadiness struct {
	Source string
	// DeliveredVia: the path that stored the data held ("" before any).
	DeliveredVia string
	// DataAsOf is the data date of the data held (zero: unknown).
	DataAsOf time.Time
	// BundleFetchedAt is when the collector last read the source, as the
	// release says (zero: no release has carried the feed yet).
	BundleFetchedAt time.Time
	// Fresh: BundleFetchedAt is within the source's stale threshold.
	Fresh bool
	// BundleError is why the last bundle copy was refused ("" when none).
	BundleError string
}

// BundleReadiness reports the bundle's state for KEV and EPSS.
func (s *IntelService) BundleReadiness(ctx context.Context) []BundleReadiness {
	out := make([]BundleReadiness, 0, 2)
	for _, src := range []string{bundleSourceKEV, bundleSourceEPSS} {
		r := BundleReadiness{Source: src}
		if st, err := s.repo.SyncStatus().GetBySource(ctx, src); err == nil {
			meta := st.Metadata()
			r.DeliveredVia, _ = meta[MetaDeliveredVia].(string)
			r.BundleError, _ = meta[MetaBundleError].(string)
			r.DataAsOf = storedAsOf(meta)
			r.BundleFetchedAt = parseMetaTime(meta[MetaBundleFetched])
			limit := KEVBundleStaleAfter
			if src == bundleSourceEPSS {
				limit = EPSSBundleStaleAfter
			}
			r.Fresh = !r.BundleFetchedAt.IsZero() && s.now().Sub(r.BundleFetchedAt) <= limit
		}
		out = append(out, r)
	}
	return out
}
