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
	if source == "epss" {
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
	const source = "kev"
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
	const source = "epss"
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
