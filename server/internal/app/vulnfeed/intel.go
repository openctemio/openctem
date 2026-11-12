package vulnfeed

// KEV and EPSS from the release's signed side manifest. After the corpus
// (or when it is already up to date) the importer reads the optional
// intel.manifest.dsse.json, verifies it against the pinned root's key set
// and the applied sequence, and hands each stream it knows to the intel
// service, which applies it only when its data date is newer than what the
// platform holds. A stream whose data is not newer is not downloaded: only
// its freshness (when the collector last read the source) is recorded. A
// refused stream is recorded in that source's status and never undoes the
// corpus import; the other stream and the next run are unaffected. A stream
// name this platform does not know is skipped and reported (the manifest is
// signed, so skipping is safe).

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/internal/app/threat"
	"github.com/openctemio/openctem/api/pkg/domain/threatintel"
	"github.com/openctemio/openctem/api/pkg/vulnbundle"
)

// IntelApplier applies KEV and EPSS streams (*threat.IntelService).
type IntelApplier interface {
	BundleWanted(ctx context.Context, source string, asOf time.Time) (bool, error)
	RecordBundleSeen(ctx context.Context, source string, st threat.BundleStream) error
	RecordBundleRefused(ctx context.Context, source string, cause error)
	ApplyBundleKEV(ctx context.Context, st threat.BundleStream, entries []*threatintel.KEVEntry, version string) (threat.BundleOutcome, error)
	ApplyBundleEPSS(ctx context.Context, st threat.BundleStream, scores []*threatintel.EPSSScore) (threat.BundleOutcome, error)
}

// WithIntel wires the KEV and EPSS applier (nil: the side manifest is
// ignored).
func (im *Importer) WithIntel(a IntelApplier) *Importer {
	im.intel = a
	return im
}

// intelSources maps a stream name to the sync status source it feeds.
var intelSources = map[string]string{vulnbundle.IntelStreamKEV: "kev", vulnbundle.IntelStreamEPSS: "epss"}

func (im *Importer) syncIntel(ctx context.Context, f smallFetcher, sequence, minKeySet uint64) {
	if im.intel == nil || sequence == 0 {
		return
	}
	skipped, err := im.applyIntel(ctx, f, sequence, minKeySet)
	st, serr := im.status.GetBySource(ctx, SourceName)
	if serr != nil {
		im.logger.Warn("vulnfeed: intel status not read", "error", serr)
		return
	}
	meta := st.Metadata()
	before := fmt.Sprint(meta["intel_error"], meta["intel_skipped"])
	if err != nil {
		im.logger.Warn("vulnfeed: KEV and EPSS not applied", "sequence", sequence, "error", err)
		meta["intel_error"] = err.Error()
	} else {
		delete(meta, "intel_error")
	}
	if len(skipped) > 0 {
		meta["intel_skipped"] = strings.Join(skipped, ",")
	} else {
		delete(meta, "intel_skipped")
	}
	if fmt.Sprint(meta["intel_error"], meta["intel_skipped"]) == before {
		return
	}
	st.SetMetadata(meta)
	if uerr := im.status.Update(ctx, st); uerr != nil {
		im.logger.Warn("vulnfeed: intel status not updated", "error", uerr)
	}
}

// applyIntel returns the names of streams it skipped as unknown and the
// first error (every known stream is tried).
func (im *Importer) applyIntel(ctx context.Context, f smallFetcher, sequence, minKeySet uint64) ([]string, error) {
	raw, err := f.Small(ctx, vulnbundle.IntelManifestFile, vulnbundle.MaxManifestBytes)
	if err != nil {
		// A release without the side manifest (older collectors) is normal.
		im.logger.Debug("vulnfeed: no intel manifest", "error", err)
		return nil, nil
	}
	m, err := im.verifyIntel(ctx, f, raw, sequence, minKeySet)
	if err != nil {
		for _, src := range intelSources {
			im.intel.RecordBundleRefused(ctx, src, err)
		}
		return nil, err
	}
	var skipped []string
	var first error
	for i := range m.Streams {
		s := &m.Streams[i]
		src, known := intelSources[s.Name]
		if !known {
			skipped = append(skipped, s.Name)
			continue
		}
		if err := im.applyIntelStream(ctx, f, src, s, sequence); err != nil {
			im.logger.Warn("vulnfeed: intel stream refused", "stream", s.Name, "sequence", sequence, "error", err)
			im.intel.RecordBundleRefused(ctx, src, err)
			if first == nil {
				first = fmt.Errorf("%s: %w", s.Name, err)
			}
		}
	}
	return skipped, first
}

func (im *Importer) verifyIntel(ctx context.Context, f smallFetcher, raw []byte, sequence, minKeySet uint64) (*vulnbundle.IntelManifest, error) {
	ksRaw, err := f.Small(ctx, vulnbundle.KeySetFile, vulnbundle.MaxKeySetBytes)
	if err != nil {
		return nil, fmt.Errorf("key set: %w", err)
	}
	ks, err := vulnbundle.VerifyKeySet(ksRaw, im.cfg.RootKeyID, minKeySet, im.now())
	if err != nil {
		return nil, err
	}
	return vulnbundle.VerifyIntelManifest(ks, raw, sequence, im.now())
}

func (im *Importer) applyIntelStream(ctx context.Context, f smallFetcher, source string, s *vulnbundle.IntelStream, sequence uint64) error {
	st := threat.BundleStream{AsOf: s.AsOf, FetchedAt: s.FetchedAt, Sequence: sequence}
	wanted, err := im.intel.BundleWanted(ctx, source, s.AsOf)
	if err != nil {
		return err
	}
	if !wanted {
		// Same or older data: the stream only says the collector read the
		// source recently.
		return im.intel.RecordBundleSeen(ctx, source, st)
	}
	maxBytes := int64(vulnbundle.MaxIntelKEVBytes)
	if s.Name == vulnbundle.IntelStreamEPSS {
		maxBytes = vulnbundle.MaxIntelEPSSBytes
	}
	gz, err := f.Small(ctx, s.File.Name, maxBytes)
	if err != nil {
		return fmt.Errorf("entries: %w", err)
	}
	if s.Name == vulnbundle.IntelStreamKEV {
		entries, err := vulnbundle.ParseIntelKEV(gz, s)
		if err != nil {
			return err
		}
		_, err = im.intel.ApplyBundleKEV(ctx, st, entries, s.Version)
		return err
	}
	scores, err := vulnbundle.ParseIntelEPSS(gz, s)
	if err != nil {
		return err
	}
	_, err = im.intel.ApplyBundleEPSS(ctx, st, scores)
	return err
}
