package vulnfeed

// The vulnerability id alias map (RFC-043 §17.2): after a bundle is applied
// (or when the corpus is already up to date) the importer reads the
// release's optional signed vulnids manifest, verifies it against the
// pinned root's key set and the applied sequence, and applies a version it
// has not applied yet. A failure is recorded in the feed status and never
// undoes the corpus import; the next run retries.

import (
	"context"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/vulnbundle"
)

// Removal guard: one version may drop at most max(minVulnIDRemovals, 5% of
// the stored entries).
const minVulnIDRemovals = 500

// VulnIDAliasWriter applies an alias map (the postgres CVE corpus
// repository).
type VulnIDAliasWriter interface {
	ApplyVulnIDAliases(ctx context.Context, entries []vulnerability.VulnIDAlias, version uint64, maxRemovalShare float64, minRemovals int) (VulnIDAliasResult, error)
}

// VulnIDAliasResult is what one application changed.
type VulnIDAliasResult struct {
	Written int
	Removed int
}

func (im *Importer) syncVulnIDs(ctx context.Context, f smallFetcher, sequence, minKeySet uint64) {
	if im.vulnIDs == nil || sequence == 0 {
		return
	}
	version, err := im.applyVulnIDs(ctx, f, sequence, minKeySet)
	if err == nil && version == 0 {
		return
	}
	st, serr := im.status.GetBySource(ctx, SourceName)
	if serr != nil {
		im.logger.Warn("vulnfeed: vulnerability id status not read", "error", serr)
		return
	}
	meta := st.Metadata()
	if err != nil {
		im.logger.Warn("vulnfeed: vulnerability id aliases not applied", "sequence", sequence, "error", err)
		meta["vulnids_error"] = err.Error()
	} else {
		delete(meta, "vulnids_error")
	}
	st.SetMetadata(meta)
	if uerr := im.status.Update(ctx, st); uerr != nil {
		im.logger.Warn("vulnfeed: vulnerability id status not updated", "error", uerr)
	}
}

// applyVulnIDs returns the version it applied (0: none newer, or the release
// has no alias map).
func (im *Importer) applyVulnIDs(ctx context.Context, f smallFetcher, sequence, minKeySet uint64) (uint64, error) {
	raw, err := f.Small(ctx, vulnbundle.VulnIDsManifestFile, vulnbundle.MaxManifestBytes)
	if err != nil {
		// A release without an alias map (older collectors) is normal.
		im.logger.Debug("vulnfeed: no vulnerability id manifest", "error", err)
		return 0, nil
	}
	ksRaw, err := f.Small(ctx, vulnbundle.KeySetFile, vulnbundle.MaxKeySetBytes)
	if err != nil {
		return 0, fmt.Errorf("key set: %w", err)
	}
	ks, err := vulnbundle.VerifyKeySet(ksRaw, im.cfg.RootKeyID, minKeySet, im.now())
	if err != nil {
		return 0, err
	}
	m, err := vulnbundle.VerifyVulnIDsManifest(ks, raw, sequence, im.now())
	if err != nil {
		return 0, err
	}
	st, err := im.status.GetBySource(ctx, SourceName)
	if err != nil {
		return 0, err
	}
	if m.Version <= toUint(st.Metadata()["vulnids_version"]) {
		return 0, nil
	}
	gz, err := f.Small(ctx, vulnbundle.VulnIDsEntriesFile, vulnbundle.MaxVulnIDsEntriesBytes)
	if err != nil {
		return 0, fmt.Errorf("vulnerability id entries: %w", err)
	}
	parsed, err := vulnbundle.ParseVulnIDEntries(gz, m)
	if err != nil {
		return 0, err
	}
	res, err := im.vulnIDs.ApplyVulnIDAliases(ctx, parsed.Entries, m.Version, 0.05, minVulnIDRemovals)
	if err != nil {
		return 0, err
	}
	if st, err = im.status.GetBySource(ctx, SourceName); err != nil {
		return 0, err
	}
	meta := st.Metadata()
	meta["vulnids_version"] = m.Version
	meta["vulnids_entries"] = len(parsed.Entries)
	meta["vulnids_invalid"] = parsed.Invalid
	meta["vulnids_conflicting"] = parsed.Conflicting
	meta["vulnids_removed"] = res.Removed
	st.SetMetadata(meta)
	if err := im.status.Update(ctx, st); err != nil {
		return 0, err
	}
	im.logger.Info("vulnerability id aliases applied", "version", m.Version, "entries", len(parsed.Entries),
		"written", res.Written, "removed", res.Removed, "invalid", parsed.Invalid, "conflicting", parsed.Conflicting)
	return m.Version, nil
}
