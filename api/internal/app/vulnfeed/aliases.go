package vulnfeed

// The alias dictionary (RFC-066 §5.6): after a bundle is applied (or when
// the corpus is already up to date) the importer reads the release's
// signed alias manifest, verifies it against the pinned root's key set and
// the applied sequence, and applies a dictionary version it has not
// applied yet. A failure is recorded in the feed status and never undoes
// the corpus import; the next run retries.

import (
	"context"
	"fmt"

	"github.com/openctemio/ctis/transfer"

	"github.com/openctemio/openctem/api/pkg/vulnbundle"
)

// Merge guard: a dictionary may fold at most max(minAliasMerges, 5% of its
// entries) feed-created products into canonical ones in one version.
const minAliasMerges = 500

// smallFetcher is the part of the transfer fetcher the dictionary needs.
type smallFetcher interface {
	Small(ctx context.Context, name string, maxBytes int64) ([]byte, error)
}

var _ smallFetcher = (*transfer.Fetcher)(nil)

func (im *Importer) syncAliases(ctx context.Context, f smallFetcher, sequence, minKeySet uint64) {
	if im.aliases == nil || sequence == 0 {
		return
	}
	version, err := im.applyAliases(ctx, f, sequence, minKeySet)
	if err == nil && version == 0 {
		return
	}
	st, serr := im.status.GetBySource(ctx, SourceName)
	if serr != nil {
		im.logger.Warn("vulnfeed: alias status not read", "error", serr)
		return
	}
	meta := st.Metadata()
	if err != nil {
		im.logger.Warn("vulnfeed: alias dictionary not applied", "sequence", sequence, "error", err)
		meta["aliases_error"] = err.Error()
	} else {
		delete(meta, "aliases_error")
	}
	st.SetMetadata(meta)
	if uerr := im.status.Update(ctx, st); uerr != nil {
		im.logger.Warn("vulnfeed: alias status not updated", "error", uerr)
	}
}

// applyAliases returns the version it applied (0: none newer, or the
// release has no dictionary).
func (im *Importer) applyAliases(ctx context.Context, f smallFetcher, sequence, minKeySet uint64) (uint64, error) {
	raw, err := f.Small(ctx, vulnbundle.AliasesManifestFile, vulnbundle.MaxManifestBytes)
	if err != nil {
		// A release without a dictionary (older collectors) is normal.
		im.logger.Debug("vulnfeed: no alias manifest", "error", err)
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
	m, err := vulnbundle.VerifyAliasManifest(ks, raw, sequence, im.now())
	if err != nil {
		return 0, err
	}
	st, err := im.status.GetBySource(ctx, SourceName)
	if err != nil {
		return 0, err
	}
	if m.Version <= toUint(st.Metadata()["aliases_version"]) {
		return 0, nil
	}
	gz, err := f.Small(ctx, vulnbundle.AliasesEntriesFile, vulnbundle.MaxAliasesEntriesBytes)
	if err != nil {
		return 0, fmt.Errorf("alias entries: %w", err)
	}
	entries, err := vulnbundle.ParseAliasEntries(gz, m)
	if err != nil {
		return 0, err
	}
	res, err := im.aliases.ApplyFeedAliases(ctx, entries, max(minAliasMerges, len(entries)/20))
	if err != nil {
		return 0, err
	}
	if st, err = im.status.GetBySource(ctx, SourceName); err != nil {
		return 0, err
	}
	cov := m.Coverage()
	meta := st.Metadata()
	meta["aliases_version"] = m.Version
	meta["aliases_entries"] = len(entries)
	meta["aliases_coverage"] = cov.Coverage
	// Entries held for review: learned entries that would fold a product
	// with data of its own (public advisory strings, no tenant data).
	meta["aliases_held"] = res.Held
	meta["aliases_held_values"] = res.HeldValues
	meta["aliases_removed"] = res.Removed
	st.SetMetadata(meta)
	if err := im.status.Update(ctx, st); err != nil {
		return 0, err
	}
	im.logger.Info("vulnerability alias dictionary applied", "version", m.Version, "entries", len(entries),
		"written", res.Written, "repointed", res.Repointed, "merged", res.Merged, "skipped", res.Skipped,
		"held", res.Held, "removed", res.Removed,
		"cves_requeued", res.Requeued, "coverage", cov.Coverage)
	return m.Version, nil
}
