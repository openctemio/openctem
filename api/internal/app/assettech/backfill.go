// Package assettech runs the asset technology jobs.
//
// Design: docs/rfcs/RFC-112-asset-technologies.md (§3.7).
package assettech

import (
	"context"

	"github.com/openctemio/openctem/api/pkg/domain/assettech"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// BackfillVersion is bumped when the backfill must run again for every
// tenant (a classifier change that should reach stored rows).
// Version 2 also removes the retired properties.technologies key.
const BackfillVersion = 2

// backfillBatch is the assets (or component links) one statement reads or
// writes: small, so no statement holds row locks for long.
const backfillBatch = 500

// BackfillRow is one stored technology still in category other.
type BackfillRow struct {
	AssetID shared.ID
	Key     string
}

// BackfillLink is one component link ingest created from a technology.
type BackfillLink struct {
	ID      shared.ID
	Product string
	Version string // raw, "" = unknown
	HasCPE  bool
}

// BackfillStats is what the backfill did for one tenant.
type BackfillStats struct {
	// Technologies: rows looked at; Classified: rows given a category.
	Technologies int
	Classified   int
	LinksRemoved int
	// PropertiesDropped: assets the retired key was removed from.
	PropertiesDropped int
	// LinksReported: links a report-only run found removable and left alone.
	LinksReported int
}

// reportSample is how many removable links a report-only run names in the log.
const reportSample = 20

// BackfillStore is the backfill's view of the database. Every method is
// tenant-scoped.
type BackfillStore interface {
	// PendingTenants returns the tenants not done at version. A tenant that
	// only had a report-only run is pending again when enforce is true.
	PendingTenants(ctx context.Context, version int, enforce bool) ([]shared.ID, error)
	// ScanUnclassified returns the tenant's next technologies in category
	// other, after (afterAsset, afterKey).
	ScanUnclassified(ctx context.Context, tenantID shared.ID, afterAsset, afterKey string, limit int) ([]BackfillRow, error)
	// SetCategories sets the category of the tenant's technologies.
	SetCategories(ctx context.Context, tenantID shared.ID, rows []BackfillRow, cats []assettech.Category) error
	ScanTechnologyLinks(ctx context.Context, tenantID shared.ID, afterID string, limit int) ([]BackfillLink, error)
	// DeleteLinks deletes the tenant's technology links by id, only those
	// without a usable version and without a CPE, and records each one.
	DeleteLinks(ctx context.Context, tenantID shared.ID, ids []shared.ID) (int, error)
	// DropRetiredProperty removes properties.technologies from at most
	// limit of the tenant's assets and returns how many it changed. Tags are
	// never touched: nothing marks a tag as one the converter added.
	DropRetiredProperty(ctx context.Context, tenantID shared.ID, limit int) (int, error)
	MarkBackfilled(ctx context.Context, tenantID shared.ID, version int, enforced bool, stats BackfillStats) error
}

// Backfill classifies the technologies the copy migration filled (category
// other: the curated list lives in code), and removes the component links
// ingest no longer creates: only a link with no usable version and no CPE.
// A versioned or CPE-backed link is never removed, whatever its category.
//
// With reportOnly (the default for the first run) nothing is deleted: the
// run counts the removable links and logs a sample, so an operator can check
// the list before enabling removal.
type Backfill struct {
	store      BackfillStore
	log        *logger.Logger
	reportOnly bool
}

// NewBackfill creates the backfill. reportOnly leaves every link in place.
func NewBackfill(store BackfillStore, log *logger.Logger, reportOnly bool) *Backfill {
	return &Backfill{store: store, log: log, reportOnly: reportOnly}
}

// Run backfills every pending tenant and returns how many it finished.
func (b *Backfill) Run(ctx context.Context) (int, error) {
	tenants, err := b.store.PendingTenants(ctx, BackfillVersion, !b.reportOnly)
	if err != nil {
		return 0, err
	}
	done := 0
	for _, t := range tenants {
		if ctx.Err() != nil {
			return done, ctx.Err()
		}
		stats, err := b.RunTenant(ctx, t)
		if err != nil {
			b.log.Warn("asset technology backfill failed", "tenant_id", t.String(), "error", logger.SanitizeError(err))
			continue
		}
		if err := b.store.MarkBackfilled(ctx, t, BackfillVersion, !b.reportOnly, stats); err != nil {
			return done, err
		}
		b.log.Info("asset technology backfill done", "tenant_id", t.String(),
			"technologies", stats.Technologies, "classified", stats.Classified, "links_removed", stats.LinksRemoved,
			"links_reported", stats.LinksReported, "report_only", b.reportOnly)
		done++
	}
	return done, nil
}

// RunTenant backfills one tenant in batches.
func (b *Backfill) RunTenant(ctx context.Context, tenantID shared.ID) (BackfillStats, error) {
	var stats BackfillStats
	afterAsset, afterKey := "", ""
	for {
		rows, err := b.store.ScanUnclassified(ctx, tenantID, afterAsset, afterKey, backfillBatch)
		if err != nil {
			return stats, err
		}
		if len(rows) == 0 {
			break
		}
		var set []BackfillRow
		var cats []assettech.Category
		for _, r := range rows {
			if c := assettech.Classify(r.Key, nil); c != assettech.CategoryOther {
				set = append(set, r)
				cats = append(cats, c)
			}
		}
		if len(set) > 0 {
			if err := b.store.SetCategories(ctx, tenantID, set, cats); err != nil {
				return stats, err
			}
		}
		stats.Technologies += len(rows)
		stats.Classified += len(set)
		last := rows[len(rows)-1]
		afterAsset, afterKey = last.AssetID.String(), last.Key
		if len(rows) < backfillBatch {
			break
		}
	}
	after := ""
	for {
		links, err := b.store.ScanTechnologyLinks(ctx, tenantID, after, backfillBatch)
		if err != nil {
			return stats, err
		}
		if len(links) == 0 {
			break
		}
		var drop []shared.ID
		for _, l := range links {
			if !linkRemovable(l) {
				continue
			}
			drop = append(drop, l.ID)
			if b.reportOnly && stats.LinksReported+len(drop) <= reportSample {
				b.log.Info("asset technology backfill would remove link", "tenant_id", tenantID.String(),
					"product", l.Product, "version", l.Version)
			}
		}
		if b.reportOnly {
			stats.LinksReported += len(drop)
		} else if len(drop) > 0 {
			n, err := b.store.DeleteLinks(ctx, tenantID, drop)
			if err != nil {
				return stats, err
			}
			stats.LinksRemoved += n
		}
		after = links[len(links)-1].ID.String()
		if len(links) < backfillBatch {
			break
		}
	}
	// The copy migration moved the values; the key is never read again.
	for {
		n, err := b.store.DropRetiredProperty(ctx, tenantID, backfillBatch)
		if err != nil {
			return stats, err
		}
		stats.PropertiesDropped += n
		if n < backfillBatch {
			break
		}
	}
	return stats, nil
}

// linkRemovable reports whether the backfill may delete the link: it has no
// usable version and no CPE. The delete statement repeats this rule, so a
// link that is versioned or CPE-backed survives even if a caller asks for it.
func linkRemovable(l BackfillLink) bool {
	return assettech.CleanVersion(l.Version) == "" && !l.HasCPE
}
