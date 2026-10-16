// Package assettech runs the asset technology jobs.
//
// Design: docs/rfcs/RFC-112-asset-technologies.md (§3.7).
package assettech

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/assettech"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// BackfillVersion is bumped when the backfill must run again for every
// tenant (a classifier change that should reach stored rows).
const BackfillVersion = 1

// backfillBatch is the assets (or component links) one statement reads or
// writes: small, so no statement holds row locks for long.
const backfillBatch = 500

// BackfillElement is one stored technology element of an asset with what
// its sources recorded about it.
type BackfillElement struct {
	Element   string
	FirstSeen time.Time
	LastSeen  time.Time
	Source    string
}

// BackfillAsset is one asset's stored technologies.
type BackfillAsset struct {
	ID        shared.ID
	Elements  []string // properties.technologies, "Name:version"
	FirstSeen time.Time
	LastSeen  time.Time
	// Seen is what set reconciliation recorded per element, when it did.
	Seen map[string]BackfillElement
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
	AssetsScanned int
	Technologies  int
	LinksRemoved  int
}

// BackfillStore is the backfill's view of the database. Every method is
// tenant-scoped.
type BackfillStore interface {
	PendingTenants(ctx context.Context, version int) ([]shared.ID, error)
	ScanAssets(ctx context.Context, tenantID shared.ID, afterID string, limit int) ([]BackfillAsset, error)
	ScanTechnologyLinks(ctx context.Context, tenantID shared.ID, afterID string, limit int) ([]BackfillLink, error)
	DeleteLinks(ctx context.Context, tenantID shared.ID, ids []shared.ID) (int, error)
	MarkBackfilled(ctx context.Context, tenantID shared.ID, version int, stats BackfillStats) error
}

// Backfill fills asset_technologies from the technologies assets already
// show, and removes the component links ingest no longer creates (a
// technology without a version or CPE, or one that is not software).
type Backfill struct {
	store BackfillStore
	techs assettech.Repository
	log   *logger.Logger
}

// NewBackfill creates the backfill.
func NewBackfill(store BackfillStore, techs assettech.Repository, log *logger.Logger) *Backfill {
	return &Backfill{store: store, techs: techs, log: log}
}

// Run backfills every pending tenant and returns how many it finished.
func (b *Backfill) Run(ctx context.Context) (int, error) {
	tenants, err := b.store.PendingTenants(ctx, BackfillVersion)
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
		if err := b.store.MarkBackfilled(ctx, t, BackfillVersion, stats); err != nil {
			return done, err
		}
		b.log.Info("asset technology backfill done", "tenant_id", t.String(),
			"assets", stats.AssetsScanned, "technologies", stats.Technologies, "links_removed", stats.LinksRemoved)
		done++
	}
	return done, nil
}

// RunTenant backfills one tenant in batches.
func (b *Backfill) RunTenant(ctx context.Context, tenantID shared.ID) (BackfillStats, error) {
	var stats BackfillStats
	after := ""
	for {
		assets, err := b.store.ScanAssets(ctx, tenantID, after, backfillBatch)
		if err != nil {
			return stats, err
		}
		if len(assets) == 0 {
			break
		}
		techs := make([]assettech.Technology, 0, len(assets)*4)
		for _, a := range assets {
			techs = append(techs, backfillTechnologies(a)...)
		}
		if err := b.techs.Upsert(ctx, tenantID, techs); err != nil {
			return stats, fmt.Errorf("backfill technologies: %w", err)
		}
		stats.AssetsScanned += len(assets)
		stats.Technologies += len(techs)
		after = assets[len(assets)-1].ID.String()
		if len(assets) < backfillBatch {
			break
		}
	}
	after = ""
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
			if !linkStillSoftware(l) {
				drop = append(drop, l.ID)
			}
		}
		if len(drop) > 0 {
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
	return stats, nil
}

// linkStillSoftware reports whether ingest would still create the link
// today.
func linkStillSoftware(l BackfillLink) bool {
	cpe := ""
	if l.HasCPE {
		cpe = "cpe"
	}
	return assettech.IsSoftwareCandidate(l.Product, l.Version, cpe, nil)
}

// backfillTechnologies is an asset's stored technologies as rows, at most
// assettech.MaxPerAsset.
func backfillTechnologies(a BackfillAsset) []assettech.Technology {
	out := make([]assettech.Technology, 0, min(len(a.Elements), assettech.MaxPerAsset))
	for _, el := range a.Elements {
		name, version := assettech.Split(el)
		first, last, source := a.FirstSeen, a.LastSeen, ""
		if s, ok := a.Seen[el]; ok {
			first, last, source = s.FirstSeen, s.LastSeen, s.Source
		}
		t, ok := assettech.Observation(a.ID, name, version, nil, 0, source, last)
		if !ok {
			continue
		}
		if !first.IsZero() && first.Before(last) {
			t.FirstSeen = first
		}
		out = append(out, t)
		if len(out) == assettech.MaxPerAsset {
			break
		}
	}
	return out
}
