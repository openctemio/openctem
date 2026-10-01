package ingest

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/ctis"
)

// IdentityBackfillVersion is bumped when the derivation changes, so every
// tenant is backfilled again.
const IdentityBackfillVersion = 1

// StoredAsset is an existing asset as the identifier backfill reads it.
type StoredAsset struct {
	ID            shared.ID
	Name          string
	Type          asset.AssetType
	Properties    map[string]any
	RepoID        string // asset_repositories.repo_id, for repositories
	LastSeen      time.Time
	CreatedAt     time.Time
	FindingCount  int
	DiscoveryTool string
}

// BackfillStats counts one tenant's backfill.
type BackfillStats struct {
	AssetsScanned    int
	IdentifiersAdded int
	ReviewsEnqueued  int
}

// BackfillSource reads what the backfill needs.
type BackfillSource interface {
	// PendingTenants returns tenants not yet backfilled at version.
	PendingTenants(ctx context.Context, version int) ([]shared.ID, error)
	// ScanAssets pages through a tenant's assets by id (keyset).
	ScanAssets(ctx context.Context, tenantID shared.ID, afterID string, limit int) ([]StoredAsset, error)
	// GetStoredAssets loads assets by id.
	GetStoredAssets(ctx context.Context, tenantID shared.ID, ids []shared.ID) (map[string]StoredAsset, error)
	// RenamedHostCandidates returns pairs of hosts one scanner reported
	// with the same IP address under different names.
	RenamedHostCandidates(ctx context.Context, tenantID shared.ID, limit int) ([]RenamedHostPair, error)
	MarkBackfilled(ctx context.Context, tenantID shared.ID, version int, stats BackfillStats) error
}

// RenamedHostPair is two host assets one scanner reported with the same IP.
type RenamedHostPair struct {
	A, B StoredAsset
	IP   string
	Tool string
}

// IdentityBackfill derives identifiers for assets that predate the identity
// model, from their names, properties and repository rows, and raises
// duplicate reviews for what it finds: two assets carrying one strong
// identifier, and hosts a scanner reported under two names. It never merges.
type IdentityBackfill struct {
	source   BackfillSource
	store    IdentityStore
	reviewer IdentityReviewer
	logger   *logger.Logger
	pageSize int
}

// NewIdentityBackfill creates the backfill.
func NewIdentityBackfill(source BackfillSource, store IdentityStore, reviewer IdentityReviewer, log *logger.Logger) *IdentityBackfill {
	return &IdentityBackfill{source: source, store: store, reviewer: reviewer, logger: log, pageSize: 500}
}

// Run backfills every tenant not yet done. It returns the number of tenants
// processed.
func (b *IdentityBackfill) Run(ctx context.Context) (int, error) {
	tenants, err := b.source.PendingTenants(ctx, IdentityBackfillVersion)
	if err != nil {
		return 0, fmt.Errorf("list tenants to backfill: %w", err)
	}
	done := 0
	for _, t := range tenants {
		if ctx.Err() != nil {
			return done, ctx.Err()
		}
		stats, err := b.RunTenant(ctx, t)
		if err != nil {
			b.logger.Warn("asset identifier backfill failed", "tenant_id", t.String(), "error", err)
			continue
		}
		if err := b.source.MarkBackfilled(ctx, t, IdentityBackfillVersion, stats); err != nil {
			b.logger.Warn("failed to mark identifier backfill done", "tenant_id", t.String(), "error", err)
			continue
		}
		b.logger.Info("asset identifier backfill complete", "tenant_id", t.String(),
			"assets", stats.AssetsScanned, "identifiers", stats.IdentifiersAdded, "reviews", stats.ReviewsEnqueued)
		done++
	}
	return done, nil
}

// sharedPair is two assets that carry one strong identifier.
type sharedPair struct {
	a, b  string
	kind  asset.IdentifierKind
	value string
}

// RunTenant backfills one tenant.
func (b *IdentityBackfill) RunTenant(ctx context.Context, tenantID shared.ID) (BackfillStats, error) {
	stats, pairs, err := b.recordIdentifiers(ctx, tenantID)
	if err != nil || b.reviewer == nil {
		return stats, err
	}
	n, err := b.reviewSharedIdentifiers(ctx, tenantID, pairs)
	stats.ReviewsEnqueued += n
	if err != nil {
		return stats, err
	}

	// Hosts one scanner reported with the same IP under two names: before
	// the Nessus and Vuls shapes were matched, a renamed host became a
	// second asset.
	candidates, err := b.source.RenamedHostCandidates(ctx, tenantID, 1000)
	if err != nil {
		return stats, err
	}
	for _, c := range candidates {
		if b.enqueue(ctx, tenantID, asset.DuplicateReasonRenamedHost,
			map[string]any{"ip": c.IP, "tool": c.Tool}, c.A, c.B) {
			stats.ReviewsEnqueued++
		}
	}
	return stats, nil
}

// recordIdentifiers pages through the tenant's assets, records their
// identifiers, and returns the strong identifiers two assets carry.
func (b *IdentityBackfill) recordIdentifiers(ctx context.Context, tenantID shared.ID) (BackfillStats, []sharedPair, error) {
	var stats BackfillStats
	var pairs []sharedPair
	after := ""
	for {
		page, err := b.source.ScanAssets(ctx, tenantID, after, b.pageSize)
		if err != nil {
			return stats, nil, err
		}
		if len(page) == 0 {
			return stats, pairs, nil
		}
		after = page[len(page)-1].ID.String()
		stats.AssetsScanned += len(page)

		var ids []asset.Identifier
		attempted := map[asset.IdentifierKey][]string{}
		for _, sa := range page {
			for _, id := range StoredAssetIdentifiers(sa) {
				ids = append(ids, id)
				if id.Kind.IsStrong() {
					attempted[id.Key()] = append(attempted[id.Key()], sa.ID.String())
				}
			}
		}
		stats.IdentifiersAdded += len(ids)
		taken, err := b.store.Upsert(ctx, tenantID, ids)
		if err != nil {
			return stats, nil, err
		}
		for _, t := range taken {
			for _, aid := range attempted[t.Key()] {
				if aid != t.AssetID.String() {
					pairs = append(pairs, sharedPair{a: t.AssetID.String(), b: aid, kind: t.Kind, value: t.Value})
				}
			}
		}
		if len(page) < b.pageSize {
			return stats, pairs, nil
		}
	}
}

// reviewSharedIdentifiers raises a review per pair of assets carrying one
// strong identifier.
func (b *IdentityBackfill) reviewSharedIdentifiers(ctx context.Context, tenantID shared.ID, pairs []sharedPair) (int, error) {
	if len(pairs) == 0 {
		return 0, nil
	}
	idSet := map[string]shared.ID{}
	for _, p := range pairs {
		for _, s := range []string{p.a, p.b} {
			if id, err := shared.IDFromString(s); err == nil {
				idSet[s] = id
			}
		}
	}
	ids := make([]shared.ID, 0, len(idSet))
	for _, id := range idSet {
		ids = append(ids, id)
	}
	loaded, err := b.source.GetStoredAssets(ctx, tenantID, ids)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, p := range pairs {
		x, okx := loaded[p.a]
		y, oky := loaded[p.b]
		if okx && oky && b.enqueue(ctx, tenantID, asset.DuplicateReasonSharedIdentifier,
			map[string]any{"kind": string(p.kind), "value": p.value}, x, y) {
			n++
		}
	}
	return n, nil
}

// enqueue raises a review keeping the asset with more history.
func (b *IdentityBackfill) enqueue(ctx context.Context, tenantID shared.ID, reason string, evidence map[string]any, x, y StoredAsset) bool {
	keep, other := x, y
	if other.FindingCount > keep.FindingCount ||
		(other.FindingCount == keep.FindingCount && other.CreatedAt.Before(keep.CreatedAt)) {
		keep, other = other, keep
	}
	ok, err := b.reviewer.EnqueueIdentityReview(ctx, tenantID.String(), asset.DuplicateReview{
		Reason:            reason,
		Evidence:          evidence,
		NormalizedName:    keep.Name,
		AssetType:         string(keep.Type),
		KeepID:            keep.ID.String(),
		KeepName:          keep.Name,
		KeepFindingCount:  keep.FindingCount,
		MergeIDs:          []string{other.ID.String()},
		MergeNames:        []string{other.Name},
		MergeFindingCount: other.FindingCount,
	})
	if err != nil {
		b.logger.Warn("failed to enqueue backfill review", "keep_id", keep.ID.String(), "error", err)
		return false
	}
	return ok
}

// StoredAssetIdentifiers derives the identifiers of an existing asset with
// the same rules ingest applies to a report, plus its repository ID and its
// former names. Former names get the asset's creation time as last_seen, so
// they do not count as recent evidence.
func StoredAssetIdentifiers(sa StoredAsset) []asset.Identifier {
	ca := &ctis.Asset{Type: ctis.AssetType(sa.Type), Value: sa.Name, Properties: ctis.Properties(sa.Properties)}
	derived := identifiersFor(ca, sa.Type, sa.Name)
	lastSeen := sa.LastSeen
	if lastSeen.IsZero() {
		lastSeen = sa.CreatedAt
	}
	firstSeen := sa.CreatedAt
	if firstSeen.IsZero() || firstSeen.After(lastSeen) {
		firstSeen = lastSeen
	}
	out := make([]asset.Identifier, 0, len(derived)+2)
	seen := map[asset.IdentifierKey]bool{}
	push := func(id asset.Identifier, first, last time.Time) {
		if seen[id.Key()] {
			return
		}
		seen[id.Key()] = true
		id.AssetID = sa.ID
		id.Source = "backfill"
		id.FirstSeen, id.LastSeen = first, last
		out = append(out, id)
	}
	for _, id := range derived {
		push(id, firstSeen, lastSeen)
	}
	if sa.Type == asset.AssetTypeRepository && sa.RepoID != "" {
		if v := asset.SCMRepoIdentifier(sa.Name, sa.RepoID); v != "" {
			push(asset.Identifier{Kind: asset.IdentifierSCMRepoID, Value: v}, firstSeen, lastSeen)
		}
	}
	if hostFamily(sa.Type) {
		for _, alias := range propStrings(sa.Properties["aliases"]) {
			alias = strings.TrimSpace(alias)
			if alias == "" || net.ParseIP(alias) != nil {
				continue
			}
			kind := asset.IdentifierHostname
			if strings.Contains(strings.TrimSuffix(alias, "."), ".") {
				kind = asset.IdentifierFQDN
			}
			if v, ok := asset.NormalizeIdentifier(kind, alias); ok {
				push(asset.Identifier{Kind: kind, Value: v}, firstSeen, firstSeen)
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Kind.Rank() < out[j].Kind.Rank() })
	return out
}
