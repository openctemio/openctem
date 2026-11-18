package assettech

// Software links for stored technologies whose version is hidden
// (docs/architecture/vulnerability-matching.md, "Version hidden"): ingest
// now links a detection of a curated public product without a version; this
// job does the same once for the technologies stored before it did.

import (
	"context"
	"time"

	"github.com/openctemio/openctem/server/pkg/domain/assettech"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/software"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// SoftwareLinkVersion is bumped when every tenant must be linked again (the
// curated list gained names that stored technologies may carry).
const SoftwareLinkVersion = 1

// softwareLinkBatch is the technologies one batch reads and links.
const softwareLinkBatch = 500

// VersionlessTechnology is one stored technology with no version.
type VersionlessTechnology struct {
	AssetID    shared.ID
	Key        string
	Name       string
	Confidence int
	LastSeen   time.Time
}

// SoftwareLinkProgress is where a tenant's run stands.
type SoftwareLinkProgress struct {
	AfterAsset string
	AfterKey   string
	Linked     int
}

// SoftwareLinkStore is the job's view of the database. Every method but
// PendingSoftwareLinkTenants is tenant-scoped.
type SoftwareLinkStore interface {
	// PendingSoftwareLinkTenants returns tenants with technologies that are
	// not done at version, with the position a previous run reached.
	PendingSoftwareLinkTenants(ctx context.Context, version int) ([]shared.ID, error)
	SoftwareLinkProgress(ctx context.Context, tenantID shared.ID, version int) (SoftwareLinkProgress, error)
	// ScanVersionlessTechnologies returns the tenant's next technologies
	// with no version and no CPE whose key is one of keys, in (asset_id,
	// name_key) order after the given position.
	ScanVersionlessTechnologies(ctx context.Context, tenantID shared.ID, afterAsset, afterKey string, keys []string, limit int) ([]VersionlessTechnology, error)
	// SaveSoftwareLinkProgress records the position reached; done marks the
	// tenant finished at version.
	SaveSoftwareLinkProgress(ctx context.Context, tenantID shared.ID, version int, p SoftwareLinkProgress, done bool) error
}

// SoftwareChangeSink receives the assets whose software changed (the
// matcher's queue).
type SoftwareChangeSink interface {
	SoftwareChanged(tenantID shared.ID, assetIDs []shared.ID)
}

// SoftwareLinkBackfill links the stored version-less technologies of
// curated public products, a batch at a time, resumable per tenant: a run
// stopped by its budget or a restart continues from the last saved
// position. Writing a link is idempotent (the version history counts one
// sighting per time), so a batch done twice changes nothing.
type SoftwareLinkBackfill struct {
	store    SoftwareLinkStore
	software software.Repository
	sink     SoftwareChangeSink
	log      *logger.Logger
}

// NewSoftwareLinkBackfill creates the job. sink may be nil.
func NewSoftwareLinkBackfill(store SoftwareLinkStore, repo software.Repository, sink SoftwareChangeSink, log *logger.Logger) *SoftwareLinkBackfill {
	return &SoftwareLinkBackfill{store: store, software: repo, sink: sink, log: log}
}

// Run links every pending tenant until ctx ends; it returns how many tenants
// it finished.
func (b *SoftwareLinkBackfill) Run(ctx context.Context) (int, error) {
	tenants, err := b.store.PendingSoftwareLinkTenants(ctx, SoftwareLinkVersion)
	if err != nil || len(tenants) == 0 {
		return 0, err
	}
	// Names resolve to the curated global products only once they exist.
	if err := b.software.EnsureCurated(ctx, software.CuratedProducts()); err != nil {
		return 0, err
	}
	done := 0
	for _, t := range tenants {
		if err := ctx.Err(); err != nil {
			return done, err // the run's time is up: the rest resume next run
		}
		finished, err := b.RunTenant(ctx, t)
		if err != nil {
			b.log.Warn("software link backfill failed", "tenant_id", t.String(), "error", logger.SanitizeError(err))
			continue
		}
		if finished {
			done++
		}
	}
	return done, nil
}

// RunTenant links one tenant's technologies from its saved position; it
// reports whether the tenant is finished.
func (b *SoftwareLinkBackfill) RunTenant(ctx context.Context, tenantID shared.ID) (bool, error) {
	p, err := b.store.SoftwareLinkProgress(ctx, tenantID, SoftwareLinkVersion)
	if err != nil {
		return false, err
	}
	keys := software.CuratedAppNames()
	for {
		if err := ctx.Err(); err != nil {
			return false, err // the position is saved: the next run resumes here
		}
		rows, err := b.store.ScanVersionlessTechnologies(ctx, tenantID, p.AfterAsset, p.AfterKey, keys, softwareLinkBatch)
		if err != nil {
			return false, err
		}
		if len(rows) > 0 {
			n, err := b.link(ctx, tenantID, rows)
			if err != nil {
				return false, err
			}
			p.Linked += n
			last := rows[len(rows)-1]
			p.AfterAsset, p.AfterKey = last.AssetID.String(), last.Key
		}
		finished := len(rows) < softwareLinkBatch
		if err := b.store.SaveSoftwareLinkProgress(ctx, tenantID, SoftwareLinkVersion, p, finished); err != nil {
			return false, err
		}
		if finished {
			b.log.Info("software link backfill done", "tenant_id", tenantID.String(), "linked", p.Linked)
			return true, nil
		}
	}
}

// link writes the links of one batch and queues its assets for matching.
func (b *SoftwareLinkBackfill) link(ctx context.Context, tenantID shared.ID, rows []VersionlessTechnology) (int, error) {
	obs := make([]software.AssetObservation, 0, len(rows))
	for _, r := range rows {
		if !assettech.IsSoftwareCandidate(r.Name, "", "", nil) {
			continue
		}
		obs = append(obs, software.AssetObservation{
			AssetID: r.AssetID,
			Obs: software.Observation{Name: r.Name, Source: software.SourceTechnology, Evidence: r.Name,
				ToolConfidence: r.Confidence},
			ObservedAt: r.LastSeen,
		})
	}
	links, err := software.BuildLinks(ctx, b.software, tenantID, obs)
	if err != nil || len(links) == 0 {
		return 0, err
	}
	res, err := b.software.UpsertLinks(ctx, tenantID, links)
	if err != nil {
		return 0, err
	}
	if b.sink != nil && len(res.ChangedAssets) > 0 {
		b.sink.SoftwareChanged(tenantID, res.ChangedAssets)
	}
	return res.Inserted, nil
}
