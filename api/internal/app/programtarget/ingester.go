// Package programtarget ingests bug-bounty program targets as the tenant's
// assets through the standard CTIS ingest (RFC-065 §16.8,
// docs/rfcs/RFC-065-bug-bounty-programs.md) and records which assets are a
// program's targets.
//
// Security: the tenant is the program's tenant, never taken from the feed
// or the file; the ingest is a trusted server-side binding whose source kind
// is feed (the program feed) or import (a file or a paste), so a program
// never claims to be a scan or an integration; the organization's scope
// exclusions still drop matching new assets; the report states targets, not
// observations, so it opens no exposure and closes no port.
package programtarget

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/internal/app/bountyprogram"
	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	bp "github.com/openctemio/openctem/api/pkg/domain/bountyprogram"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// MaxAssetsPerProgram bounds one program's ingest.
const MaxAssetsPerProgram = 4 * bp.MaxScopeItems

// Ingest is the standard ingest (*ingest.Service).
type Ingest interface {
	Ingest(ctx context.Context, agt *sensor.Sensor, input ingest.Input) (*ingest.Output, error)
}

// Store records a program's target assets
// (*postgres.BountyProgramRepository).
type Store interface {
	// ReplaceTargetAssets sets the program's target assets to ids (asset
	// id -> item key); ids not of the tenant's assets are ignored.
	ReplaceTargetAssets(ctx context.Context, tenantID, programID shared.ID, ids map[shared.ID]string) error
}

// Ingester implements bountyprogram.TargetIngester.
type Ingester struct {
	ingest Ingest
	store  Store
	now    func() time.Time
}

// New wires the ingester.
func New(i Ingest, s Store) *Ingester {
	return &Ingester{ingest: i, store: s, now: func() time.Time { return time.Now().UTC() }}
}

var _ bountyprogram.TargetIngester = (*Ingester)(nil)

// IngestProgramTargets ingests assets as the program's targets for
// tenantID and records them. No assets clears the program's targets.
func (g *Ingester) IngestProgramTargets(ctx context.Context, tenantID, programID shared.ID, src bountyprogram.TargetSource, assets []bp.TargetAsset) error {
	if tenantID.IsZero() || programID.IsZero() {
		return fmt.Errorf("%w: program target ingest needs a tenant and a program", shared.ErrValidation)
	}
	if len(assets) > MaxAssetsPerProgram {
		assets = assets[:MaxAssetsPerProgram]
	}
	ids := map[shared.ID]string{}
	if len(assets) > 0 {
		report, keys := Report(programID, src, assets, g.now())
		kind := asset.SourceKindImport
		if src.Feed {
			kind = asset.SourceKindFeed
		}
		agt := &sensor.Sensor{TenantID: &tenantID, Status: sensor.SensorStatusActive}
		out, err := g.ingest.Ingest(ctx, agt, ingest.Input{
			Report:       report,
			CoverageType: ingest.CoverageTypePartial,
			Options: ingest.Options{
				Binding:              ingest.Binding{Kind: ingest.BindingTrusted},
				SourceKind:           kind,
				SourceName:           src.Name,
				SourceRun:            src.Run,
				NoExposureProjection: true,
				DeferSensorStats:     true,
				NoCatalogWrites:      true,
			},
		})
		if err != nil {
			return fmt.Errorf("ingest program targets: %w", err)
		}
		for ref, id := range out.AssetMap {
			if key, ok := keys[ref]; ok && !id.IsZero() {
				ids[id] = key
			}
		}
	}
	return g.store.ReplaceTargetAssets(ctx, tenantID, programID, ids)
}

// Report is the CTIS report of a program's targets: one asset per target
// asset, observed when the source saw the data (never in the future). It
// returns the report and each report asset id's item key.
func Report(programID shared.ID, src bountyprogram.TargetSource, assets []bp.TargetAsset, now time.Time) (*ctis.Report, map[string]string) {
	observed := src.ObservedAt
	if observed.IsZero() || observed.After(now) {
		observed = now
	}
	r := ctis.NewReport()
	r.Metadata.ID = "program:" + programID.String()
	r.Metadata.Timestamp = observed
	r.Metadata.SourceType = "integration"
	r.Metadata.SourceRef = src.Run
	r.Metadata.CoverageType = string(ingest.CoverageTypePartial)
	r.Tool = &ctis.Tool{Name: src.Name}
	keys := make(map[string]string, len(assets))
	for i, a := range assets {
		id := "t" + strconv.Itoa(i)
		keys[id] = a.Key
		// A program publishes its network targets as reachable from the
		// internet (exposure, a tracked attribute with this source).
		public := a.Type != bp.TargetAssetMobileApp && a.Type != bp.TargetAssetRepo
		r.Assets = append(r.Assets, ctis.Asset{ID: id, Type: ctis.AssetType(a.Type), Value: a.Value, IsInternetAccessible: public})
	}
	return r, keys
}
