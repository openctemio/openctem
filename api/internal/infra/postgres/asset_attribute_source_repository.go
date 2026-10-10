package postgres

// Per-source values of reconciled asset attributes (RFC-069,
// docs/architecture/asset-attribute-reconciliation.md).

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// AssetAttributeSourceRepository implements asset.AttributeSourceRepository.
type AssetAttributeSourceRepository struct {
	db *DB
}

// NewAssetAttributeSourceRepository creates the repository.
func NewAssetAttributeSourceRepository(db *DB) *AssetAttributeSourceRepository {
	return &AssetAttributeSourceRepository{db: db}
}

var _ asset.AttributeSourceRepository = (*AssetAttributeSourceRepository)(nil)

// assetAttributeColumns maps an attribute to its assets column.
var assetAttributeColumns = map[asset.TrackedAttribute]string{
	asset.AttrCriticality:        "criticality",
	asset.AttrOwnerRef:           "owner_ref",
	asset.AttrExposure:           "exposure",
	asset.AttrDataClassification: "data_classification",
}

// Apply records observations, releases locks and writes the resolved values,
// in one transaction with the touched asset rows locked (in id order, so two
// concurrent applies never deadlock).
func (r *AssetAttributeSourceRepository) Apply(ctx context.Context, tenantID shared.ID, in asset.AttributeApply) ([]asset.AttributeChange, error) {
	touched := map[shared.ID]map[asset.TrackedAttribute]bool{}
	mark := func(id shared.ID, attr asset.TrackedAttribute) {
		if touched[id] == nil {
			touched[id] = map[asset.TrackedAttribute]bool{}
		}
		touched[id][attr] = true
	}
	for _, o := range in.Observations {
		mark(o.AssetID, o.Attribute)
	}
	for _, ref := range in.Release {
		mark(ref.AssetID, ref.Attribute)
	}
	if len(touched) == 0 {
		return nil, nil
	}
	now := in.Now
	if now.IsZero() {
		now = time.Now()
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	ids := make([]string, 0, len(touched))
	for id := range touched {
		ids = append(ids, id.String())
	}
	sort.Strings(ids)
	current, err := lockAssetAttributes(ctx, tx, tenantID, ids)
	if err != nil {
		return nil, err
	}

	if err := recordAttributeObservations(ctx, tx, tenantID, in.Observations, current, now); err != nil {
		return nil, err
	}
	for _, ref := range in.Release {
		if _, ok := current[ref.AssetID]; !ok {
			continue
		}
		if _, err := tx.ExecContext(ctx, `
			DELETE FROM asset_attribute_sources
			 WHERE tenant_id = $1 AND asset_id = $2 AND attribute = $3 AND source_kind = 'manual'`,
			tenantID.String(), ref.AssetID.String(), string(ref.Attribute)); err != nil {
			return nil, fmt.Errorf("release lock: %w", err)
		}
	}

	stored, err := loadAttributeObservations(ctx, tx, tenantID, ids)
	if err != nil {
		return nil, err
	}
	var changes []asset.AttributeChange
	for id, attrs := range touched {
		cur, ok := current[id]
		if !ok {
			continue // not this tenant's asset, or deleted
		}
		for attr := range attrs {
			res := asset.Resolve(attr, stored[id], in.Policy, now)
			if res.Winner == nil || res.Winner.Value == cur[attr] {
				continue
			}
			if err := writeAssetAttribute(ctx, tx, tenantID, id, attr, res.Winner.Value); err != nil {
				return nil, err
			}
			changes = append(changes, asset.AttributeChange{
				AssetID: id, Attribute: attr, Old: cur[attr], New: res.Winner.Value, Source: *res.Winner,
			})
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}
	sort.Slice(changes, func(i, j int) bool {
		if changes[i].AssetID != changes[j].AssetID {
			return changes[i].AssetID.String() < changes[j].AssetID.String()
		}
		return changes[i].Attribute < changes[j].Attribute
	})
	return changes, nil
}

// lockAssetAttributes locks the tenant's assets among ids and returns their
// current tracked values. Ids of other tenants or deleted assets are absent.
func lockAssetAttributes(ctx context.Context, tx *sql.Tx, tenantID shared.ID, ids []string) (map[shared.ID]map[asset.TrackedAttribute]string, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT id, criticality, COALESCE(owner_ref, ''), exposure, COALESCE(data_classification, '')
		  FROM assets
		 WHERE tenant_id = $1 AND id = ANY($2::uuid[]) AND deleted_at IS NULL
		 ORDER BY id
		 FOR UPDATE`, tenantID.String(), pq.Array(ids))
	if err != nil {
		return nil, fmt.Errorf("lock assets: %w", err)
	}
	defer rows.Close()
	out := map[shared.ID]map[asset.TrackedAttribute]string{}
	for rows.Next() {
		var id, crit, owner, exposure, dc string
		if err := rows.Scan(&id, &crit, &owner, &exposure, &dc); err != nil {
			return nil, fmt.Errorf("lock assets: %w", err)
		}
		aid, err := shared.IDFromString(id)
		if err != nil {
			return nil, fmt.Errorf("lock assets: %w", err)
		}
		out[aid] = map[asset.TrackedAttribute]string{
			asset.AttrCriticality: crit, asset.AttrOwnerRef: owner,
			asset.AttrExposure: exposure, asset.AttrDataClassification: dc,
		}
	}
	return out, rows.Err()
}

// recordAttributeObservations upserts the observations of the locked assets.
// A source's stored row is replaced only by one it observed at the same time
// or later. A manual row replaces the attribute's other manual rows.
func recordAttributeObservations(ctx context.Context, tx *sql.Tx, tenantID shared.ID,
	obs []asset.AttributeObservation, locked map[shared.ID]map[asset.TrackedAttribute]string, now time.Time,
) error {
	if len(obs) == 0 {
		return nil
	}
	n := len(obs)
	assetIDs := make([]string, 0, n)
	attrs := make([]string, 0, n)
	kinds := make([]string, 0, n)
	names := make([]string, 0, n)
	values := make([]string, 0, n)
	observed := make([]time.Time, 0, n)
	conf := make([]int64, 0, n)
	for _, o := range obs {
		if _, ok := locked[o.AssetID]; !ok || !o.Attribute.IsValid() || !o.Kind.IsValid() {
			continue
		}
		value, err := asset.NormalizeAttributeValue(o.Attribute, o.Value)
		if err != nil {
			continue // never store a value the asset column would refuse
		}
		at := o.ObservedAt
		if at.IsZero() || at.After(now) {
			at = now
		}
		c := o.Confidence
		if c < 0 || c > 100 {
			c = 100
		}
		if o.Kind == asset.SourceKindManual {
			if _, err := tx.ExecContext(ctx, `
				DELETE FROM asset_attribute_sources
				 WHERE tenant_id = $1 AND asset_id = $2 AND attribute = $3 AND source_kind = 'manual' AND source_name <> $4`,
				tenantID.String(), o.AssetID.String(), string(o.Attribute), clipStr(o.Name, asset.MaxSourceNameLength)); err != nil {
				return fmt.Errorf("replace lock: %w", err)
			}
		}
		assetIDs = append(assetIDs, o.AssetID.String())
		attrs = append(attrs, string(o.Attribute))
		kinds = append(kinds, string(o.Kind))
		names = append(names, clipStr(o.Name, asset.MaxSourceNameLength))
		values = append(values, value)
		observed = append(observed, at.UTC())
		conf = append(conf, int64(c))
	}
	if len(assetIDs) == 0 {
		return nil
	}
	// One row per source key in a statement (ON CONFLICT cannot touch a row
	// twice): DISTINCT ON keeps the latest observation of each.
	_, err := tx.ExecContext(ctx, `
		INSERT INTO asset_attribute_sources AS s
		       (tenant_id, asset_id, attribute, source_kind, source_name, value, observed_at, ingested_at, confidence)
		SELECT DISTINCT ON (o.asset_id, o.attribute, o.kind, o.name)
		       $1::uuid, o.asset_id, o.attribute, o.kind, o.name, o.value, o.observed_at, $9, o.confidence
		  FROM unnest($2::uuid[], $3::text[], $4::text[], $5::text[], $6::text[], $7::timestamptz[], $8::smallint[])
		       AS o(asset_id, attribute, kind, name, value, observed_at, confidence)
		 ORDER BY o.asset_id, o.attribute, o.kind, o.name, o.observed_at DESC
		ON CONFLICT ON CONSTRAINT pk_asset_attribute_sources DO UPDATE SET
		       value = EXCLUDED.value, observed_at = EXCLUDED.observed_at,
		       ingested_at = EXCLUDED.ingested_at, confidence = EXCLUDED.confidence
		 WHERE s.observed_at <= EXCLUDED.observed_at`,
		tenantID.String(), pq.Array(assetIDs), pq.Array(attrs), pq.Array(kinds), pq.Array(names),
		pq.Array(values), pq.Array(observed), pq.Array(conf), now.UTC())
	if err != nil {
		return fmt.Errorf("record observations: %w", err)
	}
	return nil
}

func loadAttributeObservations(ctx context.Context, q interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}, tenantID shared.ID, ids []string,
) (map[shared.ID][]asset.AttributeObservation, error) {
	rows, err := q.QueryContext(ctx, `
		SELECT asset_id, attribute, source_kind, source_name, value, observed_at, ingested_at, confidence
		  FROM asset_attribute_sources
		 WHERE tenant_id = $1 AND asset_id = ANY($2::uuid[])`, tenantID.String(), pq.Array(ids))
	if err != nil {
		return nil, fmt.Errorf("load observations: %w", err)
	}
	defer rows.Close()
	out := map[shared.ID][]asset.AttributeObservation{}
	for rows.Next() {
		var (
			assetID, attr, kind, name, value string
			observed, ingested               time.Time
			confidence                       int
		)
		if err := rows.Scan(&assetID, &attr, &kind, &name, &value, &observed, &ingested, &confidence); err != nil {
			return nil, fmt.Errorf("load observations: %w", err)
		}
		id, err := shared.IDFromString(assetID)
		if err != nil {
			return nil, fmt.Errorf("load observations: %w", err)
		}
		out[id] = append(out[id], asset.AttributeObservation{
			AssetID: id, Attribute: asset.TrackedAttribute(attr), Kind: asset.SourceKind(kind), Name: name,
			Value: value, ObservedAt: observed, IngestedAt: ingested, Confidence: confidence,
		})
	}
	return out, rows.Err()
}

// writeAssetAttribute sets one resolved value on the asset row.
func writeAssetAttribute(ctx context.Context, tx *sql.Tx, tenantID, assetID shared.ID, attr asset.TrackedAttribute, value string) error {
	var q string
	switch attr {
	case asset.AttrExposure:
		q = `UPDATE assets SET exposure = $3, last_exposure_level = exposure, exposure_changed_at = now(), updated_at = now()
		      WHERE tenant_id = $1 AND id = $2`
	case asset.AttrOwnerRef, asset.AttrDataClassification:
		q = `UPDATE assets SET ` + assetAttributeColumns[attr] + ` = NULLIF($3, ''), updated_at = now()
		      WHERE tenant_id = $1 AND id = $2`
	case asset.AttrCriticality:
		q = `UPDATE assets SET criticality = $3, updated_at = now() WHERE tenant_id = $1 AND id = $2`
	default:
		return fmt.Errorf("unknown attribute %q", attr)
	}
	if _, err := tx.ExecContext(ctx, q, tenantID.String(), assetID.String(), value); err != nil {
		return fmt.Errorf("write %s: %w", attr, err)
	}
	return nil
}

// ListForAsset returns every observation of one of the tenant's assets.
func (r *AssetAttributeSourceRepository) ListForAsset(ctx context.Context, tenantID, assetID shared.ID) ([]asset.AttributeObservation, error) {
	m, err := loadAttributeObservations(ctx, r.db, tenantID, []string{assetID.String()})
	if err != nil {
		return nil, err
	}
	return m[assetID], nil
}
