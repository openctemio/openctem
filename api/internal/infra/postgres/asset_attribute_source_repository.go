package postgres

// Per-source values of reconciled asset attributes (RFC-069,
// docs/architecture/asset-attribute-reconciliation.md).

import (
	"context"
	"database/sql"
	"errors"
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
// concurrent applies never deadlock). Each changed value or deciding source
// is a timeline event written in the same transaction.
func (r *AssetAttributeSourceRepository) Apply(ctx context.Context, tenantID shared.ID, in asset.AttributeApply) (asset.ApplyResult, error) {
	result := asset.ApplyResult{Verdicts: map[asset.ObservationVerdict]int{}}
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
	released := map[asset.AttributeRef]bool{}
	for _, ref := range in.Release {
		mark(ref.AssetID, ref.Attribute)
		released[ref] = true
	}
	for _, ref := range in.Resolve {
		mark(ref.AssetID, ref.Attribute)
	}
	if len(touched) == 0 {
		return result, nil
	}
	now := in.Now
	if now.IsZero() {
		now = time.Now()
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return result, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	ids := make([]string, 0, len(touched))
	for id := range touched {
		ids = append(ids, id.String())
	}
	sort.Strings(ids)
	current, err := lockAssetAttributes(ctx, tx, tenantID, ids)
	if err != nil {
		return result, err
	}
	before, err := loadAttributeObservations(ctx, tx, tenantID, ids)
	if err != nil {
		return result, err
	}

	recorded, err := recordAttributeObservations(ctx, tx, tenantID, in.Observations, current, before, now, result.Verdicts)
	if err != nil {
		return result, err
	}
	for _, ref := range in.Release {
		if _, ok := current[ref.AssetID]; !ok {
			continue
		}
		if _, err := tx.ExecContext(ctx, `
			DELETE FROM asset_attribute_sources
			 WHERE tenant_id = $1 AND asset_id = $2 AND attribute = $3 AND source_kind = 'manual'`,
			tenantID.String(), ref.AssetID.String(), string(ref.Attribute)); err != nil {
			return result, fmt.Errorf("release lock: %w", err)
		}
	}

	stored, err := loadAttributeObservations(ctx, tx, tenantID, ids)
	if err != nil {
		return result, err
	}
	rs := resolveState{tenantID: tenantID, in: in, now: now, current: current, before: before,
		stored: stored, recorded: recorded, released: released}
	changes, events, err := rs.resolveTouched(ctx, tx, touched)
	if err != nil {
		return result, err
	}
	result.Changes = changes
	for _, ev := range events {
		if err := recordChangeEvent(ctx, tx, ev, now); err != nil {
			return result, err
		}
	}
	result.Events = len(events)
	if err := tx.Commit(); err != nil {
		return result, fmt.Errorf("commit: %w", err)
	}
	sort.Slice(result.Changes, func(i, j int) bool {
		if result.Changes[i].AssetID != result.Changes[j].AssetID {
			return result.Changes[i].AssetID.String() < result.Changes[j].AssetID.String()
		}
		return result.Changes[i].Attribute < result.Changes[j].Attribute
	})
	return result, nil
}

// resolveState is one Apply's view of the touched assets.
type resolveState struct {
	tenantID shared.ID
	in       asset.AttributeApply
	now      time.Time
	current  map[shared.ID]map[asset.TrackedAttribute]string
	before   map[shared.ID][]asset.AttributeObservation // records before this apply
	stored   map[shared.ID][]asset.AttributeObservation // records after it
	recorded map[observationKey]bool
	released map[asset.AttributeRef]bool
}

// resolveTouched re-resolves every touched attribute, flags the deciding
// record, writes changed values and returns the changes and the timeline
// events (value or deciding-source changes), events in asset order.
func (rs resolveState) resolveTouched(ctx context.Context, tx *sql.Tx, touched map[shared.ID]map[asset.TrackedAttribute]bool) ([]asset.AttributeChange, []asset.ChangeEvent, error) {
	var (
		changes []asset.AttributeChange
		events  []asset.ChangeEvent
	)
	for id, attrs := range touched {
		cur, ok := rs.current[id]
		if !ok {
			continue // not this tenant's asset, or deleted
		}
		for attr := range attrs {
			ch, ev, err := rs.resolveOne(ctx, tx, id, attr, cur[attr])
			if err != nil {
				return nil, nil, err
			}
			if ch != nil {
				changes = append(changes, *ch)
			}
			if ev != nil {
				events = append(events, *ev)
			}
		}
	}
	sort.Slice(events, func(i, j int) bool {
		if events[i].AssetID != events[j].AssetID {
			return events[i].AssetID.String() < events[j].AssetID.String()
		}
		return events[i].Attribute < events[j].Attribute
	})
	return changes, events, nil
}

// resolveOne resolves one attribute of one asset that shows cur.
func (rs resolveState) resolveOne(ctx context.Context, tx *sql.Tx, id shared.ID, attr asset.TrackedAttribute, cur string) (*asset.AttributeChange, *asset.ChangeEvent, error) {
	in, now, tenantID := rs.in, rs.now, rs.tenantID
	prev := storedWinner(rs.before[id], attr)
	res := asset.ResolveFrom(attr, rs.stored[id], in.Policy, now, cur)
	if err := markAttributeWinner(ctx, tx, tenantID, id, attr, res.Winner); err != nil {
		return nil, nil, err
	}
	if res.Winner == nil {
		return nil, nil, nil
	}
	w := *res.Winner
	valueChanged := w.Value != cur
	sourceChanged := prev != nil && !prev.SameSource(w)
	if !valueChanged && !sourceChanged {
		return nil, nil, nil
	}
	fresh := rs.recorded[observationKey{id, attr, w.Kind, w.Name}]
	reason := changeReason(in, w, fresh, rs.released[asset.AttributeRef{AssetID: id, Attribute: attr}], prev, now)
	var change *asset.AttributeChange
	if valueChanged {
		if err := writeAssetAttribute(ctx, tx, tenantID, id, attr, w.Value); err != nil {
			return nil, nil, err
		}
		change = &asset.AttributeChange{AssetID: id, Attribute: attr, Old: cur, New: w.Value, Source: w, Reason: reason}
	}
	at := now
	if fresh && w.Kind != asset.SourceKindManual {
		at = w.ObservedAt
	}
	ev := &asset.ChangeEvent{
		ID: shared.NewID(), TenantID: tenantID, AssetID: id, At: at, Attribute: string(attr),
		Old: cur, New: w.Value, SourceKind: w.Kind, SourceName: w.Name, SourceRun: w.SourceRun,
		Reason: reason, FlapCount: 1, CreatedAt: now,
	}
	if w.Kind == asset.SourceKindManual || reason == asset.ChangeReasonLockReleased {
		ev.ActorID = in.Actor
	}
	return change, ev, nil
}

// observationKey identifies one source's record.
type observationKey struct {
	asset shared.ID
	attr  asset.TrackedAttribute
	kind  asset.SourceKind
	name  string
}

// storedWinner is the record flagged as deciding attr, or nil.
func storedWinner(obs []asset.AttributeObservation, attr asset.TrackedAttribute) *asset.AttributeObservation {
	for i := range obs {
		if obs[i].Attribute == attr && obs[i].Winner {
			return &obs[i]
		}
	}
	return nil
}

// changeReason says why attr now shows w. fresh: w was recorded by this
// apply; released: this apply released the attribute's lock; prev: the
// record that decided before.
func changeReason(in asset.AttributeApply, w asset.AttributeObservation, fresh, released bool,
	prev *asset.AttributeObservation, now time.Time,
) asset.ChangeReason {
	switch {
	case fresh && w.Kind == asset.SourceKindManual:
		return asset.ChangeReasonManualLock
	case fresh:
		return asset.ChangeReasonNewerObservation
	case released:
		return asset.ChangeReasonLockReleased
	case prev != nil && !in.Policy.Trusts(prev.Attribute, prev.Kind):
		return asset.ChangeReasonPolicyChange
	case prev != nil && in.Policy.Stale(*prev, now):
		return asset.ChangeReasonTTLExpiry
	case in.Reason.IsValid():
		return in.Reason
	}
	return asset.ChangeReasonNewerObservation
}

// markAttributeWinner flags the record of w as deciding the attribute (and
// no other); none when w is nil. Rows already right are not rewritten.
func markAttributeWinner(ctx context.Context, tx *sql.Tx, tenantID, assetID shared.ID, attr asset.TrackedAttribute, w *asset.AttributeObservation) error {
	kind, name := "", ""
	if w != nil {
		kind, name = string(w.Kind), w.Name
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE asset_attribute_sources
		   SET winner = (source_kind = $4 AND source_name = $5)
		 WHERE tenant_id = $1 AND asset_id = $2 AND attribute = $3
		   AND winner IS DISTINCT FROM (source_kind = $4 AND source_name = $5)`,
		tenantID.String(), assetID.String(), string(attr), kind, name); err != nil {
		return fmt.Errorf("mark winner: %w", err)
	}
	return nil
}

// recordChangeEvent writes ev, or folds it into the attribute's newest
// event when the value flips back within the flap window.
func recordChangeEvent(ctx context.Context, tx *sql.Tx, ev asset.ChangeEvent, now time.Time) error {
	latest, err := latestChangeEvent(ctx, tx, ev.TenantID, ev.AssetID, ev.Attribute)
	if err != nil {
		return err
	}
	var actor any
	if ev.ActorID != nil {
		actor = ev.ActorID.String()
	}
	if latest.Coalesces(ev, now) {
		at := latest.At
		if ev.At.After(at) {
			at = ev.At
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE asset_change_events
			   SET at = $4, new_value = $5, flap_count = flap_count + 1,
			       source_kind = $6, source_name = $7, source_run = $8, actor_id = $9, reason = $10
			 WHERE tenant_id = $1 AND at = $2 AND id = $3`,
			ev.TenantID.String(), latest.At, latest.ID.String(), at, clipStr(ev.New, 500),
			string(ev.SourceKind), clipStr(ev.SourceName, asset.MaxSourceNameLength), clipStr(ev.SourceRun, 100),
			actor, string(ev.Reason)); err != nil {
			return fmt.Errorf("coalesce change event: %w", err)
		}
		return nil
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO asset_change_events
		       (id, tenant_id, asset_id, at, attribute, old_value, new_value, added, removed,
		        source_kind, source_name, source_run, actor_id, reason, flap_count, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, 1, $15)`,
		ev.ID.String(), ev.TenantID.String(), ev.AssetID.String(), ev.At.UTC(), ev.Attribute,
		clipStr(ev.Old, 500), clipStr(ev.New, 500), nullTextArray(ev.Added), nullTextArray(ev.Removed),
		string(ev.SourceKind), clipStr(ev.SourceName, asset.MaxSourceNameLength), clipStr(ev.SourceRun, 100),
		actor, string(ev.Reason), now.UTC()); err != nil {
		return fmt.Errorf("record change event: %w", err)
	}
	return nil
}

func nullTextArray(v []string) any {
	if len(v) == 0 {
		return nil
	}
	return pq.Array(v)
}

// latestChangeEvent is the newest event of one asset attribute, or nil.
func latestChangeEvent(ctx context.Context, tx *sql.Tx, tenantID, assetID shared.ID, attribute string) (*asset.ChangeEvent, error) {
	var (
		id, reason     string
		ev             asset.ChangeEvent
		added, removed pq.StringArray
	)
	err := tx.QueryRowContext(ctx, `
		SELECT id, at, old_value, new_value, added, removed, flap_count, created_at, reason
		  FROM asset_change_events
		 WHERE tenant_id = $1 AND asset_id = $2 AND attribute = $3
		 ORDER BY at DESC, id DESC
		 LIMIT 1`, tenantID.String(), assetID.String(), attribute).
		Scan(&id, &ev.At, &ev.Old, &ev.New, &added, &removed, &ev.FlapCount, &ev.CreatedAt, &reason)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("latest change event: %w", err)
	}
	if ev.ID, err = shared.IDFromString(id); err != nil {
		return nil, fmt.Errorf("latest change event: %w", err)
	}
	ev.TenantID, ev.AssetID, ev.Attribute = tenantID, assetID, attribute
	ev.Added, ev.Removed = added, removed
	ev.Reason = asset.ChangeReason(reason)
	return &ev, nil
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

// recordAttributeObservations records the observations of the locked
// assets that ClassifyObservation accepts against the stored records
// (before), counting every verdict, and returns the records it wrote. A
// source's record moves only forward in observation time; a re-sighting of
// the same value is written at most once per refresh interval. A manual row
// replaces the attribute's other manual rows.
func recordAttributeObservations(ctx context.Context, tx *sql.Tx, tenantID shared.ID,
	obs []asset.AttributeObservation, locked map[shared.ID]map[asset.TrackedAttribute]string,
	before map[shared.ID][]asset.AttributeObservation, now time.Time, verdicts map[asset.ObservationVerdict]int,
) (map[observationKey]bool, error) {
	recorded := map[observationKey]bool{}
	if len(obs) == 0 {
		return recorded, nil
	}
	storedOf := map[observationKey]*asset.AttributeObservation{}
	for id, rows := range before {
		for i := range rows {
			o := &rows[i]
			storedOf[observationKey{id, o.Attribute, o.Kind, o.Name}] = o
		}
	}
	// The newest observation of each source in this batch; older ones of
	// the same source are out of order.
	latest := map[observationKey]asset.AttributeObservation{}
	var order []observationKey
	for _, o := range obs {
		if _, ok := locked[o.AssetID]; !ok || !o.Attribute.IsValid() || !o.Kind.IsValid() {
			continue
		}
		value, err := asset.NormalizeAttributeValue(o.Attribute, o.Value)
		if err != nil {
			continue // never store a value the asset column would refuse
		}
		o.Value = value
		o.Name = clipStr(o.Name, asset.MaxSourceNameLength)
		o.SourceRun = clipStr(o.SourceRun, 100)
		if o.ObservedAt.IsZero() || o.ObservedAt.After(now) {
			o.ObservedAt = now
		}
		if o.Confidence < 0 || o.Confidence > 100 {
			o.Confidence = 100
		}
		k := observationKey{o.AssetID, o.Attribute, o.Kind, o.Name}
		prev, seen := latest[k]
		switch {
		case !seen:
			order = append(order, k)
			latest[k] = o
		case o.ObservedAt.After(prev.ObservedAt):
			verdicts[asset.ObservationOutOfOrder]++
			latest[k] = o
		default:
			verdicts[asset.ObservationOutOfOrder]++
		}
	}
	accepted := make([]asset.AttributeObservation, 0, len(order))
	for _, k := range order {
		o := latest[k]
		v := asset.ClassifyObservation(storedOf[k], o, asset.ResightingRefreshInterval)
		verdicts[v]++
		if !v.Accepted() {
			continue
		}
		accepted = append(accepted, o)
		recorded[k] = true
	}
	if len(accepted) == 0 {
		return recorded, nil
	}
	n := len(accepted)
	assetIDs := make([]string, 0, n)
	attrs := make([]string, 0, n)
	kinds := make([]string, 0, n)
	names := make([]string, 0, n)
	values := make([]string, 0, n)
	observed := make([]time.Time, 0, n)
	conf := make([]int64, 0, n)
	runs := make([]string, 0, n)
	for _, o := range accepted {
		if o.Kind == asset.SourceKindManual {
			if _, err := tx.ExecContext(ctx, `
				DELETE FROM asset_attribute_sources
				 WHERE tenant_id = $1 AND asset_id = $2 AND attribute = $3 AND source_kind = 'manual' AND source_name <> $4`,
				tenantID.String(), o.AssetID.String(), string(o.Attribute), o.Name); err != nil {
				return nil, fmt.Errorf("replace lock: %w", err)
			}
		}
		assetIDs = append(assetIDs, o.AssetID.String())
		attrs = append(attrs, string(o.Attribute))
		kinds = append(kinds, string(o.Kind))
		names = append(names, o.Name)
		values = append(values, o.Value)
		observed = append(observed, o.ObservedAt.UTC())
		conf = append(conf, int64(o.Confidence))
		runs = append(runs, o.SourceRun)
	}
	// One row per source key (deduplicated above). The WHERE keeps the
	// forward-only rule under a concurrent writer as well.
	_, err := tx.ExecContext(ctx, `
		INSERT INTO asset_attribute_sources AS s
		       (tenant_id, asset_id, attribute, source_kind, source_name, value, observed_at, ingested_at, confidence, source_run)
		SELECT $1::uuid, o.asset_id, o.attribute, o.kind, o.name, o.value, o.observed_at, $9, o.confidence, o.run
		  FROM unnest($2::uuid[], $3::text[], $4::text[], $5::text[], $6::text[], $7::timestamptz[], $8::smallint[], $10::text[])
		       AS o(asset_id, attribute, kind, name, value, observed_at, confidence, run)
		ON CONFLICT ON CONSTRAINT pk_asset_attribute_sources DO UPDATE SET
		       value = EXCLUDED.value, observed_at = EXCLUDED.observed_at,
		       ingested_at = EXCLUDED.ingested_at, confidence = EXCLUDED.confidence,
		       source_run = EXCLUDED.source_run
		 WHERE s.observed_at < EXCLUDED.observed_at`,
		tenantID.String(), pq.Array(assetIDs), pq.Array(attrs), pq.Array(kinds), pq.Array(names),
		pq.Array(values), pq.Array(observed), pq.Array(conf), now.UTC(), pq.Array(runs))
	if err != nil {
		return nil, fmt.Errorf("record observations: %w", err)
	}
	return recorded, nil
}

func loadAttributeObservations(ctx context.Context, q interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}, tenantID shared.ID, ids []string,
) (map[shared.ID][]asset.AttributeObservation, error) {
	rows, err := q.QueryContext(ctx, `
		SELECT asset_id, attribute, source_kind, source_name, value, observed_at, ingested_at, confidence,
		       source_run, winner
		  FROM asset_attribute_sources
		 WHERE tenant_id = $1 AND asset_id = ANY($2::uuid[])`, tenantID.String(), pq.Array(ids))
	if err != nil {
		return nil, fmt.Errorf("load observations: %w", err)
	}
	defer rows.Close()
	out := map[shared.ID][]asset.AttributeObservation{}
	for rows.Next() {
		var (
			assetID, attr, kind, name, value, run string
			observed, ingested                    time.Time
			confidence                            int
			winner                                bool
		)
		if err := rows.Scan(&assetID, &attr, &kind, &name, &value, &observed, &ingested, &confidence, &run, &winner); err != nil {
			return nil, fmt.Errorf("load observations: %w", err)
		}
		id, err := shared.IDFromString(assetID)
		if err != nil {
			return nil, fmt.Errorf("load observations: %w", err)
		}
		out[id] = append(out[id], asset.AttributeObservation{
			AssetID: id, Attribute: asset.TrackedAttribute(attr), Kind: asset.SourceKind(kind), Name: name,
			Value: value, ObservedAt: observed, IngestedAt: ingested, Confidence: confidence,
			SourceRun: run, Winner: winner,
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
