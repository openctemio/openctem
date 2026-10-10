package postgres

// Per-source elements of set-valued asset attributes (RFC-069 §13,
// docs/architecture/asset-attribute-reconciliation.md): IP addresses and
// technologies (resolved into assets.properties) and open ports (resolved
// into the status of the address's open_port assets).

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

var _ asset.SetElementRepository = (*AssetAttributeSourceRepository)(nil)

// portSetReason is the history reason of a port closed or reopened by set
// reconciliation.
const (
	portSetClosedReason = "port closed: the port scan that had found it open no longer sees it"
	portSetOpenReason   = "port open again: reported by a source"
)

// setAsset is one locked asset and what it shows for each set attribute.
type setAsset struct {
	name  string
	shown map[asset.SetAttribute][]string
	// ports maps an open-port element ("443/tcp") to its open_port asset
	// and whether that asset is active.
	ports map[string]portAsset
}

type portAsset struct {
	id     string
	active bool
}

// setKey identifies one source's contribution to one set of one asset.
type setKey struct {
	asset shared.ID
	attr  asset.SetAttribute
	kind  asset.SourceKind
	name  string
}

// ApplySets records set observations and applies the resolved sets, in one
// transaction with the touched asset rows locked in id order (the same lock
// Apply takes, so the two never deadlock).
func (r *AssetAttributeSourceRepository) ApplySets(ctx context.Context, tenantID shared.ID, in asset.SetApply) (asset.SetApplyResult, error) {
	result := asset.SetApplyResult{Verdicts: map[asset.ObservationVerdict]int{}}
	st := setApplyState{tenantID: tenantID, in: in, now: in.Now, result: &result}
	if st.now.IsZero() {
		st.now = time.Now()
	}
	st.obs = mergeSetObservations(in.Observations, st.now)
	touched := map[asset.SetRef]bool{}
	for _, o := range st.obs {
		touched[asset.SetRef{AssetID: o.AssetID, Attribute: o.Attribute}] = true
	}
	for _, ref := range in.Resolve {
		if ref.Attribute.IsValid() {
			touched[ref] = true
		}
	}
	if len(touched) == 0 {
		return result, nil
	}
	ids := setRefAssetIDs(touched)

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return result, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if st.assets, err = lockSetAssets(ctx, tx, tenantID, ids); err != nil {
		return result, err
	}
	if st.rows, err = loadSetElements(ctx, tx, tenantID, ids); err != nil {
		return result, err
	}
	writes := st.plan()
	if err := upsertSetElements(ctx, tx, tenantID, writes, st.now); err != nil {
		return result, err
	}
	st.rows = mergeSetWrites(st.rows, writes)

	refs := make([]asset.SetRef, 0, len(touched))
	for ref := range touched {
		if _, ok := st.assets[ref.AssetID]; ok {
			refs = append(refs, ref)
		}
	}
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].AssetID != refs[j].AssetID {
			return refs[i].AssetID.String() < refs[j].AssetID.String()
		}
		return refs[i].Attribute < refs[j].Attribute
	})
	for _, ref := range refs {
		if err := st.resolve(ctx, tx, ref); err != nil {
			return result, err
		}
	}
	if err := tx.Commit(); err != nil {
		return result, fmt.Errorf("commit: %w", err)
	}
	return result, nil
}

// setApplyState is one ApplySets' view of the touched assets.
type setApplyState struct {
	tenantID shared.ID
	in       asset.SetApply
	now      time.Time
	result   *asset.SetApplyResult
	obs      []asset.SetObservation
	assets   map[shared.ID]*setAsset
	rows     map[shared.ID][]asset.SetElement
	// byRef is the observation of each observed set; dropped are the shown
	// elements no source recorded that a trusted observation covered and
	// left out.
	byRef   map[asset.SetRef]asset.SetObservation
	dropped map[asset.SetRef]map[string]bool
}

// plan records each observation against its source's records and returns
// the element rows to write.
func (st *setApplyState) plan() []asset.SetElement {
	st.byRef = map[asset.SetRef]asset.SetObservation{}
	st.dropped = map[asset.SetRef]map[string]bool{}
	var writes []asset.SetElement
	for _, o := range st.obs {
		a, ok := st.assets[o.AssetID]
		if !ok {
			continue // not this tenant's asset, or deleted
		}
		ref := asset.SetRef{AssetID: o.AssetID, Attribute: o.Attribute}
		if _, seen := st.byRef[ref]; !seen {
			st.byRef[ref] = o
		}
		var mine []asset.SetElement
		attributed := map[string]bool{}
		for _, e := range st.rows[o.AssetID] {
			if e.Attribute != o.Attribute {
				continue
			}
			attributed[e.Element] = true
			if e.Kind == o.Kind && e.Name == o.Name {
				mine = append(mine, e)
			}
		}
		writes = append(writes, asset.PlanSetObservation(mine, o, st.result.Verdicts)...)
		if st.in.Policy.SetSourceTrusted(o.Attribute, o.Kind, o.Name) {
			st.dropUnattributed(ref, o, priorOf(o, a), attributed)
		}
	}
	return writes
}

// dropUnattributed marks the shown elements no source recorded that the
// trusted observation o names in its coverage and leaves out.
func (st *setApplyState) dropUnattributed(ref asset.SetRef, o asset.SetObservation, prior []string, attributed map[string]bool) {
	reported := make(map[string]bool, len(o.Elements))
	for _, e := range o.Elements {
		reported[e] = true
	}
	for _, e := range prior {
		if attributed[e] || reported[e] || !o.Coverage.CoversUnattributed(o.Attribute, e) {
			continue
		}
		if st.dropped[ref] == nil {
			st.dropped[ref] = map[string]bool{}
		}
		st.dropped[ref][e] = true
	}
}

// resolve resolves one set, writes it and records the timeline event.
func (st *setApplyState) resolve(ctx context.Context, tx *sql.Tx, ref asset.SetRef) error {
	a := st.assets[ref.AssetID]
	rows := st.rows[ref.AssetID]
	o, observed := st.byRef[ref]
	prev := a.shown[ref.Attribute]
	if observed {
		prev = priorOf(o, a)
	}
	res := asset.ResolveSet(ref.Attribute, rows, a.shown[ref.Attribute], st.dropped[ref], st.in.Policy, st.now)
	added, removed := asset.DiffSets(prev, res.Elements)
	if err := writeResolvedSet(ctx, tx, st.tenantID, ref, a, res.Elements, st.now); err != nil {
		return err
	}
	if len(added) == 0 && len(removed) == 0 {
		return nil
	}
	ch := asset.SetChange{AssetID: ref.AssetID, Attribute: ref.Attribute, Added: added, Removed: removed}
	at := st.now
	if observed {
		ch.SourceKind, ch.SourceName, ch.SourceRun = o.Kind, o.Name, o.SourceRun
		ch.Reason = asset.ChangeReasonNewerObservation
		at = o.ObservedAt
	} else {
		ch.Reason = setChangeReason(st.in, rows, ref.Attribute, removed)
	}
	st.result.Changes = append(st.result.Changes, ch)
	ev := asset.ChangeEvent{
		ID: shared.NewID(), TenantID: st.tenantID, AssetID: ref.AssetID, At: at, Attribute: string(ref.Attribute),
		Added: capElements(added), Removed: capElements(removed),
		SourceKind: ch.SourceKind, SourceName: ch.SourceName, SourceRun: ch.SourceRun,
		Reason: ch.Reason, FlapCount: 1, CreatedAt: st.now,
	}
	if ev.SourceKind == "" {
		ev.SourceKind = asset.SourceKindScan
		if k := decidingKind(rows, ref.Attribute, removed); k != "" {
			ev.SourceKind = k
		}
	}
	if err := recordChangeEvent(ctx, tx, ev, st.now); err != nil {
		return err
	}
	st.result.Events++
	return nil
}

// setRefAssetIDs are the distinct asset ids of refs, sorted.
func setRefAssetIDs(refs map[asset.SetRef]bool) []string {
	seen := map[string]bool{}
	ids := make([]string, 0, len(refs))
	for ref := range refs {
		if id := ref.AssetID.String(); !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids
}

// priorOf is the set the asset showed before the observation's report.
func priorOf(o asset.SetObservation, a *setAsset) []string {
	if len(o.Created) == 0 {
		return a.shown[o.Attribute]
	}
	created := map[string]bool{}
	for _, e := range o.Created {
		created[e] = true
	}
	out := make([]string, 0, len(a.shown[o.Attribute]))
	for _, e := range a.shown[o.Attribute] {
		if !created[e] {
			out = append(out, e)
		}
	}
	return out
}

// mergeSetObservations normalises the observations and folds those of the
// same source on the same set (one report may name an asset twice).
func mergeSetObservations(in []asset.SetObservation, now time.Time) []asset.SetObservation {
	idx := map[setKey]int{}
	out := make([]asset.SetObservation, 0, len(in))
	for _, o := range in {
		if !o.Attribute.IsValid() || !o.Kind.IsValid() || o.AssetID.IsZero() {
			continue
		}
		o.Name = clipStr(o.Name, asset.MaxSourceNameLength)
		o.SourceRun = clipStr(o.SourceRun, 100)
		o.Coverage.Key = clipStr(o.Coverage.Key, asset.MaxSetCoverageKey)
		if o.ObservedAt.IsZero() || o.ObservedAt.After(now) {
			o.ObservedAt = now
		}
		elems := make([]string, 0, len(o.Elements))
		for _, e := range o.Elements {
			if v, err := asset.NormalizeSetElement(o.Attribute, e); err == nil {
				elems = append(elems, v)
			}
		}
		o.Elements = elems
		k := setKey{o.AssetID, o.Attribute, o.Kind, o.Name}
		if i, ok := idx[k]; ok {
			out[i].Elements = append(out[i].Elements, o.Elements...)
			out[i].Created = append(out[i].Created, o.Created...)
			if o.ObservedAt.After(out[i].ObservedAt) {
				out[i].ObservedAt = o.ObservedAt
			}
			continue
		}
		idx[k] = len(out)
		out = append(out, o)
	}
	for i := range out {
		out[i].Elements = uniqueStrings(out[i].Elements)
		if len(out[i].Elements) > asset.MaxSetElements {
			// A truncated report is not the whole set: it removes nothing.
			out[i].Elements = out[i].Elements[:asset.MaxSetElements]
			out[i].Coverage = asset.SetCoverage{Mode: asset.CoverageSightings}
		}
	}
	return out
}

// setChangeReason is why a re-resolution (no observation) changed a set:
// a source no longer trusted is a policy change, otherwise the TTL.
func setChangeReason(in asset.SetApply, rows []asset.SetElement, attr asset.SetAttribute, removed []string) asset.ChangeReason {
	gone := map[string]bool{}
	for _, e := range removed {
		gone[e] = true
	}
	for _, r := range rows {
		if r.Attribute == attr && gone[r.Element] && r.Live() && !in.Policy.SetSourceTrusted(attr, r.Kind, r.Name) {
			return asset.ChangeReasonPolicyChange
		}
	}
	if in.Reason.IsValid() {
		return in.Reason
	}
	return asset.ChangeReasonTTLExpiry
}

// decidingKind is the kind of the source whose record of a removed element
// was seen last (for a re-resolution's event).
func decidingKind(rows []asset.SetElement, attr asset.SetAttribute, removed []string) asset.SourceKind {
	gone := map[string]bool{}
	for _, e := range removed {
		gone[e] = true
	}
	var best *asset.SetElement
	for i := range rows {
		r := &rows[i]
		if r.Attribute == attr && gone[r.Element] && (best == nil || r.LastSeen.After(best.LastSeen)) {
			best = r
		}
	}
	if best == nil {
		return ""
	}
	return best.Kind
}

// maxEventElements bounds the elements one timeline event lists (the
// table's check allows 200).
const maxEventElements = 200

func capElements(v []string) []string {
	if len(v) > maxEventElements {
		return v[:maxEventElements]
	}
	return v
}

// lockSetAssets locks the tenant's assets among ids and reads what they
// show for each set attribute. Ids of other tenants or deleted assets are
// absent.
func lockSetAssets(ctx context.Context, tx *sql.Tx, tenantID shared.ID, ids []string) (map[shared.ID]*setAsset, error) {
	out, byName, err := lockSetAssetRows(ctx, tx, tenantID, ids)
	if err != nil || len(byName) == 0 {
		return out, err
	}
	if err := loadOpenPortAssets(ctx, tx, tenantID, byName); err != nil {
		return nil, err
	}
	for _, a := range out {
		var open []string
		for e, p := range a.ports {
			if p.active {
				open = append(open, e)
			}
		}
		sort.Strings(open)
		a.shown[asset.SetAttrOpenPorts] = open
	}
	return out, nil
}

func lockSetAssetRows(ctx context.Context, tx *sql.Tx, tenantID shared.ID, ids []string) (map[shared.ID]*setAsset, map[string]*setAsset, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT id, name, COALESCE(properties -> 'ip_addresses', 'null'::jsonb), COALESCE(properties -> 'technologies', 'null'::jsonb)
		  FROM assets
		 WHERE tenant_id = $1 AND id = ANY($2::uuid[]) AND deleted_at IS NULL
		 ORDER BY id
		 FOR UPDATE`, tenantID.String(), pq.Array(ids))
	if err != nil {
		return nil, nil, fmt.Errorf("lock assets: %w", err)
	}
	defer rows.Close()
	out := map[shared.ID]*setAsset{}
	byName := map[string]*setAsset{}
	for rows.Next() {
		var id, name string
		var ips, techs []byte
		if err := rows.Scan(&id, &name, &ips, &techs); err != nil {
			return nil, nil, fmt.Errorf("lock assets: %w", err)
		}
		aid, err := shared.IDFromString(id)
		if err != nil {
			return nil, nil, fmt.Errorf("lock assets: %w", err)
		}
		a := &setAsset{name: name, ports: map[string]portAsset{}, shown: map[asset.SetAttribute][]string{
			asset.SetAttrIPAddresses:  normalizedJSONSet(asset.SetAttrIPAddresses, ips),
			asset.SetAttrTechnologies: normalizedJSONSet(asset.SetAttrTechnologies, techs),
		}}
		out[aid] = a
		byName[name] = a
	}
	return out, byName, rows.Err()
}

// loadOpenPortAssets reads the open_port assets of the addresses among the
// locked assets (by name).
func loadOpenPortAssets(ctx context.Context, tx *sql.Tx, tenantID shared.ID, byName map[string]*setAsset) error {
	names := make([]string, 0, len(byName))
	for n := range byName {
		names = append(names, n)
	}
	rows, err := tx.QueryContext(ctx, `
		SELECT id, name, properties->>'host', status
		  FROM assets
		 WHERE tenant_id = $1 AND deleted_at IS NULL
		   AND asset_type = 'service' AND sub_type = 'open_port'
		   AND status IN ('active', 'inactive')
		   AND properties->>'host' = ANY($2)`, tenantID.String(), pq.Array(names))
	if err != nil {
		return fmt.Errorf("load open ports: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id, name, host, status string
		if err := rows.Scan(&id, &name, &host, &status); err != nil {
			return fmt.Errorf("load open ports: %w", err)
		}
		a := byName[host]
		e, ok := portElementOf(name)
		if a == nil || !ok {
			continue
		}
		if prev, dup := a.ports[e]; dup && prev.active {
			continue
		}
		a.ports[e] = portAsset{id: id, active: status == portStatusActive}
	}
	return rows.Err()
}

// portStatusActive is an open_port asset that is open.
const portStatusActive = "active"

// portElementOf reads the port element ("443/tcp") of an open_port asset
// name ("host:port:proto").
func portElementOf(name string) (string, bool) {
	i := strings.LastIndex(name, ":")
	if i <= 0 {
		return "", false
	}
	proto := name[i+1:]
	rest := name[:i]
	j := strings.LastIndex(rest, ":")
	if j < 0 {
		return "", false
	}
	port, err := strconv.Atoi(rest[j+1:])
	if err != nil {
		return "", false
	}
	e, err := asset.NormalizeSetElement(asset.SetAttrOpenPorts, strconv.Itoa(port)+"/"+proto)
	return e, err == nil
}

// normalizedJSONSet reads a JSON array property as normalised elements.
func normalizedJSONSet(attr asset.SetAttribute, raw []byte) []string {
	var list []any
	if len(raw) == 0 || json.Unmarshal(raw, &list) != nil {
		return nil
	}
	out := make([]string, 0, len(list))
	for _, v := range list {
		s, ok := v.(string)
		if !ok {
			continue
		}
		if e, err := asset.NormalizeSetElement(attr, s); err == nil {
			out = append(out, e)
		}
	}
	return uniqueStrings(out)
}

// writeResolvedSet makes the asset show elements: the property for IP
// addresses and technologies (unchanged when equal), the status of the
// open_port assets for open ports.
func writeResolvedSet(ctx context.Context, tx *sql.Tx, tenantID shared.ID, ref asset.SetRef, a *setAsset, elements []string, now time.Time) error {
	switch ref.Attribute {
	case asset.SetAttrIPAddresses, asset.SetAttrTechnologies:
		if equalStrings(a.shown[ref.Attribute], elements) {
			return nil
		}
		key := string(ref.Attribute)
		if _, err := tx.ExecContext(ctx, `
			UPDATE assets
			   SET properties = CASE WHEN cardinality($4::text[]) = 0 THEN COALESCE(properties, '{}'::jsonb) - $3
			                         ELSE jsonb_set(COALESCE(properties, '{}'::jsonb), ARRAY[$3], to_jsonb($4::text[])) END,
			       updated_at = now()
			 WHERE tenant_id = $1 AND id = $2`,
			tenantID.String(), ref.AssetID.String(), key, pq.Array(elements)); err != nil {
			return fmt.Errorf("write %s: %w", key, err)
		}
		a.shown[ref.Attribute] = elements
	case asset.SetAttrOpenPorts:
		want := map[string]bool{}
		for _, e := range elements {
			want[e] = true
		}
		var closeIDs, openIDs []string
		for e, p := range a.ports {
			switch {
			case p.active && !want[e]:
				closeIDs = append(closeIDs, p.id)
			case !p.active && want[e]:
				openIDs = append(openIDs, p.id)
			}
		}
		sort.Strings(closeIDs)
		sort.Strings(openIDs)
		if _, err := closePortsTx(ctx, tx, tenantID, closeIDs, now.Add(time.Second), portSetClosedReason); err != nil {
			return err
		}
		if _, err := reopenPortsTx(ctx, tx, tenantID, openIDs, portSetOpenReason); err != nil {
			return err
		}
	}
	return nil
}

// upsertSetElements writes the planned element records.
func upsertSetElements(ctx context.Context, tx *sql.Tx, tenantID shared.ID, writes []asset.SetElement, now time.Time) error {
	if len(writes) == 0 {
		return nil
	}
	n := len(writes)
	var (
		assetIDs = make([]string, 0, n)
		attrs    = make([]string, 0, n)
		kinds    = make([]string, 0, n)
		names    = make([]string, 0, n)
		elems    = make([]string, 0, n)
		keys     = make([]string, 0, n)
		first    = make([]time.Time, 0, n)
		last     = make([]time.Time, 0, n)
		removed  = make([]sql.NullTime, 0, n)
		runs     = make([]string, 0, n)
	)
	for _, w := range writes {
		assetIDs = append(assetIDs, w.AssetID.String())
		attrs = append(attrs, string(w.Attribute))
		kinds = append(kinds, string(w.Kind))
		names = append(names, w.Name)
		elems = append(elems, w.Element)
		keys = append(keys, w.CoverageKey)
		first = append(first, w.FirstSeen.UTC())
		last = append(last, w.LastSeen.UTC())
		rm := sql.NullTime{}
		if w.RemovedAt != nil {
			rm = sql.NullTime{Time: w.RemovedAt.UTC(), Valid: true}
		}
		removed = append(removed, rm)
		runs = append(runs, w.SourceRun)
	}
	removedArr := make([]any, len(removed))
	for i, rm := range removed {
		if rm.Valid {
			removedArr[i] = rm.Time.Format(time.RFC3339Nano)
		}
	}
	_, err := tx.ExecContext(ctx, `
		INSERT INTO asset_attribute_set_elements AS s
		       (tenant_id, asset_id, attribute, source_kind, source_name, element, coverage_key,
		        first_seen, last_seen, removed_at, source_run, updated_at)
		SELECT $1::uuid, w.asset_id, w.attribute, w.kind, w.name, w.element, w.coverage_key,
		       w.first_seen, w.last_seen, w.removed_at, w.run, $12
		  FROM unnest($2::uuid[], $3::text[], $4::text[], $5::text[], $6::text[], $7::text[],
		              $8::timestamptz[], $9::timestamptz[], $10::timestamptz[], $11::text[])
		       AS w(asset_id, attribute, kind, name, element, coverage_key, first_seen, last_seen, removed_at, run)
		ON CONFLICT ON CONSTRAINT pk_asset_attribute_set_elements DO UPDATE SET
		       coverage_key = EXCLUDED.coverage_key, last_seen = EXCLUDED.last_seen,
		       removed_at = EXCLUDED.removed_at, source_run = EXCLUDED.source_run, updated_at = EXCLUDED.updated_at`,
		tenantID.String(), pq.Array(assetIDs), pq.Array(attrs), pq.Array(kinds), pq.Array(names), pq.Array(elems),
		pq.Array(keys), pq.Array(first), pq.Array(last), pq.GenericArray{A: removedArr}, pq.Array(runs), now.UTC())
	if err != nil {
		return fmt.Errorf("record set elements: %w", err)
	}
	return nil
}

// mergeSetWrites applies the written records to the loaded ones.
func mergeSetWrites(rows map[shared.ID][]asset.SetElement, writes []asset.SetElement) map[shared.ID][]asset.SetElement {
	type k struct {
		attr       asset.SetAttribute
		kind       asset.SourceKind
		name, elem string
	}
	for _, w := range writes {
		list := rows[w.AssetID]
		found := false
		for i := range list {
			if (k{list[i].Attribute, list[i].Kind, list[i].Name, list[i].Element}) == (k{w.Attribute, w.Kind, w.Name, w.Element}) {
				list[i] = w
				found = true
				break
			}
		}
		if !found {
			list = append(list, w)
		}
		rows[w.AssetID] = list
	}
	return rows
}

func loadSetElements(ctx context.Context, q interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}, tenantID shared.ID, ids []string,
) (map[shared.ID][]asset.SetElement, error) {
	rows, err := q.QueryContext(ctx, `
		SELECT asset_id, attribute, source_kind, source_name, element, coverage_key,
		       first_seen, last_seen, removed_at, source_run
		  FROM asset_attribute_set_elements
		 WHERE tenant_id = $1 AND asset_id = ANY($2::uuid[])
		 ORDER BY asset_id, attribute, element, source_kind, source_name`, tenantID.String(), pq.Array(ids))
	if err != nil {
		return nil, fmt.Errorf("load set elements: %w", err)
	}
	defer rows.Close()
	out := map[shared.ID][]asset.SetElement{}
	for rows.Next() {
		var (
			assetID, attr, kind, name, elem, key, run string
			first, last                               time.Time
			removed                                   sql.NullTime
		)
		if err := rows.Scan(&assetID, &attr, &kind, &name, &elem, &key, &first, &last, &removed, &run); err != nil {
			return nil, fmt.Errorf("load set elements: %w", err)
		}
		id, err := shared.IDFromString(assetID)
		if err != nil {
			return nil, fmt.Errorf("load set elements: %w", err)
		}
		e := asset.SetElement{AssetID: id, Attribute: asset.SetAttribute(attr), Kind: asset.SourceKind(kind), Name: name,
			Element: elem, CoverageKey: key, FirstSeen: first, LastSeen: last, SourceRun: run}
		if removed.Valid {
			t := removed.Time
			e.RemovedAt = &t
		}
		out[id] = append(out[id], e)
	}
	return out, rows.Err()
}

// ListSetElements returns every element record of one of the tenant's
// assets.
func (r *AssetAttributeSourceRepository) ListSetElements(ctx context.Context, tenantID, assetID shared.ID) ([]asset.SetElement, error) {
	m, err := loadSetElements(ctx, r.db, tenantID, []string{assetID.String()})
	if err != nil {
		return nil, err
	}
	return m[assetID], nil
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x := append([]string{}, a...)
	y := append([]string{}, b...)
	sort.Strings(x)
	sort.Strings(y)
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}
