package ingest

import (
	"context"
	"encoding/json"
	"math"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Asset identity model (docs/architecture/asset-identity-resolution.md).
//
// For each incoming asset, in order:
//  1. Strong identifiers (host ID, cloud ID, BIOS UUID, serial, MAC, SCM
//     repository ID), strongest first. A candidate is vetoed when it holds a
//     different value of a single-valued kind ranked above the one that
//     matched: two host IDs mean two hosts, whatever the MAC says. Other
//     assets that lower-ranked identifiers point at become a duplicate review.
//  2. The exact name (assets.name), as before.
//  3. A hostname or FQDN the asset was seen with inside the trust window, when
//     exactly one asset has it.
//  4. An IP address seen on exactly one asset inside the trust window.
//  5. Otherwise a new asset.
//
// Nothing here merges two existing assets: conflicts go to the dedup review
// queue for an operator.

// IdentityStore is the asset_identifiers table as ingest needs it.
type IdentityStore interface {
	FindByValues(ctx context.Context, tenantID shared.ID, keys []asset.IdentifierKey) ([]asset.Identifier, error)
	ListByAssets(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) ([]asset.Identifier, error)
	GetAssetsByIDs(ctx context.Context, tenantID shared.ID, ids []shared.ID) (map[string]*asset.Asset, error)
	// Upsert records identifiers; strong ones another asset holds are
	// returned (AssetID = holder) instead of being moved.
	Upsert(ctx context.Context, tenantID shared.ID, ids []asset.Identifier) ([]asset.Identifier, error)
}

// IdentityReviewer raises duplicate reviews for identity conflicts.
type IdentityReviewer interface {
	EnqueueIdentityReview(ctx context.Context, tenantID string, rev asset.DuplicateReview) (bool, error)
}

// SetIdentityStore enables identifier-based matching. Without it ingest
// matches by name and IP only, as before.
func (p *AssetProcessor) SetIdentityStore(store IdentityStore, reviewer IdentityReviewer) {
	p.identityStore = store
	p.identityReviewer = reviewer
}

// hardwareTypes can carry host, BIOS, serial and MAC identifiers.
func hardwareType(t asset.AssetType) bool {
	switch t {
	case asset.AssetTypeHost, asset.AssetTypeIPAddress, asset.AssetTypeNetwork:
		return true
	}
	return false
}

// hostFamily are the types one host can be recorded as.
func hostFamily(t asset.AssetType) bool {
	return t == asset.AssetTypeHost || t == asset.AssetTypeIPAddress
}

// sameFamily reports whether an incoming asset of type in may be matched to
// an existing asset of type existing.
func sameFamily(existing, in asset.AssetType) bool {
	if existing == in {
		return true
	}
	return hostFamily(existing) && hostFamily(in)
}

// identityApplies reports whether identifiers are used for this type.
// Domains stay keyed by name.
func identityApplies(t asset.AssetType) bool {
	switch t {
	case asset.AssetTypeDomain, asset.AssetTypeSubdomain, asset.AssetTypeCertificate:
		return false
	}
	return true
}

// identifierProps maps property names scanners use to identifier kinds.
// hw marks hardware kinds, read only for host-like types.
var identifierProps = []struct {
	kind asset.IdentifierKind
	keys []string
	hw   bool
}{
	{asset.IdentifierCloudID, []string{"cloud_resource_id", "instance_id", "cloud_instance_id", "vm_id", "arn"}, false},
	{asset.IdentifierHostID, []string{"host_id", "machine_id", "sensor_host_id", "machine_guid"}, true},
	{asset.IdentifierBIOSUUID, []string{"bios_uuid", "system_uuid", "smbios_uuid"}, true},
	{asset.IdentifierSerial, []string{"serial_number", "hardware_serial"}, true},
	{asset.IdentifierMAC, []string{"mac_address", "mac_addresses", "mac"}, true},
}

var (
	propRepoID   = []string{"scm_repo_id", "repo_id", "repository_id", "project_id"}
	propHostname = []string{"hostname", "fqdn", "netbios_name"}
)

// identifierSet collects normalized identifiers without duplicates.
type identifierSet struct {
	name string
	out  []asset.Identifier
	seen map[asset.IdentifierKey]bool
	// typed are the kinds the typed CTIS fields (the identifiers block,
	// technical.cloud) carried; free-form properties are read for a kind
	// only when no typed field carried it.
	typed map[asset.IdentifierKind]bool
}

// addTyped adds a value from a typed CTIS field and marks its kind typed.
func (s *identifierSet) addTyped(k asset.IdentifierKind, raw string) {
	before := len(s.out)
	s.add(k, raw)
	if len(s.out) > before || s.hasKind(k) {
		s.typed[k] = true
	}
}

func (s *identifierSet) hasKind(k asset.IdentifierKind) bool {
	for _, id := range s.out {
		if id.Kind == k {
			return true
		}
	}
	return false
}

func (s *identifierSet) add(k asset.IdentifierKind, raw string) {
	v, ok := asset.NormalizeIdentifier(k, raw)
	if !ok {
		return
	}
	if k == asset.IdentifierSCMRepoID {
		v = asset.SCMRepoIdentifier(s.name, v)
	}
	key := asset.IdentifierKey{Kind: k, Value: v}
	if v == "" || s.seen[key] {
		return
	}
	s.seen[key] = true
	s.out = append(s.out, asset.Identifier{Kind: k, Value: v})
}

// addProp adds every value of a property; MAC lists may be one string
// separated by newlines, spaces or commas (the Nessus mac-address tag).
func (s *identifierSet) addProp(k asset.IdentifierKind, v any) {
	for _, item := range propStrings(v) {
		if k != asset.IdentifierMAC {
			s.add(k, item)
			continue
		}
		for _, m := range strings.FieldsFunc(item, func(r rune) bool {
			return r == ',' || r == ';' || r == ' ' || r == '\n' || r == '\t' || r == '\r'
		}) {
			s.add(k, m)
		}
	}
}

// addName adds a hostname or FQDN; addresses are not names.
func (s *identifierSet) addName(n string) {
	n = strings.TrimSpace(n)
	if n == "" || net.ParseIP(n) != nil {
		return
	}
	if strings.Contains(strings.TrimSuffix(n, "."), ".") {
		s.add(asset.IdentifierFQDN, n)
	} else {
		s.add(asset.IdentifierHostname, n)
	}
}

// addBlock adds the CTIS identifiers block.
func (s *identifierSet) addBlock(ids *ctis.AssetIdentifiers, coreType asset.AssetType) {
	if ids == nil {
		return
	}
	if hardwareType(coreType) {
		s.addTyped(asset.IdentifierHostID, ids.MachineID)
		s.addTyped(asset.IdentifierBIOSUUID, ids.BIOSUUID)
		s.addTyped(asset.IdentifierSerial, ids.SerialNumber)
		for _, m := range ids.MACAddresses {
			s.addTyped(asset.IdentifierMAC, m)
		}
	}
	s.addTyped(asset.IdentifierCloudID, ids.CloudResourceID)
	if coreType == asset.AssetTypeRepository {
		s.addTyped(asset.IdentifierSCMRepoID, ids.SCMRepoID)
	}
}

// identifiersFor extracts the identifiers an incoming CTIS asset carries:
// the CTIS identifiers block and the cloud block first, then, only for a
// strong kind neither of them carried, the same value under its usual
// property name (scanners that predate the block, such as the Nessus
// parser's mac_address), and, for hosts, names and IP addresses. A typed
// field wins over free-form properties: a report cannot add a second,
// untyped merge identity of a kind its typed block already states.
// AssetID is left unset.
func identifiersFor(ca *ctis.Asset, coreType asset.AssetType, name string) []asset.Identifier {
	if !identityApplies(coreType) {
		return nil
	}
	s := &identifierSet{name: name, seen: map[asset.IdentifierKey]bool{}, typed: map[asset.IdentifierKind]bool{}}
	props := map[string]any(ca.Properties)
	hw := hardwareType(coreType)

	s.addBlock(ca.Identifiers, coreType)
	if ca.Technical != nil && ca.Technical.Cloud != nil {
		if ca.Technical.Cloud.ARN != "" {
			s.addTyped(asset.IdentifierCloudID, ca.Technical.Cloud.ARN)
		} else {
			s.addTyped(asset.IdentifierCloudID, ca.Technical.Cloud.ResourceID)
		}
	}
	for _, p := range identifierProps {
		if (p.hw && !hw) || s.typed[p.kind] {
			continue
		}
		for _, k := range p.keys {
			s.addProp(p.kind, props[k])
		}
	}
	if coreType == asset.AssetTypeRepository && !s.typed[asset.IdentifierSCMRepoID] {
		for _, k := range propRepoID {
			s.addProp(asset.IdentifierSCMRepoID, props[k])
		}
	}
	if !hw {
		return s.out
	}

	s.addName(name)
	for _, k := range propHostname {
		for _, v := range propStrings(props[k]) {
			s.addName(v)
		}
	}
	if ca.Technical != nil && ca.Technical.IPAddress != nil {
		s.addName(ca.Technical.IPAddress.Hostname)
	}

	// Addresses, in every shape scanners send them.
	for _, ip := range ExtractAllIPs(props, name) {
		s.add(asset.IdentifierIP, ip)
	}
	if v := strings.TrimSpace(ca.Value); net.ParseIP(v) != nil {
		s.add(asset.IdentifierIP, v)
	}
	return s.out
}

// propStrings reads a property that is a string or a list of strings.
func propStrings(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, item := range t {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case float64:
		// A numeric repository ID decoded from JSON.
		if t == math.Trunc(t) && math.Abs(t) < 1e15 {
			return []string{strconv.FormatInt(int64(t), 10)}
		}
	case int:
		return []string{strconv.Itoa(t)}
	case int64:
		return []string{strconv.FormatInt(t, 10)}
	case json.Number:
		return []string{t.String()}
	}
	return nil
}

// batchIdentity holds one ingest batch's view of asset identity: the stored
// identifiers that the batch's identifiers point at, the assets they belong
// to, and what the batch itself has claimed so far.
type batchIdentity struct {
	tenantID shared.ID
	window   time.Duration

	incoming [][]asset.Identifier                       // per report asset index
	byKey    map[asset.IdentifierKey][]asset.Identifier // stored rows for incoming keys
	byAsset  map[string][]asset.Identifier              // identifiers held per asset id
	assets   map[string]*asset.Asset                    // assets the stored rows point at
	claimed  map[asset.IdentifierKey]*asset.Asset       // strong keys claimed in this batch

	writes  []pendingIdentifier
	reviews []pendingReview
}

type pendingIdentifier struct {
	a  *asset.Asset
	id asset.Identifier
}

type pendingReview struct {
	keep, other *asset.Asset
	reason      string
	evidence    map[string]any
	name        string
	assetType   asset.AssetType
}

type pendingRename struct {
	a        *asset.Asset
	old, new string
	via      string
}

// prepareIdentity loads what the batch's identifiers point at, in a fixed
// number of queries. It returns nil (identifier matching off for this batch)
// when no store is wired or a lookup fails; ingest then matches by name and
// IP as before.
func (p *AssetProcessor) prepareIdentity(ctx context.Context, tenantID shared.ID, report *ctis.Report, cfg CorrelationConfig) *batchIdentity {
	if p.identityStore == nil {
		return nil
	}
	days := cfg.StaleAssetDays
	if days <= 0 {
		days = DefaultIPTrustWindowDays
	}
	b := &batchIdentity{
		tenantID: tenantID,
		window:   time.Duration(days) * 24 * time.Hour,
		incoming: make([][]asset.Identifier, len(report.Assets)),
		byKey:    map[asset.IdentifierKey][]asset.Identifier{},
		byAsset:  map[string][]asset.Identifier{},
		assets:   map[string]*asset.Asset{},
		claimed:  map[asset.IdentifierKey]*asset.Asset{},
	}
	keySet := map[asset.IdentifierKey]bool{}
	for i := range report.Assets {
		ca := &report.Assets[i]
		name := getAssetName(ca)
		if name == "" {
			continue
		}
		rt := resolveCTISAssetType(ca)
		normalized := asset.NormalizeName(name, rt.normType, rt.normSubType)
		b.incoming[i] = identifiersFor(ca, rt.stored.Type, normalized)
		for _, id := range b.incoming[i] {
			keySet[id.Key()] = true
		}
	}
	if len(keySet) == 0 {
		return b
	}
	keys := make([]asset.IdentifierKey, 0, len(keySet))
	for k := range keySet {
		keys = append(keys, k)
	}
	rows, err := p.identityStore.FindByValues(ctx, tenantID, keys)
	if err != nil {
		p.logger.Warn("asset identifier lookup failed, matching by name and IP only", "error", err)
		return nil
	}
	ids := map[string]shared.ID{}
	for _, r := range rows {
		b.byKey[r.Key()] = append(b.byKey[r.Key()], r)
		ids[r.AssetID.String()] = r.AssetID
	}
	if len(ids) == 0 {
		return b
	}
	idList := make([]shared.ID, 0, len(ids))
	for _, id := range ids {
		idList = append(idList, id)
	}
	held, err := p.identityStore.ListByAssets(ctx, tenantID, idList)
	if err != nil {
		p.logger.Warn("asset identifier lookup failed, matching by name and IP only", "error", err)
		return nil
	}
	for _, r := range held {
		b.byAsset[r.AssetID.String()] = append(b.byAsset[r.AssetID.String()], r)
	}
	if b.assets, err = p.identityStore.GetAssetsByIDs(ctx, tenantID, idList); err != nil {
		p.logger.Warn("asset identifier lookup failed, matching by name and IP only", "error", err)
		return nil
	}
	return b
}

// strongMatch is the asset the incoming asset's strong identifiers resolve to.
type strongMatch struct {
	a     *asset.Asset
	kind  asset.IdentifierKind
	value string
}

// resolveStrong walks the incoming strong identifiers, strongest first. It
// returns the first candidate that is not vetoed, and the other non-vetoed
// candidates as conflicts.
func (b *batchIdentity) resolveStrong(i int, coreType asset.AssetType) (match *strongMatch, conflicts []strongMatch) {
	inc := b.incoming[i]
	strong := make([]asset.Identifier, 0, len(inc))
	for _, id := range inc {
		if id.Kind.IsStrong() {
			strong = append(strong, id)
		}
	}
	sort.SliceStable(strong, func(x, y int) bool { return strong[x].Kind.Rank() < strong[y].Kind.Rank() })

	seen := map[string]bool{}
	for _, id := range strong {
		owner := b.ownerOf(id.Key())
		if owner == nil || !sameFamily(owner.Type(), coreType) || seen[owner.ID().String()] {
			continue
		}
		seen[owner.ID().String()] = true
		if b.vetoed(owner, inc, id.Kind.Rank()) {
			continue
		}
		c := strongMatch{a: owner, kind: id.Kind, value: id.Value}
		if match == nil {
			match = &c
			continue
		}
		conflicts = append(conflicts, c)
	}
	return match, conflicts
}

// ownerOf returns the asset holding a strong key: claimed in this batch,
// else stored.
func (b *batchIdentity) ownerOf(k asset.IdentifierKey) *asset.Asset {
	if a, ok := b.claimed[k]; ok {
		return a
	}
	for _, r := range b.byKey[k] {
		if a, ok := b.assets[r.AssetID.String()]; ok {
			return a
		}
	}
	return nil
}

// vetoed reports whether existing holds a different value of a single-valued
// strong kind ranked above rank (lower Rank) that the incoming asset also
// carries: then they are different assets.
func (b *batchIdentity) vetoed(existing *asset.Asset, incoming []asset.Identifier, rank int) bool {
	_, vetoed := b.vetoKind(existing, incoming, rank)
	return vetoed
}

func (b *batchIdentity) vetoKind(existing *asset.Asset, incoming []asset.Identifier, rank int) (asset.IdentifierKind, bool) {
	held := b.byAsset[existing.ID().String()]
	for _, in := range incoming {
		if !in.Kind.IsSingleValued() || in.Kind.Rank() >= rank {
			continue
		}
		var has, same bool
		for _, h := range held {
			if h.Kind != in.Kind {
				continue
			}
			has = true
			if h.Value == in.Value {
				same = true
			}
		}
		if has && !same {
			return in.Kind, true
		}
	}
	return "", false
}

// resolveAlias matches on a hostname or FQDN the asset was seen with inside
// the trust window, when exactly one asset of the family has it.
func (b *batchIdentity) resolveAlias(i int, coreType asset.AssetType, name string) *asset.Asset {
	var match *asset.Asset
	for _, id := range b.incoming[i] {
		if id.Kind != asset.IdentifierFQDN && id.Kind != asset.IdentifierHostname {
			continue
		}
		if v, ok := asset.NormalizeIdentifier(id.Kind, name); !ok || v != id.Value {
			continue // only the incoming name itself, not property hostnames
		}
		for _, r := range b.byKey[id.Key()] {
			if time.Since(r.LastSeen) > b.window {
				continue
			}
			a := b.assets[r.AssetID.String()]
			if a == nil || !sameFamily(a.Type(), coreType) || b.vetoed(a, b.incoming[i], len(asset.AllIdentifierKinds())) {
				continue
			}
			if match != nil && !match.ID().Equals(a.ID()) {
				return nil // ambiguous
			}
			match = a
		}
	}
	return match
}

// ipRecency answers when an IP was last recorded on an asset.
func (b *batchIdentity) ipRecency(i int) IPRecency {
	return func(assetID, ip string) (time.Time, bool) {
		for _, r := range b.byKey[asset.IdentifierKey{Kind: asset.IdentifierIP, Value: ip}] {
			if r.AssetID.String() == assetID {
				return r.LastSeen, true
			}
		}
		return time.Time{}, false
	}
}

// attach records that incoming asset i resolved to a, so its identifiers are
// written after the upsert. A strong identifier another asset holds is left
// with that asset (and the pair goes to review); a single-valued kind a
// already has a different value of is not added.
func (b *batchIdentity) attach(i int, a *asset.Asset, coreType asset.AssetType, name, source string) {
	if b == nil || a == nil {
		return
	}
	now := time.Now().UTC()
	aid := a.ID().String()
	for _, id := range b.incoming[i] {
		if id.Kind.IsStrong() {
			if owner := b.ownerOf(id.Key()); owner != nil && !owner.ID().Equals(a.ID()) {
				b.review(a, owner, asset.DuplicateReasonIdentifierConflict,
					map[string]any{"kind": string(id.Kind), "value": id.Value}, name, coreType)
				continue
			}
			if id.Kind.IsSingleValued() {
				if k, conflict := b.vetoKind(a, []asset.Identifier{id}, len(asset.AllIdentifierKinds())); conflict && k == id.Kind {
					continue
				}
			}
			b.claimed[id.Key()] = a
		}
		id.AssetID = a.ID()
		id.Source = source
		id.FirstSeen, id.LastSeen = now, now
		b.byAsset[aid] = append(b.byAsset[aid], id)
		b.writes = append(b.writes, pendingIdentifier{a: a, id: id})
	}
}

// review queues a duplicate review between two assets.
func (b *batchIdentity) review(x, y *asset.Asset, reason string, evidence map[string]any, name string, t asset.AssetType) {
	if b == nil || x == nil || y == nil || x.ID().Equals(y.ID()) {
		return
	}
	b.reviews = append(b.reviews, pendingReview{keep: x, other: y, reason: reason, evidence: evidence, name: name, assetType: t})
}

// recordRenames writes a `renamed` state-history row per rename once the
// assets are persisted. Best-effort.
func (p *AssetProcessor) recordRenames(ctx context.Context, tenantID shared.ID, renames []pendingRename, finalID func(*asset.Asset) shared.ID) {
	if p.stateHistory == nil || len(renames) == 0 {
		return
	}
	changes := make([]*asset.AssetStateChange, 0, len(renames))
	for _, r := range renames {
		c := asset.RecordFieldChange(tenantID, finalID(r.a), asset.StateChangeRenamed,
			"name", r.old, r.new, asset.ChangeSourceScan, nil)
		c.SetReason("matched by " + r.via)
		changes = append(changes, c)
	}
	if err := p.stateHistory.CreateBatch(ctx, changes); err != nil {
		p.logger.Warn("failed to record asset renames in state history", "count", len(changes), "error", err)
	}
}

// flushIdentity writes the batch's identifiers and reviews once the assets
// are persisted. finalID maps an asset to the id the database kept for it.
// Best-effort: failures are logged and never fail the ingest.
func (p *AssetProcessor) flushIdentity(ctx context.Context, b *batchIdentity, finalID func(*asset.Asset) shared.ID) {
	if b == nil {
		return
	}
	if len(b.writes) > 0 {
		ids := make([]asset.Identifier, 0, len(b.writes))
		owner := map[asset.IdentifierKey]*asset.Asset{}
		for _, w := range b.writes {
			w.id.AssetID = finalID(w.a)
			if w.id.AssetID.IsZero() {
				continue // the asset was refused and never stored
			}
			ids = append(ids, w.id)
			if w.id.Kind.IsStrong() {
				owner[w.id.Key()] = w.a
			}
		}
		taken, err := p.identityStore.Upsert(ctx, b.tenantID, ids)
		if err != nil {
			p.logger.Warn("failed to record asset identifiers", "tenant_id", b.tenantID.String(), "error", err)
		}
		if len(taken) > 0 {
			holders := make([]shared.ID, 0, len(taken))
			for _, t := range taken {
				holders = append(holders, t.AssetID)
			}
			loaded, err := p.identityStore.GetAssetsByIDs(ctx, b.tenantID, holders)
			if err != nil {
				p.logger.Warn("failed to load identifier holders", "error", err)
			}
			for _, t := range taken {
				mine := owner[t.Key()]
				holder := loaded[t.AssetID.String()]
				if mine == nil || holder == nil || finalID(mine).Equals(holder.ID()) {
					continue
				}
				b.review(mine, holder, asset.DuplicateReasonIdentifierConflict,
					map[string]any{"kind": string(t.Kind), "value": t.Value}, mine.Name(), mine.Type())
			}
		}
	}

	if p.identityReviewer == nil {
		return
	}
	for _, r := range b.reviews {
		keep, other := r.keep, r.other
		// Keep the asset with more history: more findings, then older.
		if other.FindingCount() > keep.FindingCount() ||
			(other.FindingCount() == keep.FindingCount() && other.CreatedAt().Before(keep.CreatedAt())) {
			keep, other = other, keep
		}
		if _, err := p.identityReviewer.EnqueueIdentityReview(ctx, b.tenantID.String(), asset.DuplicateReview{
			Reason:            r.reason,
			Evidence:          r.evidence,
			NormalizedName:    r.name,
			AssetType:         string(r.assetType),
			KeepID:            finalID(keep).String(),
			KeepName:          keep.Name(),
			KeepFindingCount:  keep.FindingCount(),
			MergeIDs:          []string{finalID(other).String()},
			MergeNames:        []string{other.Name()},
			MergeFindingCount: other.FindingCount(),
		}); err != nil {
			p.logger.Warn("failed to enqueue identity review", "keep_id", keep.ID().String(), "error", err)
		}
	}
}
