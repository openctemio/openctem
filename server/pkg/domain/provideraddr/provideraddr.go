// Package provideraddr decides what the one-time provider-address move does
// with each address asset (docs/architecture/provider-address-move.md).
//
// An address inside a range a provider publishes for infrastructure many
// organizations share (edgeaddr.SharedFrontEnd) is not the organization's
// asset: the names that resolve to it are. For each such address asset the
// move:
//
//  1. folds every name-to-address resolves_to edge into the name's address
//     history (an ip_addresses set element under source scan /
//     migrated_resolves_to, history only: removed_at = last_seen);
//  2. moves services named by a host name, and certificates that cover a
//     name, from the address to that name;
//  3. archives the address when nothing else holds it (plain), or keeps it
//     as it is when something does (services named by the address, a scope
//     entry, a person's decision, a tag, any other reference, a manual edge).
//
// The plan is computed here from what the repository read, without writing:
// a dry run and an apply run the same plan, so their counts are equal by
// construction. Nothing in this package touches findings.
package provideraddr

import (
	"encoding/json"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/openctemio/openctem/server/pkg/domain/asset"
	"github.com/openctemio/openctem/server/pkg/domain/attribution"
	"github.com/openctemio/openctem/server/pkg/domain/edgeaddr"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// JobVersion is the version of the move's rules. A run is keyed by it and by
// the provider range dataset's version: a new value of either is a new pass.
const JobVersion = 1

// The history rows the fold writes on a name.
const (
	FoldAttribute  = "ip_addresses"
	FoldSourceKind = "scan"
	FoldSourceName = "migrated_resolves_to"
)

// RelinkDescription is the description of an edge the move adds.
const RelinkDescription = "moved from a provider address"

// Reason is the attribution reason of a provider address.
const Reason = string(attribution.RuleProviderSharedFrontEnd)

// Mode is what a run does.
type Mode string

// Modes.
const (
	ModeDryRun  Mode = "dry_run"
	ModeApply   Mode = "apply"
	ModeRestore Mode = "restore"
)

// Bucket is why an address is archived or kept. One bucket per address, in
// this order of precedence.
type Bucket string

// Buckets.
const (
	BucketActiveRun        Bucket = "active_run"         // target of a queued or running scan run: skipped this pass
	BucketPerson           Bucket = "person"             // a person decided its attribution or status
	BucketEntry            Bucket = "entry"              // a scope entry covers it
	BucketReference        Bucket = "reference"          // a tag, a child asset or any non-history reference
	BucketManualEdge       Bucket = "manual_edge"        // a person drew an edge to or from it
	BucketRevived          Bucket = "revived"            // a direct result revived it after an earlier pass
	BucketAddressServices  Bucket = "address_services"   // services named by the address itself
	BucketOtherEdges       Bucket = "other_edges"        // edges the move does not move
	BucketPlainAfterRelink Bucket = "plain_after_relink" // only name services, moved to their names
	BucketPlain            Bucket = "plain"              // nothing but name-to-address links
)

// Action is what the move does with the address.
type Action string

// Actions.
const (
	ActionArchive Action = "archive"
	ActionKeep    Action = "keep"
	ActionSkip    Action = "skip"
)

// Outcomes of a journal item.
const (
	OutcomeApplied          = "applied"
	OutcomeKept             = "kept"
	OutcomeSkippedActiveRun = "skipped_active_run"
	OutcomeRestored         = "restored"
	OutcomeChanged          = "changed"
	OutcomeRevived          = "revived"
	OutcomeReclassified     = "reclassified"
)

// Edge is a full asset_relationships row, as the journal keeps it.
type Edge struct {
	ID              string     `json:"id"`
	SourceID        string     `json:"source_asset_id"`
	TargetID        string     `json:"target_asset_id"`
	Type            string     `json:"relationship_type"`
	Description     *string    `json:"description,omitempty"`
	Confidence      string     `json:"confidence"`
	DiscoveryMethod string     `json:"discovery_method"`
	ImpactWeight    int        `json:"impact_weight"`
	Tags            []string   `json:"tags"`
	LastVerified    *time.Time `json:"last_verified,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
	IsControlPlane  bool       `json:"is_control_plane"`
}

// Attribution is a stored asset_attributions row.
type Attribution struct {
	State         string     `json:"state"`
	Confidence    int        `json:"confidence"`
	Reason        string     `json:"reason"`
	DecidedBy     *string    `json:"decided_by,omitempty"`
	DecidedAt     *time.Time `json:"decided_at,omitempty"`
	FollowsHostID *string    `json:"follows_host_id,omitempty"`
}

// Human reports whether a person decided it: never overwritten.
func (a *Attribution) Human() bool {
	return a != nil && (a.DecidedBy != nil || a.DecidedAt != nil)
}

func (a *Attribution) isProvider() bool {
	return a != nil && a.State == string(attribution.StateDependency) && a.Reason == Reason && a.Confidence == 100
}

// providerAttribution is what the move records on a provider address.
func providerAttribution() *Attribution {
	return &Attribution{State: string(attribution.StateDependency), Confidence: 100, Reason: Reason}
}

// FoldKey is one history row the move folded: the name, the canonical
// address and the seen window it brought.
type FoldKey struct {
	NameID    string    `json:"asset_id"`
	Element   string    `json:"element"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// Address is an address asset of the batch.
type Address struct {
	ID           string
	Name         string
	Status       string
	ManualStatus bool // a person set its status
	Tagged       bool
	Attribution  *Attribution
}

// Asset is another asset an edge of the batch reaches.
type Asset struct {
	ID   string
	Name string
	Type string
	// Covers lists the names a certificate is for (subject CN and SANs).
	Covers []string
}

// LinkKey is an edge's identity: source, target, type.
type LinkKey struct{ Source, Target, Type string }

// HistoryKey is a name's address-history element.
type HistoryKey struct{ NameID, Element string }

// BatchInput is everything the plan of one batch reads.
type BatchInput struct {
	// Addresses are the batch's address assets inside a shared range.
	Addresses []Address
	// Classes holds each one's classification (provider, class).
	Classes map[string]edgeaddr.Result
	// Edges are every edge to or from them.
	Edges []Edge
	// Assets are the other ends of those edges.
	Assets map[string]Asset
	// NamesByHost maps a lower-case host name to the tenant's domain or
	// subdomain asset of that name.
	NamesByHost map[string]string
	// Referenced: tags, children or any non-history reference.
	Referenced map[string]bool
	// ActiveRun: targets of a queued or running scan run.
	ActiveRun map[string]bool
	// Revived: a direct result revived it after an earlier pass.
	Revived map[string]bool
	// EntryCovered: a scope entry covers it.
	EntryCovered map[string]bool
	// History: the names' address-history elements that exist (any source).
	History map[HistoryKey]bool
	// Links: name-to-service and name-to-certificate edges that exist.
	Links map[LinkKey]bool
	// Findings counts findings per asset and severity (services the batch
	// relinks or keeps).
	Findings map[string]map[string]int
}

// Simulation carries what earlier batches of the same run planned, so a dry
// run (which writes nothing) plans each batch as the apply would after the
// earlier batches committed.
type Simulation struct {
	Links    map[LinkKey]bool
	History  map[HistoryKey]bool
	Services map[string]bool // services whose findings were counted
}

// NewSimulation returns an empty simulation.
func NewSimulation() *Simulation {
	return &Simulation{Links: map[LinkKey]bool{}, History: map[HistoryKey]bool{}, Services: map[string]bool{}}
}

// Item is the plan for one address: the journal row an apply writes.
type Item struct {
	AssetID          string       `json:"asset_id"`
	Address          string       `json:"address"`
	Provider         string       `json:"provider"`
	Bucket           Bucket       `json:"bucket"`
	Action           Action       `json:"action"`
	PriorStatus      string       `json:"prior_status"`
	NewStatus        string       `json:"new_status,omitempty"`
	PriorAttribution *Attribution `json:"prior_attribution,omitempty"`
	NewAttribution   *Attribution `json:"new_attribution,omitempty"`
	Edges            []Edge       `json:"edges"`
	AddedEdges       []Edge       `json:"added_edges"`
	FoldedKeys       []FoldKey    `json:"folded_keys"`
	Outcome          string       `json:"outcome"`
}

// Changes reports whether an apply changes anything for the item.
func (it *Item) Changes() bool {
	return len(it.Edges) > 0 || len(it.AddedEdges) > 0 || len(it.FoldedKeys) > 0 ||
		it.NewStatus != "" || it.NewAttribution != nil
}

// Counts are a run's counters by key (see the Count* keys).
type Counts map[string]int

// Add adds n to key.
func (c Counts) Add(key string, n int) {
	if n != 0 {
		c[key] += n
	}
}

// Merge adds every counter of o.
func (c Counts) Merge(o Counts) {
	for k, v := range o {
		c.Add(k, v)
	}
}

// Count keys. Per-provider and per-bucket keys are built with AddressKey;
// per-severity keys with SeverityKey.
const (
	CountAddresses               = "addresses"
	CountEdgesFolded             = "edges_folded"
	CountEdgesNotInHistory       = "edges_not_in_history"
	CountServicesRelinked        = "services_relinked"
	CountCertificatesRelinked    = "certificates_relinked"
	CountAddressServices         = "address_services"
	CountAddressServiceFindings  = "address_service_findings"
	CountNameServicesWithoutName = "name_services_without_name_asset"
	CountArchived                = "archived"
	CountKept                    = "kept"
	CountAttributionSet          = "attribution_set"
	CountSkippedActiveRun        = "skipped_active_run"
	CountEdgesDeleted            = "edges_deleted"
	CountEdgesAdded              = "edges_added"
	CountInventoryRemoved        = "inventory_removed"
	CountItemsJournaled          = "items_journaled"
	CountReclassified            = "reclassified"
	CountRestored                = "restored"
	CountChanged                 = "changed"
	CountFindingStatusChanges    = "finding_status_changes"
	CountInventoryBefore         = "inventory_before"
	CountInventoryAfterExpected  = "inventory_after_expected"
	CountCardEntriesExact        = "card_entries_exact"
	CountCardEntriesRange        = "card_entries_range"
	prefixAddress                = "address:"
	prefixRelinkedFindings       = "relinked_findings:"
	prefixCardEntry              = "card_entry:"
)

// AddressKey is the counter of addresses of a provider in a bucket.
func AddressKey(provider string, b Bucket) string { return prefixAddress + provider + ":" + string(b) }

// SeverityKey is the counter of findings of a severity on relinked services.
func SeverityKey(severity string) string { return prefixRelinkedFindings + severity }

// CardEntryKey is the counter of scope entries for the card by kind
// (exact or range) and origin.
func CardEntryKey(kind, origin string) string { return prefixCardEntry + kind + ":" + origin }

// ParseAddressKey splits an AddressKey; ok is false for any other key.
func ParseAddressKey(k string) (provider string, b Bucket, ok bool) {
	rest, found := strings.CutPrefix(k, prefixAddress)
	if !found {
		return "", "", false
	}
	i := strings.LastIndex(rest, ":")
	if i < 0 {
		return "", "", false
	}
	return rest[:i], Bucket(rest[i+1:]), true
}

// ParseSeverityKey returns the severity of a SeverityKey.
func ParseSeverityKey(k string) (string, bool) { return strings.CutPrefix(k, prefixRelinkedFindings) }

// ParseCardEntryKey splits a CardEntryKey.
func ParseCardEntryKey(k string) (kind, origin string, ok bool) {
	rest, found := strings.CutPrefix(k, prefixCardEntry)
	if !found {
		return "", "", false
	}
	kind, origin, ok = strings.Cut(rest, ":")
	return kind, origin, ok
}

// Plan is the plan of one batch.
type Plan struct {
	Items  []Item // addresses an apply changes or skips
	Counts Counts
}

// NewID returns an id for an added edge.
var NewID = func() string { return shared.NewID().String() }

// PlanBatch plans one batch. It reads in and sim and records in sim what it
// planned; it never writes anywhere else.
func PlanBatch(in BatchInput, sim *Simulation, now time.Time) Plan {
	plan := Plan{Counts: Counts{}}
	byAddr := map[string][]Edge{}
	for _, e := range in.Edges {
		byAddr[e.SourceID] = append(byAddr[e.SourceID], e)
		if e.TargetID != e.SourceID {
			byAddr[e.TargetID] = append(byAddr[e.TargetID], e)
		}
	}
	for _, a := range in.Addresses {
		it, ok := planAddress(a, in, byAddr[a.ID], sim, plan.Counts, now)
		if ok {
			plan.Items = append(plan.Items, it)
		}
	}
	plan.Counts.Add(CountItemsJournaled, len(plan.Items))
	return plan
}

func isNameType(t string) bool {
	return t == string(asset.AssetTypeDomain) || t == string(asset.AssetTypeSubdomain)
}

// addressPlan is the plan of one address while it is built.
type addressPlan struct {
	a     Address
	in    BatchInput
	sim   *Simulation
	c     Counts
	now   time.Time
	it    Item
	names map[string]bool // names this address resolved for, or now holds services of

	resolvesIn, exposesOut, certsOut       []Edge
	manual, other, addressServices, relink bool
}

// planAddress plans one address; ok is false when an apply leaves it as is.
func planAddress(a Address, in BatchInput, edges []Edge, sim *Simulation, c Counts, now time.Time) (Item, bool) {
	cls := in.Classes[a.ID]
	element, err := asset.NormalizeSetElement(asset.SetAttrIPAddresses, a.Name)
	if err != nil {
		return Item{}, false
	}
	p := &addressPlan{a: a, in: in, sim: sim, c: c, now: now, names: map[string]bool{},
		it: Item{AssetID: a.ID, Address: element, Provider: cls.Provider, PriorStatus: a.Status,
			PriorAttribution: a.Attribution, Edges: []Edge{}, AddedEdges: []Edge{}, FoldedKeys: []FoldKey{}}}
	c.Add(CountAddresses, 1)
	if in.ActiveRun[a.ID] {
		p.it.Bucket, p.it.Action, p.it.Outcome = BucketActiveRun, ActionSkip, OutcomeSkippedActiveRun
		c.Add(AddressKey(cls.Provider, p.it.Bucket), 1)
		c.Add(CountSkippedActiveRun, 1)
		return p.it, true
	}
	p.sortEdges(edges)
	p.fold()
	p.relinkServices()
	p.relinkCertificates()
	p.decide()
	if !p.it.Changes() {
		return Item{}, false
	}
	p.it.Outcome = OutcomeApplied
	c.Add(CountEdgesDeleted, len(p.it.Edges))
	c.Add(CountEdgesAdded, len(p.it.AddedEdges))
	return p.it, true
}

// sortEdges sorts the address's edges by what the move does with them.
// Manual edges are never touched and keep the address.
func (p *addressPlan) sortEdges(edges []Edge) {
	sort.Slice(edges, func(i, j int) bool { return edges[i].ID < edges[j].ID })
	id := p.a.ID
	for _, e := range edges {
		switch {
		case e.DiscoveryMethod == "manual":
			p.manual = true
		case e.Type == "resolves_to" && e.TargetID == id:
			p.resolvesIn = append(p.resolvesIn, e)
		case e.Type == "exposes" && e.SourceID == id:
			p.exposesOut = append(p.exposesOut, e)
		case e.Type == "serves_certificate" && e.SourceID == id:
			p.certsOut = append(p.certsOut, e)
		default:
			p.other = true
		}
	}
}

// fold turns every name-to-address edge into a history row on the name.
func (p *addressPlan) fold() {
	folds := map[HistoryKey]*FoldKey{}
	var order []HistoryKey
	for _, e := range p.resolvesIn {
		first := e.CreatedAt.UTC()
		last := first
		if e.LastVerified != nil {
			last = e.LastVerified.UTC()
		}
		if last.Before(first) {
			first, last = last, first
		}
		k := HistoryKey{NameID: e.SourceID, Element: p.it.Address}
		p.c.Add(CountEdgesFolded, 1)
		if !p.in.History[k] && !p.sim.History[k] {
			p.c.Add(CountEdgesNotInHistory, 1)
		}
		p.sim.History[k] = true
		if f, ok := folds[k]; ok {
			f.FirstSeen, f.LastSeen = minTime(f.FirstSeen, first), maxTime(f.LastSeen, last)
		} else {
			folds[k] = &FoldKey{NameID: e.SourceID, Element: p.it.Address, FirstSeen: first, LastSeen: last}
			order = append(order, k)
		}
		p.it.Edges = append(p.it.Edges, e)
		if isNameType(p.in.Assets[e.SourceID].Type) {
			p.names[e.SourceID] = true
		}
	}
	for _, k := range order {
		p.it.FoldedKeys = append(p.it.FoldedKeys, *folds[k])
	}
}

// add plans a name edge unless it exists or an earlier batch planned it.
func (p *addressPlan) add(src, dst, typ string, from Edge) {
	k := LinkKey{Source: src, Target: dst, Type: typ}
	if p.in.Links[k] || p.sim.Links[k] {
		return
	}
	p.sim.Links[k] = true
	desc := RelinkDescription
	p.it.AddedEdges = append(p.it.AddedEdges, Edge{ID: NewID(), SourceID: src, TargetID: dst, Type: typ,
		Description: &desc, Confidence: from.Confidence, DiscoveryMethod: "inferred", ImpactWeight: from.ImpactWeight,
		Tags: append([]string{}, from.Tags...), LastVerified: from.LastVerified, CreatedAt: p.now, UpdatedAt: p.now})
}

// relinkServices moves services named by a host name to that name; services
// named by the address stay and keep it.
func (p *addressPlan) relinkServices() {
	for _, e := range p.exposesOut {
		svc := p.in.Assets[e.TargetID]
		host := asset.HostOf(svc.Name)
		if _, err := netip.ParseAddr(host); err == nil || host == "" {
			p.addressServices = true
			p.c.Add(CountAddressServices, 1)
			for _, n := range p.in.Findings[e.TargetID] {
				p.c.Add(CountAddressServiceFindings, n)
			}
			continue
		}
		nameID := p.in.NamesByHost[host]
		if nameID == "" {
			p.other = true
			p.c.Add(CountNameServicesWithoutName, 1)
			continue
		}
		p.add(nameID, e.TargetID, "exposes", e)
		p.it.Edges = append(p.it.Edges, e)
		p.names[nameID] = true
		p.relink = true
		p.c.Add(CountServicesRelinked, 1)
		if !p.sim.Services[e.TargetID] {
			p.sim.Services[e.TargetID] = true
			for sev, n := range p.in.Findings[e.TargetID] {
				p.c.Add(SeverityKey(sev), n)
			}
		}
	}
}

// relinkCertificates moves a certificate to every name it covers; one that
// covers no name stays and keeps the address.
func (p *addressPlan) relinkCertificates() {
	names := make([]string, 0, len(p.names))
	for id := range p.names {
		names = append(names, id)
	}
	sort.Strings(names)
	for _, e := range p.certsOut {
		cert := p.in.Assets[e.TargetID]
		covered := false
		for _, id := range names {
			if CertificateCovers(cert.Covers, p.in.Assets[id].Name) {
				p.add(id, e.TargetID, "serves_certificate", e)
				covered = true
			}
		}
		if !covered {
			p.other = true
			continue
		}
		p.it.Edges = append(p.it.Edges, e)
		p.relink = true
		p.c.Add(CountCertificatesRelinked, 1)
	}
}

// bucket is why the address is archived or kept, in order of precedence.
func (p *addressPlan) bucket() Bucket {
	switch {
	case p.a.Attribution.Human() || p.a.ManualStatus:
		return BucketPerson
	case p.in.EntryCovered[p.a.ID]:
		return BucketEntry
	case p.a.Tagged || p.in.Referenced[p.a.ID]:
		return BucketReference
	case p.manual:
		return BucketManualEdge
	case p.in.Revived[p.a.ID]:
		return BucketRevived
	case p.addressServices:
		return BucketAddressServices
	case p.other:
		return BucketOtherEdges
	case p.relink:
		return BucketPlainAfterRelink
	}
	return BucketPlain
}

// decide archives a plain address and keeps every other one.
func (p *addressPlan) decide() {
	a := p.a
	p.it.Bucket = p.bucket()
	p.c.Add(AddressKey(p.it.Provider, p.it.Bucket), 1)
	if p.it.Bucket == BucketPlain || p.it.Bucket == BucketPlainAfterRelink {
		p.it.Action = ActionArchive
		if a.Status != string(asset.StatusArchived) {
			p.it.NewStatus = string(asset.StatusArchived)
			p.c.Add(CountArchived, 1)
			if inInventory(a.Attribution) {
				p.c.Add(CountInventoryRemoved, 1)
			}
		}
		if !a.Attribution.isProvider() {
			p.it.NewAttribution = providerAttribution()
		}
	} else {
		p.it.Action = ActionKeep
		p.c.Add(CountKept, 1)
		if a.Attribution != nil && a.Attribution.State == string(attribution.StateDiscovered) && !a.Attribution.Human() {
			p.it.NewAttribution = providerAttribution()
		}
	}
	if p.it.NewAttribution != nil {
		p.c.Add(CountAttributionSet, 1)
	}
}

func minTime(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}

func maxTime(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

// inInventory mirrors attribution.InInventory on a stored record.
func inInventory(a *Attribution) bool {
	if a == nil {
		return true
	}
	return attribution.InInventory(attribution.State(a.State))
}

// CertificateCovers reports whether a certificate for covers serves name:
// an exact name, or a wildcard "*.parent" for a name one label below parent.
func CertificateCovers(covers []string, name string) bool {
	n := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	if n == "" {
		return false
	}
	for _, c := range covers {
		c = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(c)), ".")
		if c == n {
			return true
		}
		if parent, ok := strings.CutPrefix(c, "*."); ok {
			if label, rest, found := strings.Cut(n, "."); found && label != "" && rest == parent {
				return true
			}
		}
	}
	return false
}

// MarshalJSONArray encodes a journal column (never null).
func MarshalJSONArray[T any](v []T) []byte {
	if v == nil {
		v = []T{}
	}
	b, err := json.Marshal(v)
	if err != nil {
		return []byte("[]")
	}
	return b
}
