package contentpack

// Delivery serves content packs to sensors over the sensor channel
// (research/139 §3, RFC-061 §3.4): the platform is the only place sensors
// get content from. A sensor sees its organization's active packs and the
// platform's packs on the stable channel; it fetches a pack by digest, or
// its file index and the files it lacks, and never the same digest twice.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"

	dom "github.com/openctemio/openctem/api/pkg/domain/contentpack"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Delivery scopes, as the sensor's cache names them.
const (
	ScopeTenant   = "tenant"
	ScopePlatform = "platform"
)

// maxDesiredPacks bounds each part of the desired document.
const maxDesiredPacks = 500

// DeliveredPack is one entry of the desired document.
type DeliveredPack struct {
	Digest    string          `json:"digest"`
	Scope     string          `json:"scope"`
	Size      int64           `json:"size"`
	Signature json.RawMessage `json:"signature"`
}

// Desired is what a sensor of the organization should hold, and the
// revoked digests it must drop.
type Desired struct {
	Packs   []DeliveredPack `json:"packs"`
	Revoked []string        `json:"revoked,omitempty"`
}

// IndexEntry is one file of a pack's index.
type IndexEntry struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// Delivery serves packs to sensors.
type Delivery struct {
	tenant   *Service
	platform *PlatformService
	cache    *archiveCache
	now      func() time.Time

	mu   sync.Mutex
	sets map[string]desiredMemo
}

// desiredTTL is how long a computed set authorizes file requests: a delta
// install asks for many files of one pack within seconds; a revocation
// takes effect within this time.
const desiredTTL = 10 * time.Second

type desiredMemo struct {
	at      time.Time
	set     map[string]located
	revoked []string
}

// NewDelivery builds the sensor delivery over the tenant and platform pack
// stores (either may be nil).
func NewDelivery(tenant *Service, platform *PlatformService) *Delivery {
	return &Delivery{tenant: tenant, platform: platform, cache: newArchiveCache(256 << 20), now: time.Now, sets: map[string]desiredMemo{}}
}

type located struct {
	pack  DeliveredPack
	id    string
	scope string
}

// desired lists what the organization's sensors may hold, keyed by digest
// (computed at most once per desiredTTL per organization).
func (d *Delivery) desired(ctx context.Context, tenantID string) (map[string]located, []string, error) {
	d.mu.Lock()
	m, ok := d.sets[tenantID]
	d.mu.Unlock()
	if ok && d.now().Sub(m.at) < desiredTTL {
		return m.set, m.revoked, nil
	}
	set, revoked, err := d.compute(ctx, tenantID)
	if err != nil {
		return nil, nil, err
	}
	d.mu.Lock()
	if len(d.sets) > 10000 {
		d.sets = map[string]desiredMemo{}
	}
	d.sets[tenantID] = desiredMemo{at: d.now(), set: set, revoked: revoked}
	d.mu.Unlock()
	return set, revoked, nil
}

func (d *Delivery) compute(ctx context.Context, tenantID string) (map[string]located, []string, error) {
	out := map[string]located{}
	var revoked []string
	if d.tenant != nil {
		active, _, err := d.tenant.List(ctx, ListInput{TenantID: tenantID, Status: string(dom.StatusActive), Limit: maxDesiredPacks})
		if err != nil {
			return nil, nil, err
		}
		for _, p := range active {
			out[p.Digest] = located{DeliveredPack{p.Digest, ScopeTenant, p.SizeBytes, p.Signature}, p.ID.String(), ScopeTenant}
		}
		gone, _, err := d.tenant.List(ctx, ListInput{TenantID: tenantID, Status: string(dom.StatusRevoked), Limit: maxDesiredPacks})
		if err != nil {
			return nil, nil, err
		}
		for _, p := range gone {
			if _, still := out[p.Digest]; !still {
				revoked = append(revoked, p.Digest)
			}
		}
	}
	if d.platform != nil {
		channels, err := d.platform.Channels(ctx)
		if err != nil {
			return nil, nil, err
		}
		for _, c := range channels {
			if c.Channel != dom.ChannelStable {
				continue
			}
			if _, dup := out[c.Digest]; dup {
				continue
			}
			p, err := d.platform.Get(ctx, c.PackID.String())
			if err != nil || p.Status != dom.StatusActive {
				continue
			}
			out[p.Digest] = located{DeliveredPack{p.Digest, ScopePlatform, p.SizeBytes, p.Signature}, p.ID.String(), ScopePlatform}
		}
		gone, _, err := d.platform.List(ctx, dom.Filter{Status: dom.StatusRevoked}, maxDesiredPacks, 0)
		if err != nil {
			return nil, nil, err
		}
		for _, p := range gone {
			if _, still := out[p.Digest]; !still {
				revoked = append(revoked, p.Digest)
			}
		}
	}
	sort.Strings(revoked)
	return out, revoked, nil
}

// Desired is the organization's desired document and its ETag (the hash
// of the document: unchanged content, unchanged ETag).
func (d *Delivery) Desired(ctx context.Context, tenantID string) (*Desired, string, error) {
	if _, err := parseTenant(tenantID); err != nil {
		return nil, "", err
	}
	set, revoked, err := d.desired(ctx, tenantID)
	if err != nil {
		return nil, "", err
	}
	doc := &Desired{Packs: make([]DeliveredPack, 0, len(set)), Revoked: revoked}
	for _, l := range set {
		doc.Packs = append(doc.Packs, l.pack)
	}
	sort.Slice(doc.Packs, func(i, j int) bool { return doc.Packs[i].Digest < doc.Packs[j].Digest })
	b, err := json.Marshal(doc)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(b)
	return doc, `"` + hex.EncodeToString(sum[:16]) + `"`, nil
}

// archive returns the canonical archive of a digest the organization's
// sensors may hold; any other digest (another organization's, revoked,
// unknown) is ErrNotFound.
func (d *Delivery) archive(ctx context.Context, tenantID, digest string) (*dom.Archive, error) {
	if err := dom.ValidateDigest(digest); err != nil {
		return nil, fmt.Errorf("%w: %v", shared.ErrNotFound, err)
	}
	set, _, err := d.desired(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	l, ok := set[digest]
	if !ok {
		return nil, shared.ErrNotFound
	}
	if a := d.cache.get(digest); a != nil {
		return a, nil
	}
	var data []byte
	if l.scope == ScopeTenant {
		_, data, err = d.tenant.Archive(ctx, tenantID, l.id)
	} else {
		_, data, err = d.platform.Archive(ctx, l.id)
	}
	if err != nil {
		return nil, err
	}
	a, err := dom.ReadPlatformCanonical(data, digest)
	if err != nil {
		return nil, fmt.Errorf("%w: stored content pack is corrupt", shared.ErrInternal)
	}
	d.cache.put(digest, a)
	return a, nil
}

// Archive is a pack's canonical archive.
func (d *Delivery) Archive(ctx context.Context, tenantID, digest string) ([]byte, error) {
	a, err := d.archive(ctx, tenantID, digest)
	if err != nil {
		return nil, err
	}
	return a.Canonical, nil
}

// Index is a pack's file index.
func (d *Delivery) Index(ctx context.Context, tenantID, digest string) ([]IndexEntry, error) {
	a, err := d.archive(ctx, tenantID, digest)
	if err != nil {
		return nil, err
	}
	out := make([]IndexEntry, 0, len(a.Files))
	for _, f := range a.Files {
		sum := sha256.Sum256(f.Data)
		out = append(out, IndexEntry{Path: f.Path, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(f.Data))})
	}
	return out, nil
}

// File is one file of a pack, by its sha256 (lower-case hex).
func (d *Delivery) File(ctx context.Context, tenantID, digest, sha string) ([]byte, error) {
	a, err := d.archive(ctx, tenantID, digest)
	if err != nil {
		return nil, err
	}
	for _, f := range a.Files {
		sum := sha256.Sum256(f.Data)
		if hex.EncodeToString(sum[:]) == sha {
			return f.Data, nil
		}
	}
	return nil, shared.ErrNotFound
}

// archiveCache keeps the most recently served archives (a delta fetch asks
// for many files of one pack) within a byte budget.
type archiveCache struct {
	mu     sync.Mutex
	budget int64
	used   int64
	order  []string
	items  map[string]*dom.Archive
}

func newArchiveCache(budget int64) *archiveCache {
	return &archiveCache{budget: budget, items: map[string]*dom.Archive{}}
}

func (c *archiveCache) get(digest string) *dom.Archive {
	c.mu.Lock()
	defer c.mu.Unlock()
	a := c.items[digest]
	if a != nil {
		c.touch(digest)
	}
	return a
}

func (c *archiveCache) touch(digest string) {
	for i, d := range c.order {
		if d == digest {
			c.order = append(c.order[:i], c.order[i+1:]...)
			break
		}
	}
	c.order = append(c.order, digest)
}

func (c *archiveCache) put(digest string, a *dom.Archive) {
	size := 2 * a.Size() // the canonical bytes and the parsed files
	if size > c.budget {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.items[digest]; ok {
		return
	}
	for c.used+size > c.budget && len(c.order) > 0 {
		old := c.order[0]
		c.order = c.order[1:]
		c.used -= 2 * c.items[old].Size()
		delete(c.items, old)
	}
	c.items[digest] = a
	c.used += size
	c.order = append(c.order, digest)
}
