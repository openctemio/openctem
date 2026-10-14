// Package toolfacts builds an organization's stage catalog from the tool
// contracts its sensors report (docs/rfcs/RFC-092-tool-agnostic-platform.md,
// docs/architecture/tool-contract.md): which tools implement each
// capability, how the capability's standard params map to each tool's
// settings keys, and whether a tool takes a target list.
//
// Threat model: a contract is a sensor's claim. The facts read here only
// decide which tool a capability step is routed to and how its settings are
// named; they grant no tier, no target and no access. Every fact is
// organization-scoped (the organization's own sensors plus the platform's
// sensors), so a sensor can affect only its own organization's routing, and
// the claim-time grant, tier and sensor-local policy checks still apply to
// every job. Capabilities the platform does not route are ignored.
package toolfacts

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/openctemio/ctis/capability"

	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
)

// ManifestSource reads current sensor manifests.
type ManifestSource interface {
	// CurrentManifestsByTenant: the organization's own sensors (never a
	// platform sensor, never another organization's).
	CurrentManifestsByTenant(ctx context.Context, tenantID shared.ID) (map[shared.ID]*sensor.ManifestVersion, error)
	// CurrentPlatformManifests: the platform's sensors.
	CurrentPlatformManifests(ctx context.Context) (map[shared.ID]*sensor.ManifestVersion, error)
}

// Defaults of the in-process cache.
const (
	// CacheTTL is how long an organization's catalog is reused: a new
	// manifest reaches planning within it.
	CacheTTL = 15 * time.Second
	// maxCached bounds the cache; past it the expired entries are dropped,
	// then the whole map if it is still full.
	maxCached = 4096
)

// Loader is a stage.Source over the sensors' current manifests, cached per
// organization for CacheTTL.
type Loader struct {
	src ManifestSource
	now func() time.Time
	ttl time.Duration

	mu    sync.Mutex
	cache map[shared.ID]entry
}

type entry struct {
	cat     stage.Catalog
	expires time.Time
}

var _ stage.Source = (*Loader)(nil)

// New is a Loader over src.
func New(src ManifestSource) *Loader {
	return &Loader{src: src, now: time.Now, ttl: CacheTTL, cache: map[shared.ID]entry{}}
}

// Catalog is the organization's catalog: the facts of the contracts its
// sensors and the platform's sensors report. A nil loader (or one without a
// source) is the zero catalog: no tool implements anything.
func (l *Loader) Catalog(ctx context.Context, tenantID shared.ID) (stage.Catalog, error) {
	if l == nil || l.src == nil {
		return stage.Catalog{}, nil
	}
	now := l.now()
	l.mu.Lock()
	if e, ok := l.cache[tenantID]; ok && now.Before(e.expires) {
		l.mu.Unlock()
		return e.cat, nil
	}
	l.mu.Unlock()

	own, err := l.src.CurrentManifestsByTenant(ctx, tenantID)
	if err != nil {
		return stage.Catalog{}, fmt.Errorf("tool facts: %w", err)
	}
	platform, err := l.src.CurrentPlatformManifests(ctx)
	if err != nil {
		return stage.Catalog{}, fmt.Errorf("tool facts: %w", err)
	}
	cat := stage.WithTools(Facts(own, platform))

	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.cache) >= maxCached {
		for id, e := range l.cache {
			if !now.Before(e.expires) {
				delete(l.cache, id)
			}
		}
		if len(l.cache) >= maxCached {
			l.cache = map[shared.ID]entry{}
		}
	}
	l.cache[tenantID] = entry{cat: cat, expires: now.Add(l.ttl)}
	return cat, nil
}

// reported is one tool's contract as one sensor reports it.
type reported struct {
	name     string
	contract *sensor.ToolContract
}

// Facts merges the tool contracts of the manifests: per tool name, the
// contract with the highest version wins (ties: the lower contract digest,
// so the choice does not depend on map order). Tools without a contract,
// or not installed, implement nothing.
func Facts(manifests ...map[shared.ID]*sensor.ManifestVersion) []stage.ToolFacts {
	best := map[string]reported{}
	for _, set := range manifests {
		for _, mv := range set {
			if mv == nil {
				continue
			}
			for _, t := range mv.Manifest.Tools {
				name := strings.ToLower(strings.TrimSpace(sensor.CanonicalTool(t.Name)))
				if name == "" || t.Contract == nil || !t.Installed {
					continue
				}
				cur, ok := best[name]
				if !ok || newer(t.Contract, cur.contract) {
					best[name] = reported{name: name, contract: t.Contract}
				}
			}
		}
	}
	names := make([]string, 0, len(best))
	for n := range best {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]stage.ToolFacts, 0, len(names))
	for _, n := range names {
		out = append(out, factsOf(n, best[n].contract))
	}
	return out
}

// newer reports whether contract a replaces b.
func newer(a, b *sensor.ToolContract) bool {
	if c := sensor.CompareVersions(a.Version, b.Version); c != 0 {
		return c > 0
	}
	return a.Digest < b.Digest
}

// descriptorImplements is the part of a descriptor this package reads.
type descriptorImplements struct {
	Implements []struct {
		Capability string `json:"capability"`
		Params     map[string]struct {
			Key string `json:"key"`
		} `json:"params"`
	} `json:"implements"`
}

// factsOf is one tool's facts: its capabilities in the contract's order
// (only versions the catalog routes), their param mapping from the
// descriptor and its batch flag. An unreadable descriptor leaves the
// mapping empty (no standard param is handed to the tool).
func factsOf(name string, c *sensor.ToolContract) stage.ToolFacts {
	f := stage.ToolFacts{Name: name, Batch: c.Batch, Params: map[stage.Key]map[string]string{}}
	for _, ref := range c.Implements {
		if k, ok := routedKey(ref); ok {
			f.Implements = append(f.Implements, k)
		}
	}
	if len(c.Descriptor) == 0 {
		return f
	}
	var d descriptorImplements
	if err := json.Unmarshal(c.Descriptor, &d); err != nil {
		return f
	}
	for _, im := range d.Implements {
		k, ok := routedKey(im.Capability)
		if !ok || !c.ImplementsCapability(im.Capability) || f.Params[k] != nil {
			continue
		}
		m := map[string]string{}
		for p, v := range im.Params {
			if key := strings.TrimSpace(v.Key); key != "" {
				m[p] = key
			}
		}
		f.Params[k] = m
	}
	return f
}

// routedKey is the stage key of a capability ref the platform routes
// ("scan.ports@1" -> scan.ports): a taxonomy capability of the catalog's
// contract version.
func routedKey(ref string) (stage.Key, bool) {
	key, major, ok := capability.ParseRef(ref)
	if !ok || major != stage.ContractVersion {
		return "", false
	}
	if _, known := capability.Lookup(ref); !known {
		return "", false
	}
	return stage.Key(key), true
}
