package easm

// Network seeds (docs/rfcs/RFC-082-network-seeds.md): AS numbers and
// organization names the organization asserts are its own. A seed is
// expanded from public routing data into announced prefixes (AS numbers)
// or candidate AS numbers (organizations); prefixes are offered as CIDR
// scope entries, checked against the platform guardrails, for a person to
// add through the scope flow. Nothing here widens scope or probes a target.

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/easmseed"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// NetworkSeedStore stores network seeds (*postgres.EASMNetworkSeedRepository).
type NetworkSeedStore interface {
	List(ctx context.Context, tenantID shared.ID) ([]easmseed.Seed, error)
	Get(ctx context.Context, tenantID shared.ID, id string) (*easmseed.Seed, error)
	Create(ctx context.Context, tenantID shared.ID, kind easmseed.Kind, value, label string, createdBy *shared.ID) (*easmseed.Seed, error)
	Delete(ctx context.Context, tenantID shared.ID, id string) error
	ClaimExpansion(ctx context.Context, tenantID shared.ID, id string, now time.Time, cooldown time.Duration) (bool, error)
	SaveExpansion(ctx context.Context, tenantID shared.ID, id, holder string, prefixes []string, suggestions []easmseed.ASNSuggestion, expandErr string) error
	Networks(ctx context.Context, tenantID shared.ID) (easmseed.Networks, error)
	DueForExpansion(ctx context.Context, before time.Time, limit int) ([]easmseed.Ref, error)
}

// NetworkDataSource answers the routing questions (*RIPEstat).
type NetworkDataSource interface {
	ASNHolder(ctx context.Context, asn string) (string, error)
	AnnouncedPrefixes(ctx context.Context, asn string) ([]string, error)
	SearchASNs(ctx context.Context, org string) ([]easmseed.ASNSuggestion, error)
}

// ErrExpandTooSoon refuses an expansion inside the cooldown.
var ErrExpandTooSoon = errors.New("the seed was expanded less than 15 minutes ago")

// PrefixSuggestion is an announced prefix offered as a CIDR scope entry.
type PrefixSuggestion struct {
	Prefix string `json:"prefix"`
	// Allowed: the platform guardrails accept the prefix as a scope entry.
	Allowed bool `json:"allowed"`
	// Refusal is the guardrail code when not allowed (DENY_LIST,
	// CIDR_TOO_LARGE, ...).
	Refusal string `json:"refusal,omitempty"`
}

// SeedView is a seed with its scope suggestions.
type SeedView struct {
	easmseed.Seed
	// Shared: the AS belongs to a CDN or cloud provider that serves many
	// organizations; its prefixes are never offered.
	Shared            bool               `json:"shared"`
	PrefixSuggestions []PrefixSuggestion `json:"prefix_suggestions"`
}

// NetworkSeedService manages network seeds.
type NetworkSeedService struct {
	store      NetworkSeedStore
	source     NetworkDataSource
	guardrails scopedom.Guardrails
	log        *logger.Logger
	now        func() time.Time
	// async runs an expansion in the background (tests run it inline).
	async    func(func())
	settings NetworkSeedSettings
}

// NetworkSeedSettings reads the organization's attack-surface settings,
// where the switch for lookups in public routing data lives.
type NetworkSeedSettings interface {
	GetEASMSettings(ctx context.Context, tenantID string) (*tenant.EASMSettings, error)
}

// SetSettings wires the organization's lookup switch. Without it lookups run.
func (s *NetworkSeedService) SetSettings(st NetworkSeedSettings) { s.settings = st }

// ErrLookupsOff refuses a lookup the organization turned off.
var ErrLookupsOff = fmt.Errorf("%w: lookups in public routing data are turned off for the organization", shared.ErrConflict)

// lookupsAllowed reports whether the organization lets seeds be looked up
// in public routing data. An unreadable setting answers no (fail closed:
// nothing is sent on a database error).
func (s *NetworkSeedService) lookupsAllowed(ctx context.Context, tenantID shared.ID) bool {
	if s.settings == nil {
		return true
	}
	es, err := s.settings.GetEASMSettings(ctx, tenantID.String())
	if err != nil {
		s.log.Warn("network seed settings unreadable; lookup skipped", "tenant_id", tenantID.String(), "error", logger.SanitizeError(err))
		return false
	}
	return !es.NetworkLookupsDisabled
}

// NewNetworkSeedService creates the service.
func NewNetworkSeedService(store NetworkSeedStore, source NetworkDataSource, guardrails scopedom.Guardrails, log *logger.Logger) *NetworkSeedService {
	if log == nil {
		log = logger.NewNop()
	}
	return &NetworkSeedService{store: store, source: source, guardrails: guardrails, log: log,
		now:   func() time.Time { return time.Now().UTC() },
		async: func(f func()) { go f() }}
}

// expandTimeout bounds one expansion.
const expandTimeout = 2 * time.Minute

// List returns the tenant's seeds with their suggestions.
func (s *NetworkSeedService) List(ctx context.Context, tenantID shared.ID) ([]SeedView, error) {
	seeds, err := s.store.List(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]SeedView, 0, len(seeds))
	for _, sd := range seeds {
		out = append(out, s.view(sd))
	}
	return out, nil
}

func (s *NetworkSeedService) view(sd easmseed.Seed) SeedView {
	v := SeedView{Seed: sd, PrefixSuggestions: []PrefixSuggestion{}}
	if sd.Kind != easmseed.KindASN {
		return v
	}
	v.Shared, _ = sharedAddress(map[string]any{"asn_org": sd.Holder})
	if v.Shared {
		return v
	}
	for _, p := range sd.Prefixes {
		ps := PrefixSuggestion{Prefix: p, Allowed: true}
		if err := s.guardrails.CheckPattern(scopedom.TargetTypeCIDR, p); err != nil {
			ps.Allowed = false
			var de *shared.DomainError
			if errors.As(err, &de) {
				ps.Refusal = de.Code
			} else {
				ps.Refusal = "REFUSED"
			}
		}
		v.PrefixSuggestions = append(v.PrefixSuggestions, ps)
	}
	return v
}

// Create adds a seed and starts its first expansion in the background.
func (s *NetworkSeedService) Create(ctx context.Context, tenantID shared.ID, actor *shared.ID, kind easmseed.Kind, value, label string) (*SeedView, error) {
	norm, err := easmseed.Normalize(kind, value)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", shared.ErrValidation, err)
	}
	label = cleanText(label, easmseed.MaxLabelBytes)
	sd, err := s.store.Create(ctx, tenantID, kind, norm, label, actor)
	if err != nil {
		return nil, err
	}
	s.startExpansion(tenantID, sd.ID)
	v := s.view(*sd)
	return &v, nil
}

// Delete removes a seed.
func (s *NetworkSeedService) Delete(ctx context.Context, tenantID shared.ID, id string) error {
	return s.store.Delete(ctx, tenantID, id)
}

// Expand refreshes a seed now (at most once per cooldown), in the background.
func (s *NetworkSeedService) Expand(ctx context.Context, tenantID shared.ID, id string) error {
	if _, err := s.store.Get(ctx, tenantID, id); err != nil {
		return err
	}
	if !s.lookupsAllowed(ctx, tenantID) {
		return ErrLookupsOff
	}
	ok, err := s.store.ClaimExpansion(ctx, tenantID, id, s.now(), easmseed.ExpandCooldown)
	if err != nil {
		return err
	}
	if !ok {
		return ErrExpandTooSoon
	}
	s.async(func() {
		ctx, cancel := context.WithTimeout(context.Background(), expandTimeout)
		defer cancel()
		s.expand(ctx, tenantID, id)
	})
	return nil
}

func (s *NetworkSeedService) startExpansion(tenantID shared.ID, id string) {
	s.async(func() {
		ctx, cancel := context.WithTimeout(context.Background(), expandTimeout)
		defer cancel()
		if ok, err := s.store.ClaimExpansion(ctx, tenantID, id, s.now(), 0); err != nil || !ok {
			return
		}
		s.expand(ctx, tenantID, id)
	})
}

// refreshBatch bounds one weekly refresh pass.
const refreshBatch = 200

// RefreshDue expands the seeds last expanded more than a week ago (or
// never), skipping tenants skip says no to (module off). Returns how many
// were expanded.
func (s *NetworkSeedService) RefreshDue(ctx context.Context, skip func(shared.ID) bool) (int, error) {
	refs, err := s.store.DueForExpansion(ctx, s.now().Add(-easmseed.RefreshInterval), refreshBatch)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, ref := range refs {
		if err := ctx.Err(); err != nil {
			return n, err
		}
		if skip != nil && skip(ref.TenantID) {
			continue
		}
		ok, err := s.store.ClaimExpansion(ctx, ref.TenantID, ref.ID, s.now(), easmseed.ExpandCooldown)
		if err != nil || !ok {
			continue
		}
		s.expand(ctx, ref.TenantID, ref.ID)
		n++
	}
	return n, nil
}

// expand fetches the seed's routing data and stores it. Errors are stored
// on the seed (generic text, no response content) and logged.
func (s *NetworkSeedService) expand(ctx context.Context, tenantID shared.ID, id string) {
	sd, err := s.store.Get(ctx, tenantID, id)
	if err != nil {
		return
	}
	if !s.lookupsAllowed(ctx, tenantID) {
		_ = s.store.SaveExpansion(ctx, tenantID, id, "", nil, nil, "lookups in public routing data are turned off for the organization")
		return
	}
	var holder string
	var prefixes []string
	var sugg []easmseed.ASNSuggestion
	switch sd.Kind {
	case easmseed.KindASN:
		if holder, err = s.source.ASNHolder(ctx, sd.Value); err == nil {
			prefixes, err = s.source.AnnouncedPrefixes(ctx, sd.Value)
		}
	case easmseed.KindOrgName:
		sugg, err = s.source.SearchASNs(ctx, sd.Value)
		sugg = matchingSuggestions(sd.Value, sugg)
	}
	if err != nil {
		s.log.Warn("network seed expansion failed", "tenant_id", tenantID.String(), "seed_id", id, "error", logger.SanitizeError(err))
		_ = s.store.SaveExpansion(ctx, tenantID, id, "", nil, nil, "the public routing data source did not answer; retried later")
		return
	}
	if err := s.store.SaveExpansion(ctx, tenantID, id, holder, prefixes, sugg, ""); err != nil {
		s.log.Warn("network seed expansion not saved", "tenant_id", tenantID.String(), "seed_id", id, "error", logger.SanitizeError(err))
	}
}

// matchingSuggestions keeps registry hits whose description names the
// organization (a distinctive word of it), so a broad search does not offer
// other organizations' networks; shared CDN or cloud ASNs are dropped.
func matchingSuggestions(org string, in []easmseed.ASNSuggestion) []easmseed.ASNSuggestion {
	out := []easmseed.ASNSuggestion{}
	for _, s := range in {
		if isShared, _ := sharedAddress(map[string]any{"asn_org": s.Description}); isShared {
			continue
		}
		if orgMatches(org, s.Description) {
			out = append(out, s)
		}
	}
	return out
}

// seededNetwork reports whether an address with the given ASN and ASN
// organization belongs to the tenant's seeded networks: its AS is seeded,
// it falls in a seeded AS's announced prefix, or the ASN organization names
// a seeded organization.
func seededNetwork(n easmseed.Networks, addr, asn, asnOrg string) bool {
	if asn != "" && n.ASNs[strings.ToUpper(asn)] {
		return true
	}
	if addr != "" && len(n.Prefixes) > 0 && inPrefixes(addr, n.Prefixes) {
		return true
	}
	for _, o := range n.OrgNames {
		if asnOrg != "" && orgMatches(o, asnOrg) {
			return true
		}
	}
	return false
}

func inPrefixes(addr string, prefixes []string) bool {
	a, err := netip.ParseAddr(addr)
	if err != nil {
		return false
	}
	for _, p := range prefixes {
		if pfx, err := netip.ParsePrefix(p); err == nil && pfx.Contains(a) {
			return true
		}
	}
	return false
}
