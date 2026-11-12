// Package instancezone holds instance scan zones
// (docs/rfcs/RFC-100-shared-sensors.md §6.1): private ranges an instance
// administrator lets shared sensors scan, the shared sensors that serve each
// zone and the organizations it is assigned to. An organization's internal
// target goes to a shared sensor only inside a zone assigned to that
// organization; overlapping ranges of different organizations are told apart
// by the zone, because a lookup only ever sees the zones assigned to the
// organization that asks.
package instancezone

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/jobsign"
)

// Limits.
const (
	MaxNameLength        = 100
	MaxDescriptionLength = 1000
	MaxTenantsPerZone    = jobsign.MaxZoneTenants
	MaxSensorsPerZone    = jobsign.MaxZoneSensors
)

// ErrNotFound: no such instance scan zone.
var ErrNotFound = fmt.Errorf("%w: instance scan zone not found", shared.ErrNotFound)

// ErrNameTaken: another zone has the name.
var ErrNameTaken = fmt.Errorf("%w: an instance scan zone with this name exists", shared.ErrConflict)

// Zone is one instance scan zone.
type Zone struct {
	ID          shared.ID
	Name        string
	Description string
	// Ranges are canonical, sorted, private CIDRs (jobsign.CanonicalZoneRanges).
	Ranges    []string
	SensorIDs []shared.ID
	TenantIDs []shared.ID
}

// New validates a new zone.
func New(name, description string, ranges []string) (*Zone, error) {
	z := &Zone{ID: shared.NewID()}
	if err := z.Set(name, description, ranges); err != nil {
		return nil, err
	}
	return z, nil
}

// Set validates and sets the name, description and ranges.
func (z *Zone) Set(name, description string, ranges []string) error {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > MaxNameLength {
		return fmt.Errorf("%w: name is required, at most %d characters", shared.ErrValidation, MaxNameLength)
	}
	if len(description) > MaxDescriptionLength {
		return fmt.Errorf("%w: description is at most %d characters", shared.ErrValidation, MaxDescriptionLength)
	}
	canon, err := jobsign.CanonicalZoneRanges(ranges)
	if err != nil {
		return fmt.Errorf("%w: %w", shared.ErrValidation, err)
	}
	z.Name, z.Description, z.Ranges = name, description, canon
	return nil
}

// AssignedTo reports whether the zone is assigned to the organization.
func (z *Zone) AssignedTo(tenantID shared.ID) bool { return slices.Contains(z.TenantIDs, tenantID) }

// LedgerZone is the zone as the signer records it.
func (z *Zone) LedgerZone() jobsign.LedgerZone {
	lz := jobsign.LedgerZone{ID: z.ID.String(), Ranges: slices.Clone(z.Ranges),
		Tenants: make([]string, 0, len(z.TenantIDs)), Sensors: make([]string, 0, len(z.SensorIDs))}
	for _, t := range z.TenantIDs {
		lz.Tenants = append(lz.Tenants, t.String())
	}
	for _, s := range z.SensorIDs {
		lz.Sensors = append(lz.Sensors, s.String())
	}
	slices.Sort(lz.Tenants)
	slices.Sort(lz.Sensors)
	return lz
}

// Repository persists instance scan zones. Only the admin console service
// writes them.
type Repository interface {
	Create(ctx context.Context, z *Zone, by *shared.ID) error
	Update(ctx context.Context, z *Zone) error
	Delete(ctx context.Context, id shared.ID) error
	Get(ctx context.Context, id shared.ID) (*Zone, error)
	List(ctx context.Context) ([]*Zone, error)
	// SetSensors replaces the zone's sensors; a sensor that is not a
	// shared sensor is refused (shared.ErrValidation).
	SetSensors(ctx context.Context, id shared.ID, sensorIDs []shared.ID, by *shared.ID) error
	SetTenants(ctx context.Context, id shared.ID, tenantIDs []shared.ID, by *shared.ID) error
	// ListForTenant lists the zones assigned to the organization, and only
	// those.
	ListForTenant(ctx context.Context, tenantID shared.ID) ([]*Zone, error)
}

// TargetPrefix reads an address or range target (a bare address, a CIDR,
// a URL or host:port whose host is an address) as a prefix; false for a
// name.
func TargetPrefix(target string) (netip.Prefix, bool) {
	t := strings.TrimSpace(target)
	if p, err := netip.ParsePrefix(t); err == nil {
		return p.Masked(), true
	}
	if i := strings.Index(t, "://"); i >= 0 {
		t = t[i+3:]
		if j := strings.IndexAny(t, "/?#"); j >= 0 {
			t = t[:j]
		}
		if k := strings.LastIndex(t, "@"); k >= 0 {
			t = t[k+1:]
		}
	}
	if strings.HasPrefix(t, "[") {
		if j := strings.Index(t, "]"); j > 0 {
			t = t[1:j]
		}
	} else if host, _, found := strings.Cut(t, ":"); found && !strings.Contains(t[len(host)+1:], ":") {
		t = host
	}
	a, err := netip.ParseAddr(t)
	if err != nil || a.Zone() != "" {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(a, a.BitLen()), true
}

// Covering picks the one zone of zones (the organization's assigned zones)
// that contains every target in internal (address or range targets). The
// narrowest containing range wins between overlapping zones; a tie goes to
// the lower id, so the choice is stable. nil when no single zone contains
// them all.
func Covering(zones []*Zone, internal []netip.Prefix) *Zone {
	if len(internal) == 0 {
		return nil
	}
	var best *Zone
	bestBits := -1
	for _, z := range zones {
		narrowest := 129
		ok := true
		for _, p := range internal {
			b := coverBits(z.Ranges, p)
			if b < 0 {
				ok = false
				break
			}
			narrowest = min(narrowest, b)
		}
		if !ok {
			continue
		}
		if narrowest > bestBits || (narrowest == bestBits && z.ID.String() < best.ID.String()) {
			best, bestBits = z, narrowest
		}
	}
	return best
}

// coverBits is the prefix length of the narrowest range in ranges that
// contains all of p, or -1.
func coverBits(ranges []string, p netip.Prefix) int {
	best := -1
	for _, r := range ranges {
		rp, err := netip.ParsePrefix(r)
		if err != nil {
			continue
		}
		if jobsign.ZoneContains([]string{r}, p) && rp.Bits() > best {
			best = rp.Bits()
		}
	}
	return best
}
