package scanpolicy

// Egress addresses of shared sensors (docs/rfcs/RFC-100-shared-sensors.md §9,
// G11). A shared sensor sends its packets from the operator's addresses, so
// organizations need those addresses to allowlist the scanners in their
// firewalls and intrusion detection. The instance administrator stores them
// in the console, for all regions or per region; organization members read
// them in the shared sensors view.
//
// Threat model: the list is published to every organization that may use
// shared sensors, so it must hold only the operator's public egress
// addresses. Private, loopback, link-local, metadata, CGNAT and other
// internal ranges (ctis addrscope, the one definition the sensors use) are
// refused: they would disclose the operator's internal network and invite
// organizations to allowlist ranges no scanner uses. Only a super admin
// with a fresh authenticator code and a reason changes the list (critical
// admin audit row, the other administrators emailed). Region labels follow
// the sensor region token ([A-Za-z0-9._-], at most 64 characters).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/openctemio/ctis/addrscope"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// SharedSensorsEgressKey is the platform_settings key of the egress list.
const SharedSensorsEgressKey = "shared_sensors_egress"

// ActionSharedSensorsEgressChanged is the admin audit action of a change.
const ActionSharedSensorsEgressChanged = "platform.shared_sensors_egress_changed"

// Limits of the egress list: enough for any real fleet, small enough for a
// card and an audit row.
const (
	MaxEgressRegions          = 32
	MaxEgressAddressesPerList = 64
	maxEgressRegionLen        = 64
)

var egressRegionRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// SharedSensorsEgress is the operator's egress addresses (IP addresses or
// CIDR ranges): Global for every region, Regions per region label.
type SharedSensorsEgress struct {
	Global  []string            `json:"global"`
	Regions map[string][]string `json:"regions"`
}

// Empty reports whether no address is stored.
func (e SharedSensorsEgress) Empty() bool {
	if len(e.Global) > 0 {
		return false
	}
	for _, l := range e.Regions {
		if len(l) > 0 {
			return false
		}
	}
	return true
}

// SharedSensorsEgressStore persists the egress list (platform_settings).
type SharedSensorsEgressStore interface {
	// GetSharedSensorsEgress returns ErrNotFound when nothing is stored.
	GetSharedSensorsEgress(ctx context.Context) (SharedSensorsEgress, int, error)
	SetSharedSensorsEgress(ctx context.Context, v SharedSensorsEgress, expectedVersion int, by string, at time.Time) (int, error)
}

// NormalizeSharedSensorsEgress validates and canonicalizes the list: every
// entry an IP address or CIDR range with no internal address (ctis
// addrscope), host bits cleared, duplicates removed, sorted; region labels
// sensor region tokens; empty regions dropped. The error names the first
// bad entry.
func NormalizeSharedSensorsEgress(in SharedSensorsEgress) (SharedSensorsEgress, error) {
	out := SharedSensorsEgress{Global: []string{}, Regions: map[string][]string{}}
	g, err := normalizeEgressList(in.Global)
	if err != nil {
		return SharedSensorsEgress{}, err
	}
	out.Global = g
	if len(in.Regions) > MaxEgressRegions {
		return SharedSensorsEgress{}, fmt.Errorf("%w: at most %d regions", shared.ErrValidation, MaxEgressRegions)
	}
	for region, list := range in.Regions {
		if len(region) > maxEgressRegionLen || !egressRegionRe.MatchString(region) {
			return SharedSensorsEgress{}, fmt.Errorf("%w: region %q: use letters, digits, '.', '_' or '-' (at most %d characters)",
				shared.ErrValidation, truncate(region, maxEgressRegionLen), maxEgressRegionLen)
		}
		l, err := normalizeEgressList(list)
		if err != nil {
			return SharedSensorsEgress{}, fmt.Errorf("region %s: %w", region, err)
		}
		if len(l) > 0 {
			out.Regions[region] = l
		}
	}
	return out, nil
}

func normalizeEgressList(in []string) ([]string, error) {
	if len(in) > MaxEgressAddressesPerList {
		return nil, fmt.Errorf("%w: at most %d addresses per list", shared.ErrValidation, MaxEgressAddressesPerList)
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, raw := range in {
		v, err := normalizeEgressEntry(raw)
		if err != nil {
			return nil, err
		}
		if _, dup := seen[v]; dup {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out, nil
}

// normalizeEgressEntry accepts a public IP address or CIDR range.
func normalizeEgressEntry(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", fmt.Errorf("%w: an empty address", shared.ErrValidation)
	}
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil || p.Addr().Zone() != "" {
			return "", fmt.Errorf("%w: %q is not an IP address or CIDR range", shared.ErrValidation, truncate(s, 64))
		}
		p = p.Masked()
		if addrscope.IsInternalPrefix(p) {
			return "", fmt.Errorf("%w: %s holds private or internal addresses; list public egress addresses only", shared.ErrValidation, p)
		}
		if p.Addr().Is4() && p.Bits() == 32 || p.Addr().Is6() && p.Bits() == 128 {
			return p.Addr().String(), nil
		}
		return p.String(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return "", fmt.Errorf("%w: %q is not an IP address or CIDR range", shared.ErrValidation, truncate(s, 64))
	}
	a = a.Unmap()
	if addrscope.IsInternal(a) {
		return "", fmt.Errorf("%w: %s is a private or internal address; list public egress addresses only", shared.ErrValidation, a)
	}
	return a.String(), nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func (s *Service) egressStore() (SharedSensorsEgressStore, error) {
	st, ok := s.repo.(SharedSensorsEgressStore)
	if !ok || st == nil {
		return nil, errors.New("the shared sensor egress store is not wired")
	}
	return st, nil
}

// SharedSensorsEgress returns the egress list and its version (0: nothing
// stored, the list is empty).
func (s *Service) SharedSensorsEgress(ctx context.Context) (SharedSensorsEgress, int, error) {
	st, err := s.egressStore()
	if err != nil {
		return SharedSensorsEgress{}, 0, err
	}
	v, ver, err := st.GetSharedSensorsEgress(ctx)
	if errors.Is(err, ErrNotFound) {
		return SharedSensorsEgress{Global: []string{}, Regions: map[string][]string{}}, 0, nil
	}
	if err != nil {
		return SharedSensorsEgress{}, 0, err
	}
	if v.Global == nil {
		v.Global = []string{}
	}
	if v.Regions == nil {
		v.Regions = map[string][]string{}
	}
	return v, ver, nil
}

// UpdateSharedSensorsEgress validates and stores the egress list. The caller
// checked super_admin and a fresh authenticator code. It returns the stored
// (normalized) list and its new version.
func (s *Service) UpdateSharedSensorsEgress(ctx context.Context, next SharedSensorsEgress, expectedVersion int, c Change) (SharedSensorsEgress, int, error) {
	if err := c.check(); err != nil {
		return SharedSensorsEgress{}, 0, err
	}
	norm, err := NormalizeSharedSensorsEgress(next)
	if err != nil {
		return SharedSensorsEgress{}, 0, err
	}
	st, err := s.egressStore()
	if err != nil {
		return SharedSensorsEgress{}, 0, err
	}
	prev, _, err := s.SharedSensorsEgress(ctx)
	if err != nil {
		return SharedSensorsEgress{}, 0, err
	}
	v, err := st.SetSharedSensorsEgress(ctx, norm, expectedVersion, c.Actor.ID().String(), time.Now().UTC())
	if err != nil {
		return SharedSensorsEgress{}, 0, err
	}
	from, to := egressText(prev), egressText(norm)
	s.recordKey(ctx, c, ActionSharedSensorsEgressChanged, SharedSensorsEgressKey, from, to)
	s.mailOthers(ctx, c, "[Scans] Shared sensor egress addresses changed",
		fmt.Sprintf("%s changed the egress addresses organizations see for shared sensors from %s to %s. Reason: %s",
			c.Actor.Email(), from, to, strings.TrimSpace(c.Reason)))
	return norm, v, nil
}

func egressText(v SharedSensorsEgress) string {
	b, _ := json.Marshal(v)
	return string(b)
}
