package scanzone

import (
	"fmt"
	"net/netip"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// lanRanges are the private networks a sensor scans once its host allows
// private targets (SENSOR_ALLOW_PRIVATE_TARGETS=1): RFC 1918 and IPv6
// unique-local. Carrier-grade NAT (100.64.0.0/10) is left out on purpose:
// the sensor refuses it whatever its host allows.
var lanRanges = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("fc00::/7"),
}

// WithinLAN reports whether every address of p lies in one private network
// (RFC 1918 or IPv6 unique-local).
func WithinLAN(p netip.Prefix) bool {
	p = unmapPrefix(p).Masked()
	for _, q := range lanRanges {
		if q.Bits() <= p.Bits() && q.Contains(p.Addr()) {
			return true
		}
	}
	return false
}

// ParseLANRanges parses ranges like ParseRanges and also refuses any range
// that is not wholly inside a private network. It is what the console asks
// for when a person states the internal networks a sensor scans: the
// networks of a sensor's own host, never public space.
func ParseLANRanges(in []string) ([]netip.Prefix, error) {
	if len(in) == 0 {
		return nil, fmt.Errorf("%w: list at least one network", shared.ErrValidation)
	}
	ps, err := ParseRanges(in)
	if err != nil {
		return nil, err
	}
	for _, p := range ps {
		if !WithinLAN(p) {
			return nil, fmt.Errorf("%w: range %s is not a private network (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 or fc00::/7)",
				shared.ErrValidation, p)
		}
	}
	return ps, nil
}
