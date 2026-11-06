package scan

// Name resolution for jobs bound for shared sensors
// (docs/rfcs/RFC-100-shared-sensors.md §8). The literal check
// (hasInternalTarget) sees only addresses and internal suffixes; a public
// looking name that resolves to a private, loopback, link-local, CGNAT or
// metadata address would otherwise reach a shared sensor, which probes from
// the operator's network. The sensor resolves again right before it
// connects and pins the address it checked, so a name re-bound between the
// two checks is refused there; this check keeps such names off shared
// sensors in the first place.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
)

const (
	// maxSharedNameLookups bounds the names one shared-sensor check
	// resolves; a job with more names stays on the organization's sensors.
	maxSharedNameLookups = 256
	// sharedLookupTimeout bounds one lookup.
	sharedLookupTimeout = 3 * time.Second
	// sharedLookupConcurrency bounds lookups in flight per check.
	sharedLookupConcurrency = 8
)

// errTooManyNames refuses a shared-sensor check with more names than
// maxSharedNameLookups (fail closed: the job stays on own sensors).
var errTooManyNames = fmt.Errorf("more than %d host names to check", maxSharedNameLookups)

// targetNames are the distinct host names among targets: not addresses,
// not ranges, not wildcard selectors (the sensor enumerates those and
// checks every name it finds).
func targetNames(targets []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, t := range targets {
		host := asset.HostOf(t)
		if host == "" || strings.Contains(host, "*") {
			continue
		}
		if _, err := netip.ParseAddr(host); err == nil {
			continue
		}
		if _, err := netip.ParsePrefix(host); err == nil {
			continue
		}
		host = strings.TrimSuffix(strings.ToLower(host), ".")
		if !seen[host] {
			seen[host] = true
			out = append(out, host)
		}
	}
	sort.Strings(out)
	return out
}

// namesResolvingInternal returns the names among targets that resolve to
// any internal address (isInternalAddr, which covers the cloud metadata
// addresses: they are link-local). A name that does not exist is not
// internal; any other lookup failure, a missing resolver or too many names
// is an error (fail closed).
func (s *Service) namesResolvingInternal(ctx context.Context, targets []string) ([]string, error) {
	names := targetNames(targets)
	if len(names) == 0 {
		return nil, nil
	}
	if len(names) > maxSharedNameLookups {
		return nil, errTooManyNames
	}
	if s.zoneResolver == nil {
		return nil, errors.New("no resolver for the shared-sensor name check")
	}
	var (
		mu       sync.Mutex
		internal []string
		firstErr error
		wg       sync.WaitGroup
	)
	sem := make(chan struct{}, sharedLookupConcurrency)
	for _, name := range names {
		wg.Add(1)
		sem <- struct{}{}
		go func(name string) {
			defer wg.Done()
			defer func() { <-sem }()
			lctx, cancel := context.WithTimeout(ctx, sharedLookupTimeout)
			defer cancel()
			addrs, err := s.zoneResolver.LookupNetIP(lctx, "ip", name)
			mu.Lock()
			defer mu.Unlock()
			var dnsErr *net.DNSError
			switch {
			case errors.As(err, &dnsErr) && dnsErr.IsNotFound:
				return
			case err != nil:
				if firstErr == nil {
					firstErr = fmt.Errorf("resolve %s: %w", name, err)
				}
				return
			}
			for _, a := range addrs {
				if isInternalAddr(a) {
					internal = append(internal, name)
					return
				}
			}
		}(name)
	}
	wg.Wait()
	if firstErr != nil {
		return nil, firstErr
	}
	sort.Strings(internal)
	return internal, nil
}
