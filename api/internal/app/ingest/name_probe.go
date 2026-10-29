package ingest

// Telling a name that does not resolve from one that resolves only through
// a wildcard record. A filtered resolver reports neither, so a name it left
// out proves nothing by itself. The platform asks DNS itself: no answer is a
// name that does not resolve (not_resolving); an answer is wildcard-only
// only when a random label under one of the name's parent zones resolves to
// an address the name shares (the probe the resolver's own wildcard filter
// uses). Anything uncertain (a resolver error, a timeout) changes nothing.
//
// Threat model: the names are the tenant's own assets; the lookups are plain
// DNS queries from the API host through the configured resolver, bounded in
// count, time and concurrency. The answers never leave the process.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// NameClass is what the probe found out about a name.
type NameClass int

// Classes.
const (
	// NameUnknown: the probe could not tell (resolver error, timeout).
	NameUnknown NameClass = iota
	// NameNoAnswer: DNS has no answer for the name (NXDOMAIN, no address).
	NameNoAnswer
	// NameResolves: the name resolves by itself.
	NameResolves
	// NameWildcardOnly: the name resolves only through a wildcard record of
	// a parent zone.
	NameWildcardOnly
)

// NameProber classifies a host name by asking DNS.
type NameProber interface {
	Probe(ctx context.Context, name string) NameClass
}

// DNSLookup is the resolver the probe asks (*net.Resolver satisfies it).
type DNSLookup interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Bounds of one probe round.
const (
	probeTimeout     = 4 * time.Second
	probeConcurrency = 16
	// MaxProbedNames bounds the names probed for one resolution job.
	MaxProbedNames = 2000
	maxProbeLevels = 6
)

type dnsNameProber struct{ r DNSLookup }

// NewDNSNameProber builds a prober over the resolver.
func NewDNSNameProber(r DNSLookup) NameProber {
	if r == nil {
		return nil
	}
	return dnsNameProber{r: r}
}

// notFound reports whether err is DNS saying the name does not exist.
func notFound(err error) bool {
	var de *net.DNSError
	return errors.As(err, &de) && de.IsNotFound
}

func (p dnsNameProber) lookup(ctx context.Context, name string) ([]netip.Addr, error) {
	c, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	return p.r.LookupNetIP(c, "ip", name)
}

func randomLabel() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "oc-" + hex.EncodeToString(b)
}

// Probe classifies name.
func (p dnsNameProber) Probe(ctx context.Context, name string) NameClass {
	addrs, err := p.lookup(ctx, name)
	if err != nil {
		if notFound(err) {
			return NameNoAnswer
		}
		return NameUnknown
	}
	if len(addrs) == 0 {
		return NameNoAnswer
	}
	own := map[netip.Addr]bool{}
	for _, a := range addrs {
		own[a.Unmap()] = true
	}
	labels := strings.Split(name, ".")
	// Parent zones with at least two labels, nearest first.
	for i := 1; i < len(labels)-1 && i <= maxProbeLevels; i++ {
		zone := strings.Join(labels[i:], ".")
		got, err := p.lookup(ctx, randomLabel()+"."+zone)
		if err != nil {
			continue
		}
		for _, a := range got {
			if own[a.Unmap()] {
				return NameWildcardOnly
			}
		}
	}
	return NameResolves
}

// probeNames classifies the names (at most MaxProbedNames; the rest stay
// unknown) with bounded concurrency.
func probeNames(ctx context.Context, p NameProber, names []string) map[string]NameClass {
	out := make(map[string]NameClass, len(names))
	if len(names) > MaxProbedNames {
		names = names[:MaxProbedNames]
	}
	var (
		mu  sync.Mutex
		wg  sync.WaitGroup
		sem = make(chan struct{}, probeConcurrency)
	)
	for _, n := range names {
		sem <- struct{}{}
		wg.Add(1)
		go func(n string) {
			defer wg.Done()
			defer func() { <-sem }()
			c := p.Probe(ctx, n)
			mu.Lock()
			out[n] = c
			mu.Unlock()
		}(n)
	}
	wg.Wait()
	return out
}
