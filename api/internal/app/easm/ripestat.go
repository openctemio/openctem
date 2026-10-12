package easm

// RIPEstat client for network seeds (docs/rfcs/RFC-082-network-seeds.md):
// public routing data, no key, fetched through the SSRF-guarded client from
// one fixed host. Responses are untrusted: size-capped, strictly decoded,
// every value validated before it is stored.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/openctemio/openctem/api/pkg/domain/easmseed"
	"github.com/openctemio/openctem/api/pkg/httpsec"
)

const (
	ripestatBase      = "https://stat.ripe.net/data/"
	ripestatSourceApp = "openctem"
	ripestatMaxBody   = 4 << 20
	ripestatTimeout   = 20 * time.Second
	// ripestatInterval spaces requests from this process (politeness).
	ripestatInterval = time.Second
)

// RIPEstat answers the network questions of the seeds.
type RIPEstat struct {
	client *http.Client
	base   string
	mu     sync.Mutex
	last   time.Time
	wait   time.Duration
}

// NewRIPEstat creates the client with the SSRF-guarded transport.
func NewRIPEstat() *RIPEstat {
	return &RIPEstat{client: httpsec.SafeHTTPClient(ripestatTimeout), base: ripestatBase, wait: ripestatInterval}
}

// newRIPEstatForTest points the client at a test server without the guard or
// the politeness delay.
func newRIPEstatForTest(client *http.Client, base string) *RIPEstat {
	return &RIPEstat{client: client, base: base}
}

func (c *RIPEstat) pace(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if d := c.wait - time.Since(c.last); d > 0 {
		t := time.NewTimer(d)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
	}
	c.last = time.Now()
	return nil
}

func (c *RIPEstat) get(ctx context.Context, call, resource string, out any) error {
	if err := c.pace(ctx); err != nil {
		return err
	}
	q := url.Values{"resource": {resource}, "sourceapp": {ripestatSourceApp}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+call+"/data.json?"+q.Encode(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("ripestat %s: %w", call, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ripestat %s: HTTP %d", call, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, ripestatMaxBody+1))
	if err != nil {
		return fmt.Errorf("ripestat %s: %w", call, err)
	}
	if len(body) > ripestatMaxBody {
		return fmt.Errorf("ripestat %s: response too large", call)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("ripestat %s: %w", call, err)
	}
	return nil
}

// ASNHolder returns the registered holder of an AS number.
func (c *RIPEstat) ASNHolder(ctx context.Context, asn string) (string, error) {
	var r struct {
		Data struct {
			Holder string `json:"holder"`
		} `json:"data"`
	}
	if err := c.get(ctx, "as-overview", asn, &r); err != nil {
		return "", err
	}
	return cleanText(r.Data.Holder, 300), nil
}

// AnnouncedPrefixes returns the prefixes an AS number announces, canonical,
// de-duplicated, at most easmseed.MaxPrefixesPerSeed.
func (c *RIPEstat) AnnouncedPrefixes(ctx context.Context, asn string) ([]string, error) {
	var r struct {
		Data struct {
			Prefixes []struct {
				Prefix string `json:"prefix"`
			} `json:"prefixes"`
		} `json:"data"`
	}
	if err := c.get(ctx, "announced-prefixes", asn, &r); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	out := []string{}
	for _, p := range r.Data.Prefixes {
		pfx, err := netip.ParsePrefix(strings.TrimSpace(p.Prefix))
		if err != nil {
			continue
		}
		s := pfx.Masked().String()
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
		if len(out) >= easmseed.MaxPrefixesPerSeed {
			break
		}
	}
	return out, nil
}

// SearchASNs returns AS numbers whose registration matches an organization
// name, at most easmseed.MaxSuggestionsPerOrg.
func (c *RIPEstat) SearchASNs(ctx context.Context, org string) ([]easmseed.ASNSuggestion, error) {
	var r struct {
		Data struct {
			Categories []struct {
				Category    string `json:"category"`
				Suggestions []struct {
					Value       string `json:"value"`
					Description string `json:"description"`
				} `json:"suggestions"`
			} `json:"categories"`
		} `json:"data"`
	}
	if err := c.get(ctx, "searchcomplete", org, &r); err != nil {
		return nil, err
	}
	out := []easmseed.ASNSuggestion{}
	for _, cat := range r.Data.Categories {
		if cat.Category != "ASNs" {
			continue
		}
		for _, s := range cat.Suggestions {
			asn, err := easmseed.NormalizeASN(s.Value)
			if err != nil {
				continue
			}
			out = append(out, easmseed.ASNSuggestion{ASN: asn, Description: cleanText(s.Description, 200)})
			if len(out) >= easmseed.MaxSuggestionsPerOrg {
				return out, nil
			}
		}
	}
	return out, nil
}

// cleanText keeps valid single-line text of at most n bytes.
func cleanText(s string, n int) string {
	s = strings.ToValidUTF8(s, "")
	s = strings.Join(strings.FieldsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f }), " ")
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
