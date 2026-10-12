package easm

// Certificate Transparency presence of a lookalike domain (RFC-083): how
// many unexpired certificates crt.sh lists for the exact name. Passive: the
// question goes to the CT search service, never to the candidate.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/openctemio/openctem/api/pkg/httpsec"
)

const (
	crtshBase     = "https://crt.sh/"
	crtshMaxBody  = 2 << 20
	crtshTimeout  = 30 * time.Second
	crtshInterval = 2 * time.Second
)

// CrtSh counts certificates through crt.sh with the SSRF-guarded client.
type CrtSh struct {
	client *http.Client
	base   string
	mu     sync.Mutex
	last   time.Time
	wait   time.Duration
}

// NewCrtSh creates the counter.
func NewCrtSh() *CrtSh {
	return &CrtSh{client: httpsec.SafeHTTPClient(crtshTimeout), base: crtshBase, wait: crtshInterval}
}

// CountCerts returns how many unexpired certificates name the domain.
func (c *CrtSh) CountCerts(ctx context.Context, domain string) (int, error) {
	c.mu.Lock()
	if d := c.wait - time.Since(c.last); d > 0 {
		t := time.NewTimer(d)
		select {
		case <-ctx.Done():
			t.Stop()
			c.mu.Unlock()
			return 0, ctx.Err()
		case <-t.C:
		}
	}
	c.last = time.Now()
	c.mu.Unlock()

	q := url.Values{"q": {domain}, "output": {"json"}, "exclude": {"expired"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"?"+q.Encode(), nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("crt.sh: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("crt.sh: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, crtshMaxBody+1))
	if err != nil {
		return 0, fmt.Errorf("crt.sh: %w", err)
	}
	if len(body) > crtshMaxBody {
		return 1000, nil // more certificates than we read: plenty
	}
	var rows []struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(body, &rows); err != nil {
		return 0, fmt.Errorf("crt.sh: %w", err)
	}
	return len(rows), nil
}
