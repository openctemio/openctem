package certmonitor

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Names of the CT sources, recorded per domain in ct_monitor_state.last_source.
const (
	SourceCRTSH       = "crt.sh"
	SourceCertSpotter = "certspotter"
)

const (
	// DefaultCertSpotterBaseURL is SSLMate's Cert Spotter API. Its free tier
	// answers a limited number of unauthenticated queries per hour, which is
	// why it is only the fallback when crt.sh fails (RFC-036 O1).
	DefaultCertSpotterBaseURL = "https://api.certspotter.com"

	// crtshAttempts is how many times one domain is tried against crt.sh
	// before falling back. crt.sh answers 502/503 under load and recovers
	// within seconds to minutes.
	crtshAttempts = 3

	// retryBase and retryCap bound the exponential back-off between attempts;
	// each wait gets up to 100% jitter so parallel API replicas never retry in
	// lock-step.
	retryBase = 2 * time.Second
	retryCap  = 30 * time.Second

	// maxRetryAfter caps a server-sent Retry-After we are willing to sleep.
	maxRetryAfter = 60 * time.Second

	// certSpotterMaxPages bounds the issuance pages read for one domain. Each
	// page is up to a few hundred certificates.
	certSpotterMaxPages = 10
)

// errNotRetryable marks an answer that a retry cannot fix (4xx other than 429,
// a body that is not JSON).
var errNotRetryable = errors.New("not retryable")

// errRateLimited marks a 429 from a source: the rest of the run skips it.
var errRateLimited = errors.New("rate limited")

// statusError is a non-200 answer from a CT source.
type statusError struct {
	source     string
	status     int
	retryAfter time.Duration
}

// ErrResponseTooLarge: a CT source sent more than the body cap. Nothing from
// that response is used.
var ErrResponseTooLarge = errors.New("CT response too large")

func (e *statusError) Error() string {
	return fmt.Sprintf("%s returned status %d", e.source, e.status)
}

func (e *statusError) Is(target error) bool {
	switch target {
	case errRateLimited:
		return e.status == http.StatusTooManyRequests
	case errNotRetryable:
		return e.status >= 400 && e.status < 500 && e.status != http.StatusTooManyRequests && e.status != http.StatusRequestTimeout
	}
	return false
}

// fetchResult is what one domain query produced.
type fetchResult struct {
	entries []crtEntry
	source  string
}

// sweepClient queries CT for the domains of one sweep. It remembers, for the
// length of the sweep, that a source answered 429 so it stops asking it.
type sweepClient struct {
	s                  *Service
	certSpotterLimited bool
}

// fetch queries crt.sh with retries, then Cert Spotter when crt.sh is still
// failing. It returns the error of the last source tried when both fail.
func (c *sweepClient) fetch(ctx context.Context, domain string) (fetchResult, error) {
	entries, crtErr := c.fetchCRTSH(ctx, domain)
	if crtErr == nil {
		return fetchResult{entries: entries, source: SourceCRTSH}, nil
	}
	if ctx.Err() != nil {
		return fetchResult{}, ctx.Err()
	}
	if c.s.certSpotterBaseURL == "" || c.certSpotterLimited {
		return fetchResult{}, crtErr
	}
	entries, csErr := c.s.queryCertSpotter(ctx, domain)
	if csErr == nil {
		c.s.logger.Info("crt.sh failed; used Cert Spotter instead",
			"domain", domain, "crtsh_error", crtErr.Error())
		return fetchResult{entries: entries, source: SourceCertSpotter}, nil
	}
	if errors.Is(csErr, errRateLimited) {
		c.certSpotterLimited = true
	}
	return fetchResult{}, fmt.Errorf("crt.sh: %w; certspotter: %w", crtErr, csErr)
}

// fetchCRTSH is queryCRTSH with up to crtshAttempts tries on retryable errors.
func (c *sweepClient) fetchCRTSH(ctx context.Context, domain string) ([]crtEntry, error) {
	var lastErr error
	for attempt := 0; attempt < crtshAttempts; attempt++ {
		if attempt > 0 {
			if err := c.s.sleep(ctx, retryDelay(attempt, lastErr)); err != nil {
				return nil, err
			}
		}
		entries, err := c.s.queryCRTSH(ctx, domain)
		if err == nil {
			return entries, nil
		}
		lastErr = err
		if errors.Is(err, errNotRetryable) || ctx.Err() != nil {
			break
		}
	}
	return nil, lastErr
}

// retryDelay is the wait before attempt n (n ≥ 1): base·2^(n-1) with full
// jitter, capped, or the server's Retry-After when it sent a usable one.
func retryDelay(attempt int, lastErr error) time.Duration {
	var se *statusError
	if errors.As(lastErr, &se) && se.retryAfter > 0 {
		return min(se.retryAfter, maxRetryAfter)
	}
	d := retryBase << (attempt - 1)
	if d > retryCap {
		d = retryCap
	}
	// Jitter in [d/2, d].
	return d/2 + jitter(d/2)
}

// jitter returns a uniformly random duration in [0, max]. It reads
// crypto/rand: the value only spreads retries, but one random source for the
// codebase keeps the weak-random ban simple. If the system source fails, the
// wait is the full max, which is still a valid back-off.
func jitter(maxD time.Duration) time.Duration {
	if maxD <= 0 {
		return 0
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(maxD)+1))
	if err != nil {
		return maxD
	}
	return time.Duration(n.Int64())
}

// parseRetryAfter reads a Retry-After header given in seconds. The HTTP-date
// form is ignored (crt.sh and Cert Spotter send seconds).
func parseRetryAfter(h string) time.Duration {
	h = strings.TrimSpace(h)
	if h == "" {
		return 0
	}
	n, err := strconv.Atoi(h)
	if err != nil || n <= 0 {
		return 0
	}
	return time.Duration(n) * time.Second
}

// sleep waits d or until ctx is done. Tests set noSleep.
func (s *Service) sleep(ctx context.Context, d time.Duration) error {
	if s.noSleep || d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// certSpotterIssuance is one record of Cert Spotter's /v1/issuances answer
// with expand=dns_names and expand=issuer.
type certSpotterIssuance struct {
	ID        string   `json:"id"`
	DNSNames  []string `json:"dns_names"`
	NotBefore string   `json:"not_before"`
	NotAfter  string   `json:"not_after"`
	Issuer    struct {
		FriendlyName string `json:"friendly_name"`
		Name         string `json:"name"`
	} `json:"issuer"`
	CertSHA256 string `json:"cert_sha256"`
}

// queryCertSpotter fetches the unexpired issuances for domain and its
// subdomains from Cert Spotter and maps them onto the crt.sh entry shape, so
// the rest of the sweep does not care which source answered. Cert Spotter only
// lists unexpired certificates, so a domain served from this fallback never
// raises certificate_expired.
func (s *Service) queryCertSpotter(ctx context.Context, domain string) ([]crtEntry, error) {
	base, err := url.Parse(s.certSpotterBaseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid Cert Spotter base URL: %w", err)
	}
	base.Path = "/v1/issuances"

	var out []crtEntry
	after := ""
	for page := 0; page < certSpotterMaxPages; page++ {
		q := url.Values{}
		q.Set("domain", domain)
		q.Set("include_subdomains", "true")
		q.Add("expand", "dns_names")
		q.Add("expand", "issuer")
		if after != "" {
			q.Set("after", after)
		}
		u := *base
		u.RawQuery = q.Encode()

		body, err := s.get(ctx, u.String(), SourceCertSpotter)
		if err != nil {
			return nil, err
		}
		var items []certSpotterIssuance
		if err := json.Unmarshal(body, &items); err != nil {
			return nil, fmt.Errorf("failed to parse Cert Spotter JSON: %w: %w", errNotRetryable, err)
		}
		if len(items) == 0 {
			break
		}
		for _, it := range items {
			issuer := it.Issuer.FriendlyName
			if issuer == "" {
				issuer = it.Issuer.Name
			}
			out = append(out, crtEntry{
				NameValue:    strings.Join(it.DNSNames, "\n"),
				NotBefore:    it.NotBefore,
				NotAfter:     it.NotAfter,
				IssuerName:   issuer,
				SerialNumber: it.CertSHA256,
			})
		}
		after = items[len(items)-1].ID
		if after == "" {
			break
		}
	}
	return out, nil
}

// get performs one bounded GET against a CT source and returns the body of a
// 200 answer; any other status is a *statusError.
func (s *Service) get(ctx context.Context, rawURL, source string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build %s request: %w", source, err)
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s request failed: %w", source, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		return nil, &statusError{source: source, status: resp.StatusCode, retryAfter: parseRetryAfter(resp.Header.Get("Retry-After"))}
	}
	limit := s.maxBody
	if limit <= 0 {
		limit = maxBodyBytes
	}
	// Read one byte past the cap: a body that reaches it is refused as a
	// whole instead of being cut into truncated JSON (RFC-036 appendix T-4).
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read %s response: %w", source, err)
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("%w: %s response exceeds %d bytes", ErrResponseTooLarge, source, limit)
	}
	return body, nil
}
