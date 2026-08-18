// Package certmonitor implements OpenCTEM's Certificate-Transparency (CT)
// discovery source: a scheduled, per-tenant poller that queries the PUBLIC
// crt.sh CT-log aggregator for the tenant's own registered domains and emits
// first-class ExposureEvents.
//
// This is CTEM Discovery breadth ("exposure != vulnerability") that needs no
// credentials, no agent, and no customer consent — it reads only public CT-log
// data. It complements the agent-side subfinder recon (which enumerates
// subdomains on demand during a scan job): CT monitoring runs continuously
// server-side and, crucially, surfaces cert-expiry exposures and certs issued
// for domains the tenant never scanned. See docs/rfcs/RFC-019.
//
// The outbound query goes through httpsec.SafeHTTPClient (SSRF-guarded: it
// refuses RFC1918 / link-local addresses even though crt.sh is public — defense
// against DNS rebinding of the configurable feed URL), is body-bounded, and is
// politeness-rate-limited between domains so we never hammer crt.sh.
//
// Tenant isolation: the tenant is taken from the asset being queried, never from
// the CT response. Every emitted exposure is stamped with that tenant. A failure
// on one domain or one tenant is logged and skipped (fail-open); it never
// aborts the whole sweep.
package certmonitor

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	assetdom "github.com/openctemio/api/pkg/domain/asset"
	exposuredom "github.com/openctemio/api/pkg/domain/exposure"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/httpsec"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

const (
	// DefaultFeedBaseURL is the public crt.sh CT-log aggregator. No auth.
	DefaultFeedBaseURL = "https://crt.sh"

	// Source is the exposure source tag for everything this connector emits.
	Source = "cert_transparency"

	// httpTimeout bounds a single crt.sh query. crt.sh can be slow for busy
	// domains, so this is generous.
	httpTimeout = 45 * time.Second

	// maxBodyBytes bounds a single crt.sh JSON response.
	maxBodyBytes = 48 << 20 // 48 MiB

	// userAgent identifies OpenCTEM to crt.sh.
	userAgent = "OpenCTEM/1.0 (+https://github.com/openctemio)"

	// defaultMaxDomainsPerRun caps how many of a tenant's domain assets we query
	// per sweep, so a tenant with thousands of domains cannot make us hammer
	// crt.sh. When a tenant has more, the overflow is logged and picked up on a
	// later run (ordering is stable by asset name).
	defaultMaxDomainsPerRun = 50

	// defaultMaxSubdomainsPerDomain caps subdomain_discovered exposures emitted
	// for a single domain in one run (a wildcard/CDN domain can have thousands of
	// CT entries).
	defaultMaxSubdomainsPerDomain = 500

	// defaultExpiryWindow is how soon a cert must expire to raise a
	// certificate_expiring exposure.
	defaultExpiryWindow = 30 * 24 * time.Hour

	// defaultRequestDelay is the politeness delay between crt.sh queries within a
	// single tenant sweep.
	defaultRequestDelay = 1 * time.Second

	// assetPageSize is how many domain assets we page per DB round-trip.
	assetPageSize = 200
)

// AssetLister is the narrow slice of the asset repository the CT sweep needs:
// paginated listing of a tenant's domain assets. Satisfied by
// *postgres.AssetRepository.
type AssetLister interface {
	List(ctx context.Context, filter assetdom.Filter, opts assetdom.ListOptions, page pagination.Pagination) (pagination.Result[*assetdom.Asset], error)
}

// ExposureUpserter is the narrow slice of the exposure repository the CT sweep
// needs: fingerprint-deduped batch upsert. Satisfied by
// *postgres.ExposureRepository.
type ExposureUpserter interface {
	BulkUpsert(ctx context.Context, events []*exposuredom.ExposureEvent) error
}

// Service is the CT discovery source.
type Service struct {
	assetRepo    AssetLister
	exposureRepo ExposureUpserter
	httpClient   *http.Client
	feedBaseURL  string

	maxDomains   int
	maxSubs      int
	expiryWindow time.Duration
	requestDelay time.Duration

	logger *logger.Logger
}

// NewService constructs the CT discovery service. An empty feedBaseURL defaults
// to crt.sh.
func NewService(
	assetRepo AssetLister,
	exposureRepo ExposureUpserter,
	feedBaseURL string,
	log *logger.Logger,
) *Service {
	if strings.TrimSpace(feedBaseURL) == "" {
		feedBaseURL = DefaultFeedBaseURL
	}
	return &Service{
		assetRepo:    assetRepo,
		exposureRepo: exposureRepo,
		httpClient:   httpsec.SafeHTTPClient(httpTimeout),
		feedBaseURL:  strings.TrimRight(feedBaseURL, "/"),
		maxDomains:   defaultMaxDomainsPerRun,
		maxSubs:      defaultMaxSubdomainsPerDomain,
		expiryWindow: defaultExpiryWindow,
		requestDelay: defaultRequestDelay,
		logger:       log.With("service", "cert_monitor"),
	}
}

// FeedBaseURL returns the configured crt.sh base URL (for diagnostics).
func (s *Service) FeedBaseURL() string { return s.feedBaseURL }

// setHTTPClient overrides the outbound client and disables the politeness delay.
// Test-only: production always uses the SSRF-guarded SafeHTTPClient built in
// NewService, which (correctly) refuses the loopback address an httptest server
// listens on.
func (s *Service) setHTTPClient(c *http.Client) {
	s.httpClient = c
	s.requestDelay = 0
}

// MonitorTenant runs one CT sweep for a single tenant: it lists the tenant's
// domain assets, queries crt.sh for each (bounded + rate-limited), and upserts
// the resulting ExposureEvents (deduped by fingerprint). Returns the number of
// exposures emitted (created or re-sighted). Fail-open per domain: a crt.sh
// error on one domain is logged and the sweep continues.
func (s *Service) MonitorTenant(ctx context.Context, tenantID shared.ID) (int, error) {
	if s == nil || s.assetRepo == nil || s.exposureRepo == nil {
		return 0, nil
	}
	if tenantID.IsZero() {
		return 0, fmt.Errorf("%w: tenant ID is required", shared.ErrValidation)
	}

	domains, capped, err := s.listDomains(ctx, tenantID)
	if err != nil {
		return 0, fmt.Errorf("failed to list domain assets: %w", err)
	}
	if capped {
		s.logger.Warn("tenant has more domains than the per-run cap; remainder deferred to next sweep",
			"tenant_id", tenantID.String(), "cap", s.maxDomains)
	}
	if len(domains) == 0 {
		return 0, nil
	}

	var events []*exposuredom.ExposureEvent
	for i, da := range domains {
		if err := ctx.Err(); err != nil {
			return len(events), err
		}
		// Politeness delay between crt.sh queries (not before the first one).
		if i > 0 && s.requestDelay > 0 {
			select {
			case <-ctx.Done():
				return len(events), ctx.Err()
			case <-time.After(s.requestDelay):
			}
		}

		entries, err := s.queryCRTSH(ctx, da.name)
		if err != nil {
			// Fail-open: one domain's crt.sh outage must not abort the sweep.
			s.logger.Warn("crt.sh query failed; skipping domain",
				"tenant_id", tenantID.String(), "domain", da.name, "error", err)
			continue
		}

		subs, expiring := collectDiscoveries(da.name, entries, time.Now().UTC(), s.expiryWindow, s.maxSubs)
		events = append(events, s.buildEvents(tenantID, da, subs, expiring)...)
	}

	if len(events) == 0 {
		return 0, nil
	}
	if err := s.exposureRepo.BulkUpsert(ctx, events); err != nil {
		return 0, fmt.Errorf("failed to upsert CT exposures: %w", err)
	}

	s.logger.Info("ct sweep complete",
		"tenant_id", tenantID.String(),
		"domains", len(domains),
		"exposures", len(events))
	return len(events), nil
}

// domainAsset is the minimal projection of a domain asset the sweep needs.
type domainAsset struct {
	id   shared.ID
	name string
}

// listDomains returns the tenant's domain-type assets (up to the per-run cap).
// The bool reports whether the cap truncated the list.
func (s *Service) listDomains(ctx context.Context, tenantID shared.ID) ([]domainAsset, bool, error) {
	filter := assetdom.NewFilter().
		WithTenantID(tenantID.String()).
		WithTypes(assetdom.AssetTypeDomain)

	out := make([]domainAsset, 0, s.maxDomains)
	for pageNum := 1; ; pageNum++ {
		page := pagination.New(pageNum, assetPageSize)
		res, err := s.assetRepo.List(ctx, filter, assetdom.NewListOptions(), page)
		if err != nil {
			return nil, false, err
		}
		if len(res.Data) == 0 {
			break
		}
		for _, a := range res.Data {
			name := normalizeDomain(a.Name())
			if name == "" {
				continue
			}
			out = append(out, domainAsset{id: a.ID(), name: name})
			if len(out) >= s.maxDomains {
				// Truncated only if there is more data beyond what we collected.
				more := len(res.Data) > 0 && res.Total > int64(len(out))
				return out, more, nil
			}
		}
		if int64(pageNum*assetPageSize) >= res.Total {
			break
		}
	}
	return out, false, nil
}

// buildEvents converts the pure discovery results into ExposureEvents for the
// given tenant/domain. Events that fail construction are skipped (defensive;
// inputs are already validated).
func (s *Service) buildEvents(tenantID shared.ID, da domainAsset, subs []string, expiring []expiringCert) []*exposuredom.ExposureEvent {
	events := make([]*exposuredom.ExposureEvent, 0, len(subs)+len(expiring))
	assetID := da.id

	for _, host := range subs {
		ev, err := exposuredom.NewExposureEvent(
			tenantID,
			exposuredom.EventTypeSubdomainDiscovered,
			exposuredom.SeverityInfo,
			fmt.Sprintf("Subdomain seen in Certificate Transparency: %s", host),
			Source,
			map[string]any{
				"domain":           host,
				"parent_domain":    da.name,
				"discovery_source": Source,
			},
		)
		if err != nil {
			continue
		}
		ev.UpdateDescription(fmt.Sprintf(
			"A TLS certificate for %q (under your monitored domain %q) was found in public Certificate Transparency logs. "+
				"Confirm this host is known and intended to be internet-facing.", host, da.name))
		id := assetID
		ev.SetAssetID(&id)
		events = append(events, ev)
	}

	for _, ec := range expiring {
		ev, err := exposuredom.NewExposureEvent(
			tenantID,
			exposuredom.EventTypeCertificateExpiring,
			expirySeverity(ec.DaysLeft),
			fmt.Sprintf("TLS certificate expiring soon: %s", ec.Host),
			Source,
			map[string]any{
				"domain":         ec.Host,
				"parent_domain":  da.name,
				"not_after":      ec.NotAfter.Format(time.RFC3339),
				"days_remaining": ec.DaysLeft,
				"issuer":         ec.Issuer,
				"serial_number":  ec.Serial,
			},
		)
		if err != nil {
			continue
		}
		ev.UpdateDescription(fmt.Sprintf(
			"The most recent public TLS certificate for %q expires on %s (%d day(s) away). "+
				"An expired certificate breaks TLS for this host — renew before it lapses.",
			ec.Host, ec.NotAfter.Format("2006-01-02"), ec.DaysLeft))
		id := assetID
		ev.SetAssetID(&id)
		events = append(events, ev)
	}

	return events
}

// queryCRTSH fetches and parses crt.sh JSON for one domain.
func (s *Service) queryCRTSH(ctx context.Context, domain string) ([]crtEntry, error) {
	u, err := url.Parse(s.feedBaseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid feed base URL: %w", err)
	}
	u.Path = "/"
	q := url.Values{}
	// "%.<domain>" is a SQL-LIKE wildcard: match the domain and every subdomain.
	// url.Values.Encode percent-encodes the leading '%' to %25 as crt.sh expects.
	q.Set("q", "%."+domain)
	q.Set("output", "json")
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build crt.sh request: %w", err)
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("crt.sh request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crt.sh returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to read crt.sh response: %w", err)
	}
	return parseCRTSH(body)
}

// crtEntry is one certificate record from crt.sh's JSON output.
type crtEntry struct {
	CommonName   string `json:"common_name"`
	NameValue    string `json:"name_value"`
	NotBefore    string `json:"not_before"`
	NotAfter     string `json:"not_after"`
	IssuerName   string `json:"issuer_name"`
	SerialNumber string `json:"serial_number"`
}

// parseCRTSH parses crt.sh JSON output. It is pure (no I/O) so the (quirky)
// crt.sh response shape is unit-testable without the SSRF-guarded HTTP client.
// crt.sh returns a bare JSON array; malformed individual entries are skipped
// rather than failing the whole parse.
func parseCRTSH(body []byte) ([]crtEntry, error) {
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return nil, nil
	}
	var entries []crtEntry
	if err := json.Unmarshal([]byte(trimmed), &entries); err != nil {
		return nil, fmt.Errorf("failed to parse crt.sh JSON: %w", err)
	}
	return entries, nil
}

// expiringCert is a host whose most-recent CT certificate expires within the
// window.
type expiringCert struct {
	Host     string
	NotAfter time.Time
	DaysLeft int
	Issuer   string
	Serial   string
}

// collectDiscoveries is the pure core: from the crt.sh entries for a domain it
// derives (a) the set of distinct subdomains observed and (b) the hosts whose
// most-recent certificate expires within the window.
//
// Expiry uses the MAX not_after per host so a long tail of historical/expired
// certs never raises a false "expiring" alert when the host actually has a
// current cert — and a host whose newest cert already lapsed is treated as
// "expired, not expiring" and dropped (avoids flooding on long-dead hosts).
func collectDiscoveries(domain string, entries []crtEntry, now time.Time, window time.Duration, maxSubs int) (subdomains []string, expiring []expiringCert) {
	domain = normalizeDomain(domain)
	if domain == "" {
		return nil, nil
	}
	suffix := "." + domain

	subSet := make(map[string]struct{})
	// Per host: the newest not_after seen, and the issuer/serial of that cert.
	type latest struct {
		notAfter time.Time
		issuer   string
		serial   string
	}
	newest := make(map[string]latest)

	for _, e := range entries {
		na := parseCRTTime(e.NotAfter)

		for _, host := range hostsFromEntry(e) {
			host = normalizeDomain(host)
			if host == "" {
				continue
			}
			// Only accept the queried domain and its subdomains. crt.sh's LIKE
			// query is broad; this is the authoritative scope check.
			if host != domain && !strings.HasSuffix(host, suffix) {
				continue
			}
			// subdomain_discovered is for hosts BELOW the apex (the apex is the
			// already-known domain asset).
			if host != domain {
				subSet[host] = struct{}{}
			}
			if na.IsZero() {
				continue
			}
			if cur, ok := newest[host]; !ok || na.After(cur.notAfter) {
				newest[host] = latest{notAfter: na, issuer: e.IssuerName, serial: e.SerialNumber}
			}
		}
	}

	subdomains = make([]string, 0, len(subSet))
	for h := range subSet {
		subdomains = append(subdomains, h)
	}
	sort.Strings(subdomains)
	if maxSubs > 0 && len(subdomains) > maxSubs {
		subdomains = subdomains[:maxSubs]
	}

	cutoff := now.Add(window)
	for host, l := range newest {
		// Newest cert already expired -> not "expiring soon".
		if !l.notAfter.After(now) {
			continue
		}
		// Newest cert expires beyond the window -> healthy.
		if l.notAfter.After(cutoff) {
			continue
		}
		days := int(l.notAfter.Sub(now).Hours() / 24)
		expiring = append(expiring, expiringCert{
			Host:     host,
			NotAfter: l.notAfter,
			DaysLeft: days,
			Issuer:   l.issuer,
			Serial:   l.serial,
		})
	}
	sort.Slice(expiring, func(i, j int) bool { return expiring[i].Host < expiring[j].Host })
	return subdomains, expiring
}

// hostsFromEntry pulls the certificate's subject hosts: the common_name plus
// each newline-separated SAN in name_value.
func hostsFromEntry(e crtEntry) []string {
	hosts := make([]string, 0, 4)
	if cn := strings.TrimSpace(e.CommonName); cn != "" {
		hosts = append(hosts, cn)
	}
	for _, line := range strings.Split(e.NameValue, "\n") {
		if h := strings.TrimSpace(line); h != "" {
			hosts = append(hosts, h)
		}
	}
	return hosts
}

// normalizeDomain lowercases, trims, drops a trailing dot, and strips a leading
// wildcard label ("*.") so "*.Example.com." becomes "example.com".
func normalizeDomain(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimSuffix(s, ".")
	s = strings.TrimPrefix(s, "*.")
	// Guard against obviously non-host junk (emails, spaces).
	if s == "" || strings.ContainsAny(s, " @/") {
		return ""
	}
	return s
}

// parseCRTTime parses the timestamp formats crt.sh emits (no timezone; UTC).
func parseCRTTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	for _, layout := range []string{
		"2006-01-02T15:04:05.999999",
		"2006-01-02T15:04:05",
		time.RFC3339,
		"2006-01-02",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

// expirySeverity maps days-until-expiry to an exposure severity.
func expirySeverity(daysLeft int) exposuredom.Severity {
	switch {
	case daysLeft <= 7:
		return exposuredom.SeverityHigh
	case daysLeft <= 14:
		return exposuredom.SeverityMedium
	default:
		return exposuredom.SeverityLow
	}
}
