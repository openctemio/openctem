// Package certmonitor implements OpenCTEM's Certificate-Transparency (CT)
// discovery source: a scheduled, per-tenant poller that queries public CT data
// (crt.sh, with SSLMate Cert Spotter as the fallback) for the tenant's own
// domains and emits first-class ExposureEvents.
//
// This is CTEM Discovery breadth ("exposure != vulnerability") that needs no
// credentials, no sensor and no traffic to the tenant's hosts: it reads only
// public CT-log data. See docs/rfcs/RFC-019 and RFC-036 (P0: rotation through
// every watched domain, retries, fallback, back-off).
//
// The watched domains are the tenant's domain assets, verified domains and
// active domain scope targets. Each run picks the ones due, oldest-queried
// first, up to a per-run cap (selection.go); per-domain state lives in
// ct_monitor_state so the rotation survives restarts.
//
// Outbound queries dial through httpsec.SafeDialContext (SSRF-guarded: private,
// link-local and metadata addresses are refused even though the sources are
// public — defense against DNS rebinding of the configurable URLs), are
// body-bounded, retried with jittered back-off and politeness-delayed.
//
// Tenant isolation: the tenant is taken from the domain being queried, never
// from the CT response. Every emitted exposure is stamped with that tenant. A
// failure on one domain or one tenant is recorded and skipped (fail-open); it
// never aborts the whole sweep.
package certmonitor

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	scopeapp "github.com/openctemio/openctem/api/internal/app/scope"
	assetdom "github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	exposuredom "github.com/openctemio/openctem/api/pkg/domain/exposure"
	"github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/verifieddomain"
	"github.com/openctemio/openctem/api/pkg/httpsec"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

const (
	// DefaultFeedBaseURL is the public crt.sh CT-log aggregator. No auth.
	DefaultFeedBaseURL = "https://crt.sh"

	// Source is the exposure source tag for everything this connector emits.
	Source = "cert_transparency"

	// httpTimeout bounds a single CT query end to end. crt.sh can be slow for
	// busy domains, so this is generous.
	httpTimeout = 60 * time.Second

	// responseHeaderTimeout is how long we wait for crt.sh to start answering.
	// The shared SSRF-guarded client waits 15 s, which crt.sh's database
	// routinely exceeds for any domain with a few thousand certificates.
	responseHeaderTimeout = 50 * time.Second

	// maxBodyBytes bounds a single CT JSON response.
	maxBodyBytes = 48 << 20 // 48 MiB

	// userAgent identifies OpenCTEM to the CT sources.
	userAgent = "OpenCTEM/1.0 (+https://github.com/openctemio)"

	// DefaultMaxDomainsPerRun caps how many of a tenant's domains one sweep
	// queries, so a tenant with thousands of domains cannot make us hammer
	// crt.sh. The rest are picked up on later runs: the rotation order
	// (selectDue) puts never-queried and longest-unqueried domains first.
	DefaultMaxDomainsPerRun = 50

	// defaultMaxSubdomainsPerDomain caps subdomain_discovered exposures emitted
	// for a single domain in one run (a wildcard/CDN domain can have thousands of
	// CT entries).
	defaultMaxSubdomainsPerDomain = 500

	// defaultExpiryWindow is how soon a cert must expire to raise a
	// certificate_expiring exposure.
	defaultExpiryWindow = 30 * 24 * time.Hour

	// defaultExpiredLookback is how recently a host's newest certificate must
	// have lapsed to raise certificate_expired. Older lapses are almost always
	// decommissioned hosts, and raising them would flood a tenant with years
	// of CT history.
	defaultExpiredLookback = 30 * 24 * time.Hour

	// defaultRequestDelay is the politeness delay between CT queries within a
	// single tenant sweep.
	defaultRequestDelay = 1 * time.Second

	// DefaultRecheckAfter is how long a successfully queried domain is left
	// alone. Slightly under the daily sweep interval so a daily run always
	// re-queries it, while an API restart in between does not.
	DefaultRecheckAfter = 20 * time.Hour

	// DefaultSweepBudget bounds one tenant's sweep in wall-clock time. With
	// retries and the fallback a single bad domain can take minutes; past the
	// budget the sweep stops and the domains it did not reach stay first in
	// line for the next run.
	DefaultSweepBudget = 30 * time.Minute

	// assetPageSize is how many domain assets we page per DB round-trip. It
	// must not exceed pagination's 100-row clamp: at 200 the loop below
	// believed it had read two pages' worth after the first (clamped) page
	// and stopped, so a tenant's domain assets past the 100th were never seen.
	assetPageSize = 100
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

// VerifiedDomainLister lists a tenant's DNS-TXT-verified domains. Satisfied by
// *postgres.VerifiedDomainRepository.
type VerifiedDomainLister interface {
	ListByTenant(ctx context.Context, tenantID shared.ID) ([]*verifieddomain.VerifiedDomain, error)
}

// SeedRootLister lists a tenant's root_domain seeds with discovery on.
// Satisfied by *postgres.EASMSeedRepository.
type SeedRootLister interface {
	DiscoveryRootDomains(ctx context.Context, tenantID shared.ID) ([]string, error)
}

// ScopeTargetLister lists a tenant's active scope targets. Satisfied by
// *postgres.ScopeTargetRepository.
type ScopeTargetLister interface {
	ListActive(ctx context.Context, tenantID shared.ID) ([]*scope.Target, error)
}

// StateStore keeps the per-domain rotation record between sweeps. Satisfied
// by *postgres.CTMonitorStateRepository.
type StateStore interface {
	ListStates(ctx context.Context, tenantID shared.ID) (map[string]DomainState, error)
	SaveState(ctx context.Context, tenantID shared.ID, st DomainState) error
}

// TenantLocker is optionally implemented by the StateStore: it serializes
// sweeps of one tenant across API replicas. ok=false means another replica is
// sweeping that tenant now.
type TenantLocker interface {
	TryLockTenant(ctx context.Context, tenantID shared.ID) (release func(), ok bool, err error)
}

// Service is the CT discovery source.
type Service struct {
	assetRepo    AssetLister
	exposureRepo ExposureUpserter
	verified     VerifiedDomainLister
	scopeTargets ScopeTargetLister
	exclusions   ExclusionSource // nil = exclusions not wired (tests, minimal wiring)
	state        StateStore
	httpClient   *http.Client
	feedBaseURL  string

	// certSpotterBaseURL is the fallback source; empty disables it.
	certSpotterBaseURL string

	// Promotion of CT names into assets (promote.go); nil = off.
	ingester    AssetIngester
	assetNames  AssetNameLookup
	attribution AttributionStore

	maxDomains      int
	maxSubs         int
	expiryWindow    time.Duration
	expiredLookback time.Duration
	requestDelay    time.Duration
	recheckAfter    time.Duration
	sweepBudget     time.Duration
	maxPromotions   int
	noSleep         bool
	now             func() time.Time

	logger *logger.Logger

	// tombstones lets promotion skip rejected names (nil: no check).
	tombstones TombstoneChecker

	// seeds lists root_domain seeds to watch (nil: none).
	seeds SeedRootLister

	// maxBody bounds one CT response (maxBodyBytes; tests lower it).
	maxBody int64
}

// NewService constructs the CT discovery service. An empty feedBaseURL defaults
// to crt.sh. Without SetDomainSources and SetStateStore it queries only domain
// assets and keeps no rotation state (the test and minimal wiring).
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
		assetRepo:       assetRepo,
		exposureRepo:    exposureRepo,
		httpClient:      newCTHTTPClient(),
		feedBaseURL:     strings.TrimRight(feedBaseURL, "/"),
		maxDomains:      DefaultMaxDomainsPerRun,
		maxSubs:         defaultMaxSubdomainsPerDomain,
		expiryWindow:    defaultExpiryWindow,
		expiredLookback: defaultExpiredLookback,
		requestDelay:    defaultRequestDelay,
		recheckAfter:    DefaultRecheckAfter,
		sweepBudget:     DefaultSweepBudget,
		maxPromotions:   DefaultMaxPromotionsPerRun,
		maxBody:         maxBodyBytes,
		now:             func() time.Time { return time.Now().UTC() },
		logger:          log.With("service", "cert_monitor"),
	}
}

// newCTHTTPClient is the SSRF-guarded client with a response-header timeout
// long enough for crt.sh.
func newCTHTTPClient() *http.Client {
	return httpsec.SafeHTTPClientWithHeaderTimeout(httpTimeout, responseHeaderTimeout)
}

// SetDomainSources adds verified domains and active domain scope targets to
// the names the sweep queries, next to domain assets.
func (s *Service) SetDomainSources(verified VerifiedDomainLister, targets ScopeTargetLister) {
	s.verified = verified
	s.scopeTargets = targets
}

// SetSeedSource adds the tenant's root_domain seeds (RFC-036 §6.3) to the
// names the sweep queries. A seed is the tenant's assertion: names found
// under it get fqdn_under_asserted_root unless a verified domain covers them.
func (s *Service) SetSeedSource(seeds SeedRootLister) { s.seeds = seeds }

// SetStateStore enables the persisted rotation cursor and failure back-off.
func (s *Service) SetStateStore(st StateStore) { s.state = st }

// SetCertSpotterFallback sets the Cert Spotter base URL used when crt.sh keeps
// failing. An empty string or "off" disables the fallback.
func (s *Service) SetCertSpotterFallback(baseURL string) {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if strings.EqualFold(baseURL, "off") {
		baseURL = ""
	}
	s.certSpotterBaseURL = baseURL
}

// SetLimits sets the per-run domain cap and the re-check age. Zero or negative
// values keep the defaults.
func (s *Service) SetLimits(maxDomainsPerRun int, recheckAfter time.Duration) {
	if maxDomainsPerRun > 0 {
		s.maxDomains = maxDomainsPerRun
	}
	if recheckAfter > 0 {
		s.recheckAfter = recheckAfter
	}
}

// FeedBaseURL returns the configured crt.sh base URL (for diagnostics).
func (s *Service) FeedBaseURL() string { return s.feedBaseURL }

// setHTTPClient overrides the outbound client and disables the politeness delay
// and retry waits. Test-only: production always uses the SSRF-guarded client
// built in NewService, which (correctly) refuses the loopback address an
// httptest server listens on.
func (s *Service) setHTTPClient(c *http.Client) {
	s.httpClient = c
	s.requestDelay = 0
	s.noSleep = true
}

// MonitorTenant runs one CT sweep for a single tenant: it gathers the tenant's
// domains (domain assets, verified domains, active domain scope targets),
// picks the ones due this run in rotation order, queries CT for each (crt.sh
// with retries, Cert Spotter as the fallback) and upserts the resulting
// ExposureEvents (deduped by fingerprint). Returns the number of exposures
// emitted (created or re-sighted). Fail-open per domain: a failure on one
// domain is recorded in its state, backs it off, and the sweep continues.
func (s *Service) MonitorTenant(ctx context.Context, tenantID shared.ID) (int, error) {
	if s == nil || s.assetRepo == nil || s.exposureRepo == nil {
		return 0, nil
	}
	if tenantID.IsZero() {
		return 0, fmt.Errorf("%w: tenant ID is required", shared.ErrValidation)
	}

	if locker, ok := s.state.(TenantLocker); ok {
		release, got, err := locker.TryLockTenant(ctx, tenantID)
		if err != nil {
			return 0, err
		}
		if !got {
			s.logger.Info("ct sweep: another instance is sweeping this tenant; skipping", "tenant_id", tenantID.String())
			return 0, nil
		}
		defer release()
	}

	// Retention (O7): rejected-name tombstones expire after 12 months.
	if s.tombstones != nil {
		if _, err := s.tombstones.PurgeExpiredTombstones(ctx, tenantID); err != nil {
			s.logger.Warn("ct sweep: expired tombstones not purged", "tenant_id", tenantID.String(), "error", err)
		}
	}

	roots, assetsByName, err := s.gatherRoots(ctx, tenantID)
	if err != nil {
		return 0, err
	}
	var excl *scopeapp.ExclusionMatcher
	if s.exclusions != nil {
		// Fail closed: without the exclusions nothing is discovered.
		if excl, err = s.exclusions.LoadExclusionMatcher(ctx, tenantID); err != nil {
			return 0, fmt.Errorf("failed to load scope exclusions: %w", err)
		}
	}
	roots, droppedRoots := withoutExcludedRoots(roots, excl)
	if droppedRoots > 0 {
		s.logger.Info("ct sweep: excluded domains are not queried",
			"tenant_id", tenantID.String(), "excluded_domains", droppedRoots)
	}
	if len(roots) == 0 {
		return 0, nil
	}

	states := map[string]DomainState{}
	if s.state != nil {
		states, err = s.state.ListStates(ctx, tenantID)
		if err != nil {
			return 0, fmt.Errorf("failed to load CT monitor state: %w", err)
		}
	}
	now := s.now()
	due, deferred := selectDue(roots, states, now, s.recheckAfter, s.maxDomains)
	if deferred > 0 {
		s.logger.Info("ct sweep: more domains due than the per-run cap; the rest rotate in on later runs",
			"tenant_id", tenantID.String(), "cap", s.maxDomains, "deferred", deferred)
	}
	if len(due) == 0 {
		return 0, nil
	}

	client := &sweepClient{s: s}
	var events []*exposuredom.ExposureEvent
	var promotions []promotion
	failed, queried, excludedHosts := 0, 0, 0
	started := s.now()
	for i, root := range due {
		if err := ctx.Err(); err != nil {
			return len(events), err
		}
		if s.sweepBudget > 0 && s.now().Sub(started) > s.sweepBudget {
			s.logger.Warn("ct sweep: time budget spent; the remaining domains go first next run",
				"tenant_id", tenantID.String(), "budget", s.sweepBudget.String(), "remaining", len(due)-i)
			break
		}
		queried++
		// Politeness delay between queries (not before the first one).
		if i > 0 && s.requestDelay > 0 {
			if err := s.sleep(ctx, s.requestDelay); err != nil {
				return len(events), err
			}
		}

		st := states[root.name]
		st.Domain = root.name
		attempted := s.now()
		st.LastCheckedAt = &attempted

		res, err := client.fetch(ctx, root.name)
		if err != nil {
			if ctx.Err() != nil {
				return len(events), ctx.Err()
			}
			failed++
			st.ConsecutiveFailures++
			st.LastError = truncate(err.Error(), 500)
			next := attempted.Add(failureBackoff(st.ConsecutiveFailures))
			st.NextAttemptAt = &next
			s.saveState(ctx, tenantID, st)
			s.logger.Warn("CT query failed; domain backed off",
				"tenant_id", tenantID.String(), "domain", root.name,
				"failures", st.ConsecutiveFailures, "next_attempt_at", next.Format(time.RFC3339), "error", err)
			continue
		}

		d := collectDiscoveries(root.name, res.entries, attempted, s.expiryWindow, s.expiredLookback, s.maxSubs)
		d, dropped := withoutExcluded(d, excl)
		excludedHosts += dropped
		events = append(events, s.buildEvents(tenantID, root, assetsByName, d)...)
		for _, h := range d.promotable {
			promotions = append(promotions, promotion{host: h, root: root, source: res.source})
		}

		st.LastSuccessAt = &attempted
		st.LastSource = res.source
		st.LastError = ""
		st.ConsecutiveFailures = 0
		st.NextAttemptAt = nil
		st.SubdomainsSeen = len(d.subdomains)
		s.saveState(ctx, tenantID, st)
	}

	if len(events) > 0 {
		if err := s.exposureRepo.BulkUpsert(ctx, events); err != nil {
			return 0, fmt.Errorf("failed to upsert CT exposures: %w", err)
		}
	}

	promoted, err := s.promote(ctx, tenantID, promotions)
	if err != nil {
		// Exposures are written; promotion retries on the next run.
		s.logger.Warn("ct promotion failed", "tenant_id", tenantID.String(), "error", err)
	}

	s.logger.Info("ct sweep complete",
		"tenant_id", tenantID.String(),
		"domains_known", len(roots),
		"domains_queried", queried,
		"domains_failed", failed,
		"hosts_excluded", excludedHosts,
		"exposures", len(events),
		"assets_promoted", promoted)
	return len(events), nil
}

func (s *Service) saveState(ctx context.Context, tenantID shared.ID, st DomainState) {
	if s.state == nil {
		return
	}
	if err := s.state.SaveState(ctx, tenantID, st); err != nil {
		s.logger.Warn("failed to save CT monitor state", "tenant_id", tenantID.String(), "domain", st.Domain, "error", err)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// gatherRoots collects every domain the tenant asked us to watch: its domain
// assets that are not awaiting review or rejected (paged, no cap), verified
// domains, root_domain seeds with discovery
// on and active domain scope targets.
// It also returns the domain assets by name so a discovered host can be tied
// to its nearest known domain asset.
func (s *Service) gatherRoots(ctx context.Context, tenantID shared.ID) ([]rootDomain, map[string]shared.ID, error) {
	var in []rootDomain
	assetsByName := map[string]shared.ID{}

	// Only domain assets the tenant has not left to review or rejected: a
	// domain a sensor report created (needs_review or candidate) must not
	// widen the CT watch list by itself (research/22b S2).
	approved, _, err := attribution.ParseFilter([]string{attribution.FilterApproved})
	if err != nil {
		return nil, nil, err
	}
	filter := assetdom.NewFilter().
		WithTenantID(tenantID.String()).
		WithTypes(assetdom.AssetTypeDomain).
		WithAttribution(approved)
	seen := 0
	for pageNum := 1; ; pageNum++ {
		res, err := s.assetRepo.List(ctx, filter, assetdom.NewListOptions(), pagination.New(pageNum, assetPageSize))
		if err != nil {
			return nil, nil, fmt.Errorf("failed to list domain assets: %w", err)
		}
		seen += len(res.Data)
		for _, a := range res.Data {
			name := normalizeDomain(a.Name())
			if name == "" {
				continue
			}
			id := a.ID()
			if _, ok := assetsByName[name]; !ok {
				assetsByName[name] = id
			}
			in = append(in, rootDomain{name: name, origin: OriginAsset, assetID: &id})
		}
		// Stop on an empty page or once every row is read; never on page
		// arithmetic, which the repository's clamp can make wrong.
		if len(res.Data) == 0 || int64(seen) >= res.Total {
			break
		}
	}

	if s.verified != nil {
		vds, err := s.verified.ListByTenant(ctx, tenantID)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to list verified domains: %w", err)
		}
		for _, vd := range vds {
			if vd.IsVerified() {
				in = append(in, rootDomain{name: vd.Domain(), origin: OriginVerified})
			}
		}
	}

	if s.seeds != nil {
		names, err := s.seeds.DiscoveryRootDomains(ctx, tenantID)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to list seeds: %w", err)
		}
		for _, n := range names {
			in = append(in, rootDomain{name: n, origin: OriginSeed})
		}
	}

	if s.scopeTargets != nil {
		targets, err := s.scopeTargets.ListActive(ctx, tenantID)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to list scope targets: %w", err)
		}
		for _, t := range targets {
			switch t.TargetType() {
			case scope.TargetTypeDomain, scope.TargetTypeSubdomain, scope.TargetTypeEmailDomain:
				in = append(in, rootDomain{name: t.Pattern(), origin: OriginScope})
			}
		}
	}

	roots := mergeRoots(in)
	for i := range roots {
		if id, ok := assetsByName[roots[i].name]; ok && roots[i].assetID == nil {
			roots[i].assetID = &id
		}
	}
	return roots, assetsByName, nil
}

// nearestAsset returns the domain asset for host or its closest parent, or
// the root's own asset, or nil.
func nearestAsset(host string, root rootDomain, assetsByName map[string]shared.ID) *shared.ID {
	for h := host; h != "" && h != root.name; h = parentOf(h) {
		if id, ok := assetsByName[h]; ok {
			return &id
		}
	}
	return root.assetID
}

// buildEvents converts the pure discovery results into ExposureEvents for the
// given tenant/root. Events that fail construction are skipped (defensive;
// inputs are already validated).
func (s *Service) buildEvents(tenantID shared.ID, root rootDomain, assetsByName map[string]shared.ID, d discoveries) []*exposuredom.ExposureEvent {
	events := make([]*exposuredom.ExposureEvent, 0, len(d.subdomains)+len(d.expiring)+len(d.expired))

	for _, host := range d.subdomains {
		ev, err := exposuredom.NewExposureEvent(
			tenantID,
			exposuredom.EventTypeSubdomainDiscovered,
			exposuredom.SeverityInfo,
			fmt.Sprintf("Subdomain seen in Certificate Transparency: %s", host),
			Source,
			map[string]any{
				"domain":           host,
				"parent_domain":    root.name,
				"root_origin":      root.origin,
				"discovery_source": Source,
			},
		)
		if err != nil {
			continue
		}
		ev.UpdateDescription(fmt.Sprintf(
			"A TLS certificate for %q (under your monitored domain %q) was found in public Certificate Transparency logs. "+
				"Confirm this host is known and intended to be internet-facing.", host, root.name))
		if id := nearestAsset(host, root, assetsByName); id != nil {
			ev.SetAssetID(id)
		}
		events = append(events, ev)
	}

	for _, ec := range d.expiring {
		ev, err := exposuredom.NewExposureEvent(
			tenantID,
			exposuredom.EventTypeCertificateExpiring,
			expirySeverity(ec.DaysLeft),
			fmt.Sprintf("TLS certificate expiring soon: %s", ec.Host),
			Source,
			certDetails(root, ec),
		)
		if err != nil {
			continue
		}
		ev.UpdateDescription(fmt.Sprintf(
			"The most recent public TLS certificate for %q expires on %s (%d day(s) away). "+
				"An expired certificate breaks TLS for this host — renew before it lapses.",
			ec.Host, ec.NotAfter.Format("2006-01-02"), ec.DaysLeft))
		if id := nearestAsset(ec.Host, root, assetsByName); id != nil {
			ev.SetAssetID(id)
		}
		events = append(events, ev)
	}

	for _, ec := range d.expired {
		ev, err := exposuredom.NewExposureEvent(
			tenantID,
			exposuredom.EventTypeCertificateExpired,
			exposuredom.SeverityMedium,
			fmt.Sprintf("TLS certificate expired: %s", ec.Host),
			Source,
			certDetails(root, ec),
		)
		if err != nil {
			continue
		}
		ev.UpdateDescription(fmt.Sprintf(
			"The most recent public TLS certificate for %q expired on %s (%d day(s) ago) and no newer certificate "+
				"appears in Certificate Transparency logs. If the host still serves TLS, clients now reject it; "+
				"if it was retired, remove its DNS records.",
			ec.Host, ec.NotAfter.Format("2006-01-02"), -ec.DaysLeft))
		if id := nearestAsset(ec.Host, root, assetsByName); id != nil {
			ev.SetAssetID(id)
		}
		events = append(events, ev)
	}

	return events
}

func certDetails(root rootDomain, ec expiringCert) map[string]any {
	return map[string]any{
		"domain":         ec.Host,
		"parent_domain":  root.name,
		"not_after":      ec.NotAfter.Format(time.RFC3339),
		"days_remaining": ec.DaysLeft,
		"issuer":         ec.Issuer,
		"serial_number":  ec.Serial,
	}
}

// queryCRTSH fetches and parses crt.sh JSON for one domain (one attempt).
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
	// One row per certificate instead of a precertificate + certificate pair:
	// halves the answer and the time crt.sh spends building it.
	q.Set("deduplicate", "Y")
	u.RawQuery = q.Encode()

	body, err := s.get(ctx, u.String(), SourceCRTSH)
	if err != nil {
		return nil, err
	}
	entries, err := parseCRTSH(body)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errNotRetryable, err)
	}
	return entries, nil
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

// discoveries is what one domain's CT entries yield.
type discoveries struct {
	subdomains []string
	expiring   []expiringCert
	expired    []expiringCert
	// promotable are the subdomains fit to become inventory assets: named
	// exactly (not only through a wildcard) on a certificate that is valid
	// or lapsed within promoteLookback.
	promotable []ctHost
}

// ctHost is what CT says about one promotable name.
type ctHost struct {
	Name      string
	FirstSeen time.Time // earliest not_before: the earliest external evidence
	NotAfter  time.Time // newest not_after
	Issuer    string
}

// promoteLookback: a name whose newest certificate lapsed longer ago than
// this is history (a retired host), kept as a subdomain_discovered exposure
// for dangling-DNS work but not added to the inventory.
const promoteLookback = 90 * 24 * time.Hour

// collectDiscoveries is the pure core: from the CT entries for a domain it
// derives (a) the set of distinct subdomains observed, (b) the hosts whose
// most-recent certificate expires within the window and (c) the hosts whose
// most-recent certificate lapsed within the look-back.
//
// Expiry uses the MAX not_after per host, so a long tail of historical certs
// never raises a false alert when the host has a current cert. A host whose
// newest cert lapsed longer ago than the look-back is dropped (a retired host,
// and raising it would flood the tenant with years of CT history).
func collectDiscoveries(domain string, entries []crtEntry, now time.Time, window, expiredLookback time.Duration, maxSubs int) discoveries {
	var d discoveries
	domain = normalizeDomain(domain)
	if domain == "" {
		return d
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
	exact := make(map[string]bool)          // seen as a literal name, not only "*.name"
	firstSeen := make(map[string]time.Time) // earliest not_before per host

	for _, e := range entries {
		na := parseCRTTime(e.NotAfter)
		nb := parseCRTTime(e.NotBefore)

		for _, raw := range hostsFromEntry(e) {
			wildcard := strings.HasPrefix(strings.TrimSpace(raw), "*.")
			host := normalizeDomain(raw)
			// CT names are third-party data: anything that is not a plain
			// DNS hostname (control characters, markup, over-long labels)
			// is dropped before it reaches an exposure title or the UI.
			if !validHostname(host) {
				continue
			}
			// Only accept the queried domain and its subdomains. The CT
			// sources' wildcard queries are broad; this is the authoritative
			// scope check.
			if host != domain && !strings.HasSuffix(host, suffix) {
				continue
			}
			// subdomain_discovered is for hosts BELOW the apex (the apex is the
			// already-known domain), named literally: "*.dev" proves no host
			// called dev exists, and it would be counted with no asset behind
			// it (research/22 P0-13, 22c B9).
			if host != domain {
				if !wildcard {
					subSet[host] = struct{}{}
					exact[host] = true
				}
				if !nb.IsZero() {
					if cur, ok := firstSeen[host]; !ok || nb.Before(cur) {
						firstSeen[host] = nb
					}
				}
			}
			if na.IsZero() {
				continue
			}
			if cur, ok := newest[host]; !ok || na.After(cur.notAfter) {
				newest[host] = latest{notAfter: na, issuer: e.IssuerName, serial: e.SerialNumber}
			}
		}
	}

	d.subdomains = make([]string, 0, len(subSet))
	for h := range subSet {
		d.subdomains = append(d.subdomains, h)
	}
	sort.Strings(d.subdomains)
	if maxSubs > 0 && len(d.subdomains) > maxSubs {
		d.subdomains = d.subdomains[:maxSubs]
	}

	for _, h := range d.subdomains {
		l, ok := newest[h]
		if !exact[h] || !ok || now.Sub(l.notAfter) > promoteLookback {
			continue
		}
		fs := firstSeen[h]
		if fs.IsZero() {
			fs = now
		}
		d.promotable = append(d.promotable, ctHost{Name: h, FirstSeen: fs, NotAfter: l.notAfter, Issuer: l.issuer})
	}

	for host, l := range newest {
		days := int(l.notAfter.Sub(now).Hours() / 24)
		d.classifyExpiry(expiringCert{Host: host, NotAfter: l.notAfter, DaysLeft: days, Issuer: l.issuer, Serial: l.serial}, now, window, expiredLookback)
	}
	sort.Slice(d.expiring, func(i, j int) bool { return d.expiring[i].Host < d.expiring[j].Host })
	sort.Slice(d.expired, func(i, j int) bool { return d.expired[i].Host < d.expired[j].Host })
	return d
}

// classifyExpiry files a host's newest certificate as expired (lapsed within
// the look-back), expiring (within the window) or healthy (dropped).
func (d *discoveries) classifyExpiry(ec expiringCert, now time.Time, window, expiredLookback time.Duration) {
	switch {
	case !ec.NotAfter.After(now):
		if expiredLookback > 0 && now.Sub(ec.NotAfter) <= expiredLookback {
			d.expired = append(d.expired, ec)
		}
	case !ec.NotAfter.After(now.Add(window)):
		d.expiring = append(d.expiring, ec)
	}
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
