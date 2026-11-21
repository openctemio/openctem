package cirun

// Why a CI token exchange was refused, in words the job and the
// organization's administrator can act on. Design:
// docs/architecture/ci-runner-identity.md ("Refusal reasons").

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/openctemio/openctem/server/pkg/domain/cirun"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/httpsec"
	"github.com/openctemio/openctem/server/pkg/oidc"
)

// Issuer key failure classes: why the issuer's signing keys could not be
// fetched. Never an address: the job and the organization learn the class,
// not the platform's network.
const (
	// IssuerCauseBlockedAddress: the issuer's host resolves to an address
	// the platform does not reach (a private address not opened, or one never
	// reachable).
	IssuerCauseBlockedAddress = "blocked_address"
	// IssuerCauseDNS: the issuer's host name does not resolve.
	IssuerCauseDNS = "dns"
	// IssuerCauseTLS: the issuer's certificate is not trusted, or TLS failed.
	IssuerCauseTLS = "tls"
	// IssuerCauseTimeout: the issuer did not answer in time.
	IssuerCauseTimeout = "timeout"
	// IssuerCauseIssuerMismatch: the issuer's discovery document names
	// another issuer (a trailing slash, another host name or path).
	IssuerCauseIssuerMismatch = "issuer_mismatch"
	// IssuerCauseHTTPStatus: the issuer answered with an error status.
	IssuerCauseHTTPStatus = "http_status"
	// IssuerCauseKeyNotFound: the issuer's keys do not include the one that
	// signed the token (a key rotated moments ago).
	IssuerCauseKeyNotFound = "key_not_found"
	// IssuerCauseUnreachable: the connection failed otherwise.
	IssuerCauseUnreachable = "unreachable"
)

// IssuerUnavailableError is ErrIssuerUnavailable with its class. Withheld:
// the issuer is a hosted service, where the caller may be anyone, so the job
// is not told the class (the administrator's record keeps it).
type IssuerUnavailableError struct {
	Cause    string
	Withheld bool
}

func (e *IssuerUnavailableError) Error() string { return ErrIssuerUnavailable.Error() + ": " + e.Cause }

// Is makes errors.Is(err, ErrIssuerUnavailable) hold.
func (e *IssuerUnavailableError) Is(target error) bool { return target == ErrIssuerUnavailable }

// IssuerCause classifies why the issuer's keys could not be had.
func IssuerCause(err error) string {
	var (
		dnsErr   *net.DNSError
		certErr  *tls.CertificateVerificationError
		unknown  x509.UnknownAuthorityError
		hostErr  x509.HostnameError
		invalid  x509.CertificateInvalidError
		recErr   tls.RecordHeaderError
		alertErr tls.AlertError
		netErr   net.Error
	)
	switch {
	case err == nil:
		return IssuerCauseUnreachable
	case errors.Is(err, oidc.ErrKeyNotFound):
		return IssuerCauseKeyNotFound
	case errors.Is(err, httpsec.ErrBlockedDestination):
		return IssuerCauseBlockedAddress
	case errors.Is(err, oidc.ErrIssuerMismatch):
		return IssuerCauseIssuerMismatch
	case errors.Is(err, httpsec.ErrUnresolvable), errors.As(err, &dnsErr):
		return IssuerCauseDNS
	case errors.As(err, &certErr), errors.As(err, &unknown), errors.As(err, &hostErr), errors.As(err, &invalid),
		errors.As(err, &recErr), errors.As(err, &alertErr):
		return IssuerCauseTLS
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, os.ErrDeadlineExceeded),
		errors.As(err, &netErr) && netErr.Timeout():
		return IssuerCauseTimeout
	case errors.Is(err, oidc.ErrHTTPStatus):
		return IssuerCauseHTTPStatus
	}
	return IssuerCauseUnreachable
}

// IssuerUnavailableMessage is what the job is told for a cause class. It
// never names an address.
func IssuerUnavailableMessage(cause string) string {
	const retry = " Nothing was used up: the same token may be retried."
	switch cause {
	case IssuerCauseBlockedAddress:
		return "The platform could not fetch the CI provider's signing keys: the provider's host name resolves to an address the platform does not connect to (a private network address that is not opened). A platform administrator opens it under System > Private networks in the platform console." + retry
	case IssuerCauseDNS:
		return "The platform could not fetch the CI provider's signing keys: the provider's host name does not resolve from the platform. Check the issuer address in the trust configuration and the platform's DNS." + retry
	case IssuerCauseTLS:
		return "The platform could not fetch the CI provider's signing keys: the provider's TLS certificate is not trusted by the platform (a private certificate authority, an expired certificate or another host name). Add the certificate authority to the platform or fix the certificate." + retry
	case IssuerCauseTimeout:
		return "The platform could not fetch the CI provider's signing keys: the provider did not answer in time. Retry in 30 seconds." + retry
	case IssuerCauseIssuerMismatch:
		return "The platform could not fetch the CI provider's signing keys: the provider's discovery document names a different issuer than the token (often a trailing slash, or another host name). The trust configuration's issuer must match the provider's own issuer address exactly." + retry
	case IssuerCauseHTTPStatus:
		return "The platform could not fetch the CI provider's signing keys: the provider answered with an error. Check that the issuer address serves /.well-known/openid-configuration." + retry
	case IssuerCauseKeyNotFound:
		return "The CI provider has just changed its signing keys and the platform may fetch them again shortly. Retry in 30 seconds." + retry
	}
	return "The platform could not fetch the CI provider's signing keys: the provider could not be reached. Retry in 30 seconds." + retry
}

// Reasons of an unverified refusal (no tenant audit row is written for
// them: the caller is not known yet).
const (
	// UnverifiedNoConfiguration: no enabled trust configuration has the
	// token's issuer.
	UnverifiedNoConfiguration = cirun.UnverifiedReasonNoConfiguration
	// UnverifiedKeysUnavailable: the issuer's keys could not be had (Cause
	// says why).
	UnverifiedKeysUnavailable = "keys_unavailable"
	// UnverifiedNotVerified: the token did not verify (signature, audience,
	// expiry).
	UnverifiedNotVerified = "not_verified"
)

// unverifiedThrottle bounds how often one (tenant, issuer, reason) is
// written: an anonymous caller can repeat a refused exchange, and each
// repeat must not be a database write.
const unverifiedThrottle = 30 * time.Second

// unverifiedKeysMax bounds the throttle's memory; it is cleared when full.
const unverifiedKeysMax = 4096

// unverifiedNewPerHour bounds the records of keys not written before that one
// tenant gets per hour (per server): an anonymous caller choosing issuers
// close to a configured one cannot turn each into a database write.
const unverifiedNewPerHour = 20

// unverifiedBudget is one tenant's new-record budget in the current hour.
type unverifiedBudget struct {
	start time.Time
	used  int
}

// maxUnverifiedIssuer bounds a stored issuer (an issuer the token claims,
// so caller-chosen).
const maxUnverifiedIssuer = 255

type unverifiedKey struct {
	tenant shared.ID
	issuer string
	reason string
}

type unverifiedPending struct {
	written time.Time
	count   int
}

// unverifiedRecorder keeps the bounded, deduplicated per-tenant record of
// refusals before verification.
type unverifiedRecorder struct {
	mu      sync.Mutex
	pending map[unverifiedKey]*unverifiedPending
	budget  map[shared.ID]*unverifiedBudget
}

// takeNew spends one of the tenant's new-record budget (caller holds mu).
func (u *unverifiedRecorder) takeNew(tenant shared.ID, now time.Time) bool {
	if u.budget == nil || len(u.budget) >= unverifiedKeysMax {
		u.budget = map[shared.ID]*unverifiedBudget{}
	}
	b := u.budget[tenant]
	if b == nil || now.Sub(b.start) >= time.Hour {
		b = &unverifiedBudget{start: now}
		u.budget[tenant] = b
	}
	if b.used >= unverifiedNewPerHour {
		return false
	}
	b.used++
	return true
}

// recordUnverified notes one refusal before verification for the tenant's
// administrators: issuer, reason, cause class, time and count, never token
// contents. The issuer is the token's claim, so it is kept only when it is a
// plain https issuer address of bounded length and, for no_configuration,
// on the same host as an issuer the tenant configured (a typing mistake
// worth showing); any other issuer is recorded as "" (another issuer), so
// made-up issuers share one record. The row is written only for a tenant
// that has a trust configuration (the store checks), at most once per
// unverifiedThrottle per (tenant, issuer, reason), at most
// unverifiedNewPerHour new keys per tenant and hour, and the store keeps a
// bounded number per tenant without pushing recent ones out.
func (s *Service) recordUnverified(ctx context.Context, tenantID shared.ID, issuer, reason, cause string) {
	if tenantID.IsZero() || s.unverifiedStore == nil {
		return
	}
	issuer = strings.TrimSpace(issuer)
	if reason != UnverifiedNoConfiguration {
		// The configuration matched on the issuer without its trailing
		// slashes (EnabledTrustConfigs), so the record carries the matched
		// form: slash variants of one issuer are one record, and a caller
		// cannot fill the list with them.
		issuer = strings.TrimRight(issuer, "/")
	}
	if !plainIssuer(issuer) {
		issuer = ""
	}
	if issuer != "" && reason == UnverifiedNoConfiguration && !s.nearConfiguredIssuer(ctx, tenantID, issuer) {
		issuer = ""
	}
	key := unverifiedKey{tenant: tenantID, issuer: issuer, reason: reason}
	now := s.now()
	s.unverified.mu.Lock()
	if s.unverified.pending == nil || len(s.unverified.pending) >= unverifiedKeysMax {
		s.unverified.pending = map[unverifiedKey]*unverifiedPending{}
	}
	p := s.unverified.pending[key]
	if p == nil {
		p = &unverifiedPending{}
		s.unverified.pending[key] = p
	}
	p.count++
	if !p.written.IsZero() && now.Sub(p.written) < unverifiedThrottle {
		s.unverified.mu.Unlock()
		return
	}
	// Only no_configuration records are budgeted: the others name an issuer a
	// configuration already matched, so they are bounded by the tenant's
	// configurations and must never be starved by caller-chosen issuers.
	if p.written.IsZero() && reason == UnverifiedNoConfiguration && !s.unverified.takeNew(tenantID, now) {
		// Over the tenant's budget of new records: keep counting, retry
		// with the next refusal.
		s.unverified.mu.Unlock()
		return
	}
	n := p.count
	p.count, p.written = 0, now
	s.unverified.mu.Unlock()

	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer cancel()
	if err := s.unverifiedStore.RecordUnverifiedRefusal(wctx, cirun.UnverifiedRefusal{TenantID: tenantID, Issuer: issuer,
		Reason: reason, Cause: cause, LastSeen: now, Count: n}); err != nil {
		s.log.Warn("ci unverified refusal not recorded", "error", err)
	}
}

// nearConfiguredIssuer reports whether issuer is close to one of the tenant's
// configured issuers: the same host name. A read error
// counts as not close.
func (s *Service) nearConfiguredIssuer(ctx context.Context, tenantID shared.ID, issuer string) bool {
	if s.repo == nil {
		return false
	}
	configs, err := s.repo.ListTrustConfigs(ctx, tenantID)
	if err != nil {
		return false
	}
	issuers := make([]string, 0, len(configs))
	for _, c := range configs {
		issuers = append(issuers, c.Issuer)
	}
	// A claimed issuer is kept under its own name only when it has the same
	// host name as a configured one (a trailing slash, case, scheme, port or
	// path difference: the mistakes the record exists to show). Every usual
	// configured issuer has an empty path, so a made-up issuer on another
	// host must not count as close for having the same (empty) path.
	tu, err := url.Parse(issuer)
	if err != nil {
		return false
	}
	for _, c := range issuers {
		if cu, err := url.Parse(c); err == nil && cu.Hostname() != "" && strings.EqualFold(tu.Hostname(), cu.Hostname()) {
			return true
		}
	}
	return false
}

// SetUnverifiedRefusalStore wires the unverified refusal records (nil: not
// kept).
func (s *Service) SetUnverifiedRefusalStore(st cirun.UnverifiedRefusalStore) { s.unverifiedStore = st }

// UnverifiedRefusals lists the tenant's refusals before verification, with
// the issuers of its trust configurations to compare against.
func (s *Service) UnverifiedRefusals(ctx context.Context, tenantID shared.ID) ([]cirun.UnverifiedRefusal, []cirun.TrustConfig, error) {
	var list []cirun.UnverifiedRefusal
	if s.unverifiedStore != nil {
		var err error
		if list, err = s.unverifiedStore.ListUnverifiedRefusals(ctx, tenantID); err != nil {
			return nil, nil, err
		}
	}
	configs, err := s.repo.ListTrustConfigs(ctx, tenantID)
	if err != nil {
		return nil, nil, err
	}
	return list, configs, nil
}

// plainIssuer reports whether s is an https URL with a host, no
// credentials, query or fragment, of bounded length: safe to show to an
// administrator as the issuer a token claimed.
func plainIssuer(s string) bool {
	if s == "" || len(s) > maxUnverifiedIssuer {
		return false
	}
	for _, r := range s {
		if r < 0x21 || r > 0x7e {
			return false
		}
	}
	u, err := url.Parse(s)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.RawQuery == "" && u.Fragment == ""
}

// IssuerDifference names how a token's issuer differs from the nearest
// configured one, so an administrator sees the mistake.
const (
	IssuerDiffTrailingSlash = "trailing_slash"
	IssuerDiffCase          = "case"
	IssuerDiffScheme        = "scheme"
	IssuerDiffHost          = "host"
	IssuerDiffPath          = "path"
)

// NearestIssuer returns the configured issuer closest to the token's and
// how they differ ("" when none is close: another host and path).
func NearestIssuer(token string, configured []string) (string, string) {
	tu, err := url.Parse(token)
	if err != nil {
		return "", ""
	}
	bestIssuer, bestDiff, bestRank := "", "", 99
	for _, c := range configured {
		cu, err := url.Parse(c)
		if err != nil {
			continue
		}
		diff, rank := "", 99
		sameHost := strings.EqualFold(tu.Host, cu.Host)
		samePath := strings.TrimRight(tu.Path, "/") == strings.TrimRight(cu.Path, "/")
		switch {
		case token == c:
			continue
		case strings.TrimRight(token, "/") == strings.TrimRight(c, "/"):
			diff, rank = IssuerDiffTrailingSlash, 0
		case strings.EqualFold(token, c):
			diff, rank = IssuerDiffCase, 1
		case sameHost && samePath && tu.Scheme != cu.Scheme:
			diff, rank = IssuerDiffScheme, 2
		case sameHost:
			diff, rank = IssuerDiffPath, 3
		case samePath:
			diff, rank = IssuerDiffHost, 4
		default:
			continue
		}
		if rank < bestRank {
			bestIssuer, bestDiff, bestRank = c, diff, rank
		}
	}
	return bestIssuer, bestDiff
}

// ruleRefusalMessage is the job-facing text of a rule refusal: what the
// configuration accepts and the token's own value that did not match. It
// never names the configuration or its listed values (the token may come
// from anyone on a shared issuer).
func ruleRefusalMessage(code string, c cirun.Claims) string {
	q := func(v string) string {
		v = strings.TrimSpace(v)
		if v == "" {
			return "nothing"
		}
		if len(v) > 300 {
			v = v[:300] + "..."
		}
		return fmt.Sprintf("%q", v)
	}
	switch code {
	case cirun.RefuseWorkflow:
		return fmt.Sprintf("the trust configuration accepts only the pipeline files it lists, and this job runs %s. "+
			"An administrator adds it under CI/CD, Trusted pipelines, Pipeline definitions (or from Recent refused tokens).", q(c.WorkflowDefinition()))
	case cirun.RefuseRef:
		return fmt.Sprintf("the trust configuration accepts only the branches and tags it lists, and this job runs on %s. "+
			"An administrator adds it under CI/CD, Trusted pipelines, Branches and tags (or from Recent refused tokens).", q(c.Ref))
	case cirun.RefuseRepository:
		return fmt.Sprintf("the trust configuration accepts only the repositories it lists, and this job comes from %s.", q(c.Repository))
	case cirun.RefuseOwner:
		return fmt.Sprintf("the trust configuration accepts only the organizations or groups it lists, and this job comes from %s.", q(c.Owner()))
	case cirun.RefuseEnvironment:
		return fmt.Sprintf("the trust configuration accepts only the deployment environments it lists, and this job runs in %s.", q(c.Environment))
	case cirun.RefuseEvent:
		return fmt.Sprintf("the trust configuration accepts only the pipeline events it lists, and this job was started by %s.", q(c.Event))
	case cirun.RefuseRefNotProtected:
		return fmt.Sprintf("the trust configuration accepts only protected branches and tags, and %s is not protected.", q(c.Ref))
	case cirun.RefuseForkPullRequest:
		return fmt.Sprintf("the trust configuration does not accept fork pull requests, and this job was started by %s.", q(c.Event))
	case cirun.RefuseOrganization:
		return fmt.Sprintf("the token's organization %s is not the one the trust configuration names.", q(c.OrgID))
	case cirun.RefuseSSHRerun:
		return "the job is a re-run with SSH access, which is never accepted."
	case cirun.RefuseMissingClaims:
		return "the token lacks the repository, commit, ref or token id the platform needs."
	}
	return ""
}

// RuleRefusalMessage joins the job-facing texts of the refusals (one per
// distinct code, at most three).
func RuleRefusalMessage(refusals []*cirun.Refusal, c cirun.Claims) string {
	seen := map[string]bool{}
	parts := make([]string, 0, 3)
	for _, r := range refusals {
		if r == nil || seen[r.Code] || len(parts) == 3 {
			continue
		}
		seen[r.Code] = true
		if m := ruleRefusalMessage(r.Code, c); m != "" {
			parts = append(parts, m)
		}
	}
	return strings.Join(parts, " Also, ")
}
