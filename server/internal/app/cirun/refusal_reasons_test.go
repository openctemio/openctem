package cirun

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"

	"github.com/openctemio/openctem/server/pkg/domain/cirun"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/httpsec"
	"github.com/openctemio/openctem/server/pkg/logger"
	"github.com/openctemio/openctem/server/pkg/oidc"
)

func TestIssuerCause(t *testing.T) {
	wrap := func(err error) error {
		return fmt.Errorf("%w: discovery: %w", oidc.ErrJWKSUnavailable, fmt.Errorf("Get \"https://gitlab.example.com\": %w", err))
	}
	for name, tc := range map[string]struct {
		err  error
		want string
	}{
		"blocked":         {wrap(httpsec.ErrBlockedDestination), IssuerCauseBlockedAddress},
		"unresolvable":    {wrap(httpsec.ErrUnresolvable), IssuerCauseDNS},
		"dns":             {wrap(&net.DNSError{Err: "no such host", Name: "gitlab.example.com", IsNotFound: true}), IssuerCauseDNS},
		"unknown CA":      {wrap(x509.UnknownAuthorityError{}), IssuerCauseTLS},
		"wrong host cert": {wrap(x509.HostnameError{Host: "gitlab.example.com", Certificate: &x509.Certificate{}}), IssuerCauseTLS},
		"tls verify":      {wrap(&tls.CertificateVerificationError{Err: errors.New("x")}), IssuerCauseTLS},
		"deadline":        {wrap(context.DeadlineExceeded), IssuerCauseTimeout},
		"issuer mismatch": {wrap(fmt.Errorf("%w: a", oidc.ErrIssuerMismatch)), IssuerCauseIssuerMismatch},
		"status":          {wrap(fmt.Errorf("%w 404", oidc.ErrHTTPStatus)), IssuerCauseHTTPStatus},
		"key not found":   {fmt.Errorf("%w %q", oidc.ErrKeyNotFound, "k1"), IssuerCauseKeyNotFound},
		"refused":         {wrap(errors.New("connect: connection refused")), IssuerCauseUnreachable},
	} {
		if got := IssuerCause(tc.err); got != tc.want {
			t.Errorf("%s: IssuerCause = %q, want %q", name, got, tc.want)
		}
	}
}

// The real client: an issuer whose host the guard refuses comes back as a
// blocked address, through every wrapping layer.
func TestIssuerCause_ThroughOIDCClient(t *testing.T) {
	c := oidc.NewClient(&http.Client{Transport: failingTransport{}}, func(string) error { return httpsec.ErrBlockedDestination })
	tok := jwtv5.NewWithClaims(jwtv5.SigningMethodHS256, jwtv5.MapClaims{"iss": "https://gitlab.example.com", "aud": "a",
		"sub": "s", "jti": "j", "iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix()})
	tok.Header["kid"] = "k1"
	raw, err := tok.SignedString([]byte("not-used"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.VerifyWorkloadToken(context.Background(), raw, oidc.WorkloadExpectations{Issuer: "https://gitlab.example.com", Audience: "a"})
	if !errors.Is(err, oidc.ErrJWKSUnavailable) {
		t.Skipf("the verifier refused the token before fetching keys: %v", err)
	}
	if got := IssuerCause(err); got != IssuerCauseBlockedAddress {
		t.Fatalf("IssuerCause = %q (%v), want blocked_address", got, err)
	}
}

type failingTransport struct{}

func (failingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("no network in this test")
}

var ipLike = regexp.MustCompile(`\d+\.\d+\.\d+\.\d+|[0-9a-f]+::[0-9a-f]`)

// The job-facing text names the class and never an address.
func TestIssuerUnavailableMessage(t *testing.T) {
	for _, c := range []string{IssuerCauseBlockedAddress, IssuerCauseDNS, IssuerCauseTLS, IssuerCauseTimeout,
		IssuerCauseIssuerMismatch, IssuerCauseHTTPStatus, IssuerCauseKeyNotFound, IssuerCauseUnreachable, "other"} {
		m := IssuerUnavailableMessage(c)
		if m == "" || ipLike.MatchString(m) {
			t.Fatalf("%s: %q", c, m)
		}
	}
	if !strings.Contains(IssuerUnavailableMessage(IssuerCauseBlockedAddress), "Private networks") {
		t.Fatal("the blocked address text does not say where it is opened")
	}
}

func TestIssuerUnavailableError(t *testing.T) {
	var err error = &IssuerUnavailableError{Cause: IssuerCauseTLS}
	var iu *IssuerUnavailableError
	if !errors.Is(err, ErrIssuerUnavailable) || !errors.As(err, &iu) || iu.Cause != IssuerCauseTLS {
		t.Fatal("IssuerUnavailableError must be ErrIssuerUnavailable with its cause")
	}
}

func TestNearestIssuer(t *testing.T) {
	configured := []string{"https://gitlab.example.com", "https://ci.example.org/oidc"}
	for token, want := range map[string][2]string{
		"https://gitlab.example.com/":       {"https://gitlab.example.com", IssuerDiffTrailingSlash},
		"https://GitLab.example.com":        {"https://gitlab.example.com", IssuerDiffCase},
		"http://gitlab.example.com":         {"https://gitlab.example.com", IssuerDiffScheme},
		"https://gitlab.example.com/gitlab": {"https://gitlab.example.com", IssuerDiffPath},
		"https://ci.example.net/oidc":       {"https://ci.example.org/oidc", IssuerDiffHost},
		"https://unrelated.example.net/x":   {"", ""},
		"https://gitlab.example.com":        {"", ""}, // identical: not a near miss
	} {
		gotIssuer, gotDiff := NearestIssuer(token, configured)
		if gotIssuer != want[0] || gotDiff != want[1] {
			t.Errorf("NearestIssuer(%q) = %q %q, want %q %q", token, gotIssuer, gotDiff, want[0], want[1])
		}
	}
}

func TestPlainIssuer(t *testing.T) {
	for s, ok := range map[string]bool{
		"https://gitlab.example.com":           true,
		"https://gitlab.example.com/sub":       true,
		"http://gitlab.example.com":            false,
		"https://user@gitlab.example.com":      false,
		"https://gitlab.example.com/?q=1":      false,
		"https://gitlab.example.com/#x":        false,
		"https://gitlab.example.com/\u202ex":   false,
		"https://gitlab.example.com/ x":        false,
		"https://" + strings.Repeat("a", 260):  false,
		"":                                     false,
		"call https://phish.example.com today": false,
	} {
		if plainIssuer(s) != ok {
			t.Errorf("plainIssuer(%q) = %v, want %v", s, !ok, ok)
		}
	}
}

// The job is told the rule and its own value, never the configuration's
// listed values.
func TestRuleRefusalMessage(t *testing.T) {
	c := cirun.Claims{Provider: cirun.ProviderGitLab, Repository: "grp/proj", Ref: "refs/heads/main",
		Workflow: "gitlab.example.com/grp/proj//.gitlab-ci.yml@refs/heads/main"}
	refusals := []*cirun.Refusal{
		{Code: cirun.RefuseWorkflow, Detail: `pipeline definition "x" is not listed`, ConfigID: shared.NewID(), ConfigName: "secret-config-name"},
		{Code: cirun.RefuseWorkflow},
		{Code: cirun.RefuseRef, Detail: "ref"},
	}
	m := RuleRefusalMessage(refusals, c)
	for _, want := range []string{"pipeline files it lists", `"gitlab.example.com/grp/proj//.gitlab-ci.yml@refs/heads/main"`,
		"Pipeline definitions", `"refs/heads/main"`, "Branches and tags"} {
		if !strings.Contains(m, want) {
			t.Errorf("message lacks %q: %s", want, m)
		}
	}
	if strings.Contains(m, "secret-config-name") || strings.Count(m, "pipeline files it lists") != 1 {
		t.Fatalf("message names the configuration or repeats a code: %s", m)
	}
}

type memUnverified struct {
	mu   sync.Mutex
	rows []cirun.UnverifiedRefusal
}

func (m *memUnverified) RecordUnverifiedRefusal(_ context.Context, r cirun.UnverifiedRefusal) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rows = append(m.rows, r)
	return nil
}

func (m *memUnverified) ListUnverifiedRefusals(context.Context, shared.ID) ([]cirun.UnverifiedRefusal, error) {
	return nil, nil
}

func (m *memUnverified) total() (writes, count int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.rows {
		count += r.Count
	}
	return len(m.rows), count
}

// Repeats within the throttle are counted, not written; a caller-chosen
// issuer that is not a plain https address is not kept; no store, nothing.
func TestRecordUnverified_ThrottleAndIssuerHygiene(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 18, 8, 0, 0, 0, time.UTC)
	s := &Service{log: logger.NewNop(), now: func() time.Time { return now }}
	tenant := shared.NewID()
	s.recordUnverified(ctx, tenant, "https://gitlab.example.com", UnverifiedNoConfiguration, "") // no store: no panic

	st := &memUnverified{}
	s.SetUnverifiedRefusalStore(st)
	for i := 0; i < 5; i++ {
		s.recordUnverified(ctx, tenant, "https://gitlab.example.com", UnverifiedNoConfiguration, "")
	}
	if w, c := st.total(); w != 1 || c != 1 {
		t.Fatalf("within the throttle: %d writes, count %d; want 1, 1", w, c)
	}
	now = now.Add(unverifiedThrottle + time.Second)
	s.recordUnverified(ctx, tenant, "https://gitlab.example.com", UnverifiedNoConfiguration, "")
	if w, c := st.total(); w != 2 || c != 6 {
		t.Fatalf("after the throttle: %d writes, count %d; want 2, 6", w, c)
	}
	s.recordUnverified(ctx, tenant, "javascript:alert(1)", UnverifiedNotVerified, "")
	s.recordUnverified(ctx, shared.ID{}, "https://gitlab.example.com", UnverifiedNotVerified, "")
	st.mu.Lock()
	last := st.rows[len(st.rows)-1]
	n := len(st.rows)
	st.mu.Unlock()
	if n != 3 || last.Issuer != "" || last.Reason != UnverifiedNotVerified {
		t.Fatalf("hygiene: %d rows, last %+v", n, last)
	}
}

// cfgRepo answers only the configurations a test lists.
type cfgRepo struct {
	cirun.Repository
	cfgs []cirun.TrustConfig
}

func (r cfgRepo) ListTrustConfigs(context.Context, shared.ID) ([]cirun.TrustConfig, error) {
	return r.cfgs, nil
}

func newUnverifiedService(now *time.Time, issuers ...string) (*Service, *memUnverified) {
	cfgs := make([]cirun.TrustConfig, 0, len(issuers))
	for _, i := range issuers {
		cfgs = append(cfgs, cirun.TrustConfig{Issuer: i})
	}
	s := &Service{log: logger.NewNop(), now: func() time.Time { return *now }, repo: cfgRepo{cfgs: cfgs}}
	st := &memUnverified{}
	s.SetUnverifiedRefusalStore(st)
	return s, st
}

// Review finding R1: every usual configured issuer has an empty path, so a
// made-up pathless issuer on another host counted as close (same path) and
// was stored under its own name. Only the same host is close.
func TestRecordUnverified_PathlessFarIssuerIsNotKept(t *testing.T) {
	now := time.Date(2026, 11, 18, 8, 0, 0, 0, time.UTC)
	s, st := newUnverifiedService(&now, "https://gitlab.example.com")
	ctx := context.Background()
	tenant := shared.NewID()
	s.recordUnverified(ctx, tenant, "https://junk.example.org", UnverifiedNoConfiguration, "")
	s.recordUnverified(ctx, tenant, "https://gitlab.example.com/gitlab", UnverifiedNoConfiguration, "") // same host, other path
	s.recordUnverified(ctx, tenant, "https://GitLab.example.com", UnverifiedNoConfiguration, "")        // case
	s.recordUnverified(ctx, tenant, "https://gitlab.example.com:8443", UnverifiedNoConfiguration, "")   // port
	got := map[string]bool{}
	for _, r := range st.rows {
		got[r.Issuer] = true
	}
	if got["https://junk.example.org"] {
		t.Fatalf("a made-up pathless issuer was stored under its name: %v", got)
	}
	for _, want := range []string{"", "https://gitlab.example.com/gitlab", "https://GitLab.example.com", "https://gitlab.example.com:8443"} {
		if !got[want] {
			t.Errorf("missing record for %q: %v", want, got)
		}
	}
}

// Review finding R1 (starvation): a flood of made-up issuers spends the new
// record budget, but the keys_unavailable and not_verified records of the
// tenant's real issuer are still written (not budgeted).
func TestRecordUnverified_FloodDoesNotStarveRealIssuerRecords(t *testing.T) {
	now := time.Date(2026, 11, 18, 8, 0, 0, 0, time.UTC)
	s, st := newUnverifiedService(&now, "https://gitlab.example.com")
	ctx := context.Background()
	tenant := shared.NewID()
	for i := 0; i < 3*unverifiedNewPerHour; i++ {
		// Same host, distinct paths: the budget is what stops them.
		s.recordUnverified(ctx, tenant, fmt.Sprintf("https://gitlab.example.com/p%03d", i), UnverifiedNoConfiguration, "")
	}
	_, before := st.total()
	s.recordUnverified(ctx, tenant, "https://gitlab.example.com", UnverifiedKeysUnavailable, IssuerCauseKeyNotFound)
	s.recordUnverified(ctx, tenant, "https://gitlab.example.com", UnverifiedNotVerified, "")
	st.mu.Lock()
	defer st.mu.Unlock()
	var keys, notVerified, noCfg int
	for _, r := range st.rows {
		switch r.Reason {
		case UnverifiedKeysUnavailable:
			keys++
		case UnverifiedNotVerified:
			notVerified++
		default:
			noCfg++
		}
	}
	if noCfg != unverifiedNewPerHour || keys != 1 || notVerified != 1 || before == 0 {
		t.Fatalf("no_configuration writes %d (want %d), keys_unavailable %d, not_verified %d (want 1, 1)", noCfg, unverifiedNewPerHour, keys, notVerified)
	}
}

// Review finding N1: tokens whose issuer is the configured one plus any
// number of trailing slashes all match the configuration, so they are one
// record, not one per variant.
func TestRecordUnverified_SlashVariantsOfMatchedIssuerAreOneRecord(t *testing.T) {
	now := time.Date(2026, 11, 18, 8, 0, 0, 0, time.UTC)
	s, st := newUnverifiedService(&now, "https://gitlab.example.com")
	ctx := context.Background()
	tenant := shared.NewID()
	for _, reason := range []string{UnverifiedNotVerified, UnverifiedKeysUnavailable} {
		for i := 0; i < 50; i++ {
			s.recordUnverified(ctx, tenant, "https://gitlab.example.com"+strings.Repeat("/", i), reason, "")
		}
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if len(st.rows) != 2 {
		t.Fatalf("slash variants wrote %d records, want 2 (one per reason): %v", len(st.rows), st.rows)
	}
	for _, r := range st.rows {
		if r.Issuer != "https://gitlab.example.com" {
			t.Errorf("record issuer %q, want the matched configuration's issuer", r.Issuer)
		}
	}
}
