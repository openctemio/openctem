// Package signupevent describes the sign-up events the platform console shows
// (docs/architecture/signup-activity.md): one event per account created,
// organization created and access request submitted, holding aggregate data
// only.
//
// An event keeps the registrable domain of the email address and the client
// network prefix (/24 for IPv4, /48 for IPv6). It never keeps the email local
// part, the full address, a name or a user agent.
package signupevent

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Kind is what happened.
type Kind string

// Kinds.
const (
	KindAccountCreated      Kind = "account_created"
	KindOrganizationCreated Kind = "organization_created"
	KindAccessRequested     Kind = "access_requested"
)

// Valid reports whether k is a known kind.
func (k Kind) Valid() bool {
	switch k {
	case KindAccountCreated, KindOrganizationCreated, KindAccessRequested:
		return true
	}
	return false
}

// Kinds lists every kind, in display order.
func Kinds() []Kind {
	return []Kind{KindAccountCreated, KindOrganizationCreated, KindAccessRequested}
}

// Source is the path that produced the event.
type Source string

// Sources.
const (
	// SourcePassword: public registration with email and password.
	SourcePassword Source = "password"
	// SourceInvitation: registration with an invitation addressed to the
	// email.
	SourceInvitation Source = "invitation"
	// SourceOAuth: first sign-in with a social identity provider.
	SourceOAuth Source = "oauth"
	// SourceSSO: just-in-time account of an organization's single sign-on
	// (OIDC or SAML).
	SourceSSO Source = "sso"
	// SourceSelfService: an organization a signed-in person created.
	SourceSelfService Source = "self_service"
	// SourcePublic: the public request-access form.
	SourcePublic Source = "public"
	// SourceConsole: an organization a platform administrator created.
	SourceConsole Source = "console"
	// SourceAccessRequest: an organization created by approving an access
	// request.
	SourceAccessRequest Source = "access_request"
	// SourceControlPlane: an organization the hosted service's control plane
	// provisioned.
	SourceControlPlane Source = "control_plane"
)

// SelfService reports whether the person signing up drove the event. Only
// those events carry a client network prefix and count toward the burst
// alerts: an organization an administrator or the control plane created
// comes from the operator's own address.
func (s Source) SelfService() bool {
	switch s {
	case SourcePassword, SourceInvitation, SourceOAuth, SourceSSO, SourceSelfService, SourcePublic:
		return true
	}
	return false
}

// Event is what a sign-up path reports. Email is reduced to its registrable
// domain and the client address (from the request context) to its network
// prefix before anything is stored.
type Event struct {
	Kind     Kind
	Source   Source
	Email    string
	TenantID shared.ID
	UserID   shared.ID
}

// Recorder records a sign-up event. It is best effort: it never fails or
// holds up the sign-up that reports it.
type Recorder interface {
	Record(ctx context.Context, e Event)
}

// Record is one stored event.
type Record struct {
	ID          int64
	Kind        Kind
	Source      Source
	EmailDomain string
	IPPrefix    string
	TenantID    *shared.ID
	UserID      *shared.ID
	OccurredAt  time.Time
}

// Filter selects stored events.
type Filter struct {
	Kind   Kind // empty: every kind
	Since  time.Time
	Limit  int
	Offset int
}

// DailyCount is the number of events of one kind on one UTC day.
type DailyCount struct {
	Day   time.Time
	Kind  Kind
	Count int64
}

// Repository stores the events.
type Repository interface {
	Insert(ctx context.Context, r Record) error
	List(ctx context.Context, f Filter) ([]Record, int64, error)
	Daily(ctx context.Context, since time.Time) ([]DailyCount, error)
	// Purge deletes events older than before and returns how many went.
	Purge(ctx context.Context, before time.Time) (int64, error)
}

// EmailDomain returns the registrable domain (eTLD+1) of an email address,
// lower-cased: "a.b@mail.example.co.uk" gives "example.co.uk". An address
// without a usable domain gives "".
func EmailDomain(email string) string {
	email = strings.TrimSpace(email)
	at := strings.LastIndex(email, "@")
	if at < 0 || at == len(email)-1 {
		return ""
	}
	host := strings.TrimSuffix(strings.ToLower(email[at+1:]), ".")
	if host == "" || len(host) > 253 || net.ParseIP(strings.Trim(host, "[]")) != nil {
		return ""
	}
	d, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		return ""
	}
	return d
}

// IPPrefix returns the network of a client address: /24 for IPv4 (and
// IPv4-mapped IPv6), /48 for IPv6, in CIDR notation. An address that does not
// parse gives "".
func IPPrefix(ip string) string {
	ip = strings.TrimSpace(ip)
	if h, _, err := net.SplitHostPort(ip); err == nil {
		ip = h
	}
	parsed := net.ParseIP(strings.Trim(ip, "[]"))
	if parsed == nil {
		return ""
	}
	if v4 := parsed.To4(); v4 != nil {
		return (&net.IPNet{IP: v4.Mask(net.CIDRMask(24, 32)), Mask: net.CIDRMask(24, 32)}).String()
	}
	return (&net.IPNet{IP: parsed.Mask(net.CIDRMask(48, 128)), Mask: net.CIDRMask(48, 128)}).String()
}

// ThresholdsSettingKey is the platform_settings key of the burst thresholds.
const ThresholdsSettingKey = "signup_burst_thresholds"

// Bounds of the burst thresholds.
const (
	MaxThreshold      = 100_000
	MinWindowMinutes  = 5
	MaxWindowMinutes  = 1440
	MaxIgnoredDomains = 50
)

// Errors of the thresholds store.
var (
	ErrThresholdsNotFound = fmt.Errorf("%w: sign-up burst thresholds not stored", shared.ErrNotFound)
	ErrVersionConflict    = fmt.Errorf("%w: the setting was changed by someone else", shared.ErrConflict)
)

// BurstThresholds raise an alert when, within one window, the events of one
// kind from one client network prefix or one email domain reach a
// threshold. 0 turns a dimension off.
type BurstThresholds struct {
	PerIPPrefix    int `json:"per_ip_prefix"`
	PerEmailDomain int `json:"per_email_domain"`
	WindowMinutes  int `json:"window_minutes"`
	// IgnoredDomains are email domains the per-domain count skips (large
	// consumer mail providers, the operator's own domain). The per-prefix
	// count still covers them.
	IgnoredDomains []string `json:"ignored_domains"`
}

// DefaultBurstThresholds: 10 events of a kind from one /24 (or /48), or 20
// from one email domain, within an hour.
func DefaultBurstThresholds() BurstThresholds {
	return BurstThresholds{PerIPPrefix: 10, PerEmailDomain: 20, WindowMinutes: 60, IgnoredDomains: []string{}}
}

// Normalize lower-cases, trims, de-duplicates and sorts the ignored domains.
func (t BurstThresholds) Normalize() BurstThresholds {
	seen := make(map[string]struct{}, len(t.IgnoredDomains))
	out := make([]string, 0, len(t.IgnoredDomains))
	for _, d := range t.IgnoredDomains {
		d = strings.TrimSuffix(strings.TrimPrefix(strings.ToLower(strings.TrimSpace(d)), "@"), ".")
		if d == "" {
			continue
		}
		if _, ok := seen[d]; ok {
			continue
		}
		seen[d] = struct{}{}
		out = append(out, d)
	}
	sort.Strings(out)
	t.IgnoredDomains = out
	return t
}

var reDomain = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$`)

// Validate refuses a negative or absurd threshold, a window outside
// [MinWindowMinutes, MaxWindowMinutes] and an ignored domain that is not a
// domain name. Call it on a normalized value.
func (t BurstThresholds) Validate() error {
	for _, v := range []int{t.PerIPPrefix, t.PerEmailDomain} {
		if v < 0 || v > MaxThreshold {
			return fmt.Errorf("%w: each threshold is between 0 (off) and %d", shared.ErrValidation, MaxThreshold)
		}
	}
	if t.WindowMinutes < MinWindowMinutes || t.WindowMinutes > MaxWindowMinutes {
		return fmt.Errorf("%w: the window is between %d and %d minutes", shared.ErrValidation, MinWindowMinutes, MaxWindowMinutes)
	}
	if len(t.IgnoredDomains) > MaxIgnoredDomains {
		return fmt.Errorf("%w: at most %d ignored domains", shared.ErrValidation, MaxIgnoredDomains)
	}
	for _, d := range t.IgnoredDomains {
		if len(d) > 253 || !reDomain.MatchString(d) {
			return fmt.Errorf("%w: %q is not a domain name", shared.ErrValidation, d)
		}
	}
	return nil
}

// Ignores reports whether the per-domain count skips domain.
func (t BurstThresholds) Ignores(domain string) bool {
	for _, d := range t.IgnoredDomains {
		if d == domain {
			return true
		}
	}
	return false
}

// ThresholdsStore persists the thresholds (platform_settings). Get returns
// ErrThresholdsNotFound when nothing is stored; Set returns
// ErrVersionConflict when the stored version is not expectedVersion (0:
// nothing stored yet).
type ThresholdsStore interface {
	GetBurstThresholds(ctx context.Context) (BurstThresholds, int, error)
	SetBurstThresholds(ctx context.Context, t BurstThresholds, expectedVersion int, by string, at time.Time) (int, error)
}
