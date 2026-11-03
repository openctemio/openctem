package licensekey

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/openctemio/openctem/api/pkg/domain/limits"
)

// Type is the kind of license.
type Type string

// License types.
const (
	TypeEnterprise    Type = "enterprise"
	TypeTrial         Type = "trial"
	TypeNonProduction Type = "non_production"
)

// Claims is the signed payload of a license. Every vendor-specific string
// (issuer, portals, image references, signing identities) travels here, so
// the open core names no vendor. Unknown keys are refused: a claim this
// build does not know cannot be silently ignored.
type Claims struct {
	Schema     string    `json:"schema"`
	ID         string    `json:"id"`
	CustomerID string    `json:"customer_id"`
	Type       Type      `json:"type"`
	Licensee   Licensee  `json:"licensee"`
	IssuedAt   time.Time `json:"issued_at"`
	NotBefore  time.Time `json:"not_before"`
	ExpiresAt  time.Time `json:"expires_at"`
	// GraceDays is required (a pointer tells a missing value from 0).
	GraceDays    *int                      `json:"grace_days"`
	Entitlements []limits.GrantKey         `json:"entitlements"`
	Meters       map[string]int64          `json:"meters,omitempty"`
	Addons       map[limits.GrantKey]Addon `json:"addons,omitempty"`
	Bind         *Binding                  `json:"bind,omitempty"`
	Renewal      *Renewal                  `json:"renewal,omitempty"`
	Issuer       Issuer                    `json:"issuer"`
}

// Licensee names the licensed organization (never a person's e-mail).
type Licensee struct {
	Name string `json:"name"`
}

// Addon describes a separately shipped component an entitlement covers.
type Addon struct {
	Image                string `json:"image"`
	CosignIdentityRegexp string `json:"cosign_identity_regexp,omitempty"`
	OIDCIssuer           string `json:"oidc_issuer,omitempty"`
	MinVersion           string `json:"min_version,omitempty"`
}

// Binding optionally pins a license to installations; empty = not bound.
type Binding struct {
	InstallationIDs []string `json:"installation_ids"`
}

// Renewal is the optional, opt-in renewal location.
type Renewal struct {
	URL     string `json:"url"`
	Default string `json:"default,omitempty"`
}

// Issuer is shown on the subscription page.
type Issuer struct {
	Name       string `json:"name"`
	PortalURL  string `json:"portal_url,omitempty"`
	SupportURL string `json:"support_url,omitempty"`
}

// Bounds and formats of the claims.
const (
	maxEntitlements = 64
	maxMeters       = 32
	maxBindings     = 64
	maxNameRunes    = 200
	maxURLBytes     = 512
	maxImageBytes   = 256
	maxRegexpBytes  = 512
)

var (
	licenseIDPattern  = regexp.MustCompile(`^lic_[0-9A-Za-z]{4,64}$`)
	customerIDPattern = regexp.MustCompile(`^cus_[0-9A-Za-z]{4,64}$`)
	meterPattern      = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}(\.[a-z][a-z0-9_]{0,63})?$`)
	uuidPattern       = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	versionPattern    = regexp.MustCompile(`^v?[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}([-+][0-9A-Za-z.-]{1,64})?$`)
)

// Grace is the grace window after expires_at.
func (c *Claims) Grace() time.Duration {
	if c.GraceDays == nil {
		return 0
	}
	return time.Duration(*c.GraceDays) * 24 * time.Hour
}

// GraceEndsAt is when the license becomes expired.
func (c *Claims) GraceEndsAt() time.Time { return c.ExpiresAt.Add(c.Grace()) }

// Grants reports whether the license names key (whatever its state).
func (c *Claims) Grants(key limits.GrantKey) bool {
	for _, k := range c.Entitlements {
		if k == key {
			return true
		}
	}
	return false
}

// BoundTo reports whether the license may be used by installationID: an
// unbound license anywhere, a bound one only by a listed installation.
func (c *Claims) BoundTo(installationID string) bool {
	if c.Bind == nil || len(c.Bind.InstallationIDs) == 0 {
		return true
	}
	return installationID != "" && contains(c.Bind.InstallationIDs, strings.ToLower(installationID))
}

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrInvalidClaims}, a...)...)
}

// validate checks every claim; any failure refuses the license.
//
//nolint:cyclop // one flat list of independent checks
func (c *Claims) validate() error {
	switch {
	case c.Schema != Schema:
		return invalid("schema %q", c.Schema)
	case !licenseIDPattern.MatchString(c.ID):
		return invalid("id")
	case !customerIDPattern.MatchString(c.CustomerID):
		return invalid("customer_id")
	case c.Type != TypeEnterprise && c.Type != TypeTrial && c.Type != TypeNonProduction:
		return invalid("type %q", c.Type)
	}
	if err := checkName("licensee.name", c.Licensee.Name); err != nil {
		return err
	}
	if strings.Contains(c.Licensee.Name, "@") {
		return invalid("licensee.name is an organization name, not an e-mail")
	}
	switch {
	case c.IssuedAt.IsZero() || c.NotBefore.IsZero() || c.ExpiresAt.IsZero():
		return invalid("issued_at, not_before and expires_at are required")
	case !c.ExpiresAt.After(c.NotBefore):
		return invalid("expires_at is not after not_before")
	case c.ExpiresAt.Sub(c.NotBefore) > MaxTerm:
		return invalid("term longer than %s", MaxTerm)
	case c.IssuedAt.After(c.ExpiresAt):
		return invalid("issued_at is after expires_at")
	case c.GraceDays == nil:
		return invalid("grace_days is required")
	case *c.GraceDays < 0 || *c.GraceDays > MaxGraceDays:
		return invalid("grace_days must be 0 to %d", MaxGraceDays)
	}
	if err := c.validateEntitlements(); err != nil {
		return err
	}
	if len(c.Meters) > maxMeters {
		return invalid("more than %d meters", maxMeters)
	}
	for name, v := range c.Meters {
		if !meterPattern.MatchString(name) || v < 0 {
			return invalid("meter %q", name)
		}
	}
	if c.Bind != nil {
		if len(c.Bind.InstallationIDs) > maxBindings {
			return invalid("more than %d bound installations", maxBindings)
		}
		for _, id := range c.Bind.InstallationIDs {
			if !uuidPattern.MatchString(id) {
				return invalid("bind.installation_ids: %q is not a lower-case UUID", id)
			}
		}
	}
	if c.Renewal != nil {
		if err := checkURL("renewal.url", c.Renewal.URL, true); err != nil {
			return err
		}
		if c.Renewal.Default != "" && c.Renewal.Default != "on" && c.Renewal.Default != "off" {
			return invalid("renewal.default %q", c.Renewal.Default)
		}
	}
	if err := checkName("issuer.name", c.Issuer.Name); err != nil {
		return err
	}
	if err := checkURL("issuer.portal_url", c.Issuer.PortalURL, false); err != nil {
		return err
	}
	return checkURL("issuer.support_url", c.Issuer.SupportURL, false)
}

func (c *Claims) validateEntitlements() error {
	if len(c.Entitlements) == 0 || len(c.Entitlements) > maxEntitlements {
		return invalid("1 to %d entitlements", maxEntitlements)
	}
	seen := map[limits.GrantKey]bool{}
	for _, k := range c.Entitlements {
		if !limits.IsGrantKey(k) {
			return fmt.Errorf("%w: %q", ErrUnknownEntitlement, k)
		}
		if seen[k] {
			return invalid("entitlement %q listed twice", k)
		}
		seen[k] = true
	}
	for k, a := range c.Addons {
		if !seen[k] {
			return invalid("addons.%s without the entitlement", k)
		}
		if a.Image == "" || len(a.Image) > maxImageBytes || strings.ContainsFunc(a.Image, unicode.IsSpace) {
			return invalid("addons.%s.image", k)
		}
		if len(a.CosignIdentityRegexp) > maxRegexpBytes {
			return invalid("addons.%s.cosign_identity_regexp is too long", k)
		}
		if a.CosignIdentityRegexp != "" {
			if _, err := regexp.Compile(a.CosignIdentityRegexp); err != nil {
				return invalid("addons.%s.cosign_identity_regexp does not compile", k)
			}
		}
		if err := checkURL("addons.oidc_issuer", a.OIDCIssuer, false); err != nil {
			return err
		}
		if a.MinVersion != "" && !versionPattern.MatchString(a.MinVersion) {
			return invalid("addons.%s.min_version", k)
		}
	}
	return nil
}

func checkName(field, s string) error {
	n := utf8.RuneCountInString(s)
	if strings.TrimSpace(s) == "" || n > maxNameRunes || !utf8.ValidString(s) ||
		strings.ContainsFunc(s, unicode.IsControl) {
		return invalid("%s: 1 to %d printable characters", field, maxNameRunes)
	}
	return nil
}

// checkURL accepts an absolute https URL with a host and no user info.
func checkURL(field, s string, required bool) error {
	if s == "" {
		if required {
			return invalid("%s is required", field)
		}
		return nil
	}
	u, err := url.Parse(s)
	if len(s) > maxURLBytes || err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return invalid("%s must be an https URL", field)
	}
	return nil
}
