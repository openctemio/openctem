// Package brand is the product brand of one installation: the name, logos,
// color and links that users see in the console, emails, reports and
// notifications. It is configuration, not code: a differently named build or
// a white-label deployment sets BRAND_* (or a BRAND_FILE) and changes nothing
// else. Technical identifiers (module paths, image names, OPENCTEM_* variables,
// header and cookie names, the sensor protocol) never come from here.
//
// Design: api/docs/architecture/brand.md.
package brand

import (
	"errors"
	"fmt"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// The upstream product. DefaultName is also the name a "Powered by" line
// credits, so it stays fixed whatever the configured brand is.
const (
	DefaultName       = "OpenCTEM"
	DefaultDocsURL    = "https://docs.openctem.io"
	DefaultWebsiteURL = "https://openctem.io"
	DefaultEmail      = "info@openctem.io"
)

// Limits on configured text.
const (
	maxNameLen   = 64
	maxFooterLen = 500
	maxURLLen    = 2048
)

// AssetKind names one image a brand can carry.
type AssetKind string

const (
	AssetLogoLight AssetKind = "logo-light"
	AssetLogoDark  AssetKind = "logo-dark"
	AssetFavicon   AssetKind = "favicon"
)

// AssetKinds lists every kind, in a stable order.
var AssetKinds = []AssetKind{AssetLogoLight, AssetLogoDark, AssetFavicon}

// Brand is the instance brand. The zero value is not valid: start from
// Default().
type Brand struct {
	Name         string
	ShortName    string
	PrimaryColor string // "#rrggbb"; "" keeps the theme's color
	DocsURL      string
	WebsiteURL   string
	SupportURL   string
	SupportEmail string
	TermsURL     string
	PrivacyURL   string
	EmailFooter  string
	// PoweredBy adds a "Powered by OpenCTEM" credit where the brand is shown,
	// when the brand is not OpenCTEM itself.
	PoweredBy bool
	// Assets are the operator's images; a missing kind keeps the built-in one.
	Assets map[AssetKind]Asset
}

// Default is today's OpenCTEM brand.
func Default() Brand {
	return Brand{
		Name:         DefaultName,
		ShortName:    DefaultName,
		DocsURL:      DefaultDocsURL,
		WebsiteURL:   DefaultWebsiteURL,
		SupportEmail: DefaultEmail,
		PoweredBy:    true,
	}
}

// Short is the short name, falling back to the name.
func (b Brand) Short() string {
	if b.ShortName != "" {
		return b.ShortName
	}
	return b.Name
}

// DisplayName is the name, falling back to the default (a Brand built
// without Default() still names the product).
func (b Brand) DisplayName() string {
	if b.Name != "" {
		return b.Name
	}
	return DefaultName
}

// ShowPoweredBy reports whether the "Powered by OpenCTEM" credit is shown.
func (b Brand) ShowPoweredBy() bool {
	return b.PoweredBy && b.DisplayName() != DefaultName
}

// Docs is the documentation origin, without a trailing slash.
func (b Brand) Docs() string {
	if b.DocsURL == "" {
		return DefaultDocsURL
	}
	return strings.TrimRight(b.DocsURL, "/")
}

// DocsLink rewrites a link to the default documentation site onto the
// configured one, keeping the path. Other links are returned unchanged.
func (b Brand) DocsLink(link string) string {
	if !strings.HasPrefix(link, DefaultDocsURL) || b.Docs() == DefaultDocsURL {
		return link
	}
	rest := strings.TrimPrefix(link, DefaultDocsURL)
	if rest != "" && rest[0] != '/' && rest[0] != '#' && rest[0] != '?' {
		return link // another host that merely starts with the same text
	}
	return b.Docs() + rest
}

var colorRE = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)

// Validate checks every field. A brand with an invalid value is refused at
// startup rather than shown half-applied.
func (b Brand) Validate() error {
	var errs []error
	if err := validateName("name", b.Name, true); err != nil {
		errs = append(errs, err)
	}
	if err := validateName("short name", b.ShortName, false); err != nil {
		errs = append(errs, err)
	}
	if b.PrimaryColor != "" && !colorRE.MatchString(b.PrimaryColor) {
		errs = append(errs, fmt.Errorf("primary color %q: want #rrggbb", b.PrimaryColor))
	}
	for _, u := range []struct{ field, v string }{
		{"docs URL", b.DocsURL}, {"website URL", b.WebsiteURL}, {"support URL", b.SupportURL},
		{"terms URL", b.TermsURL}, {"privacy URL", b.PrivacyURL},
	} {
		if err := ValidateURL(u.v); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", u.field, err))
		}
	}
	if err := validateEmail(b.SupportEmail); err != nil {
		errs = append(errs, fmt.Errorf("support email: %w", err))
	}
	if err := validateFooter(b.EmailFooter); err != nil {
		errs = append(errs, fmt.Errorf("email footer: %w", err))
	}
	return errors.Join(errs...)
}

func validateName(field, v string, required bool) error {
	if v == "" {
		if required {
			return fmt.Errorf("%s is required", field)
		}
		return nil
	}
	if !utf8.ValidString(v) || utf8.RuneCountInString(v) > maxNameLen {
		return fmt.Errorf("%s: at most %d characters of valid UTF-8", field, maxNameLen)
	}
	if strings.TrimSpace(v) != v {
		return fmt.Errorf("%s: no leading or trailing spaces", field)
	}
	for _, r := range v {
		// Markup and placeholder characters: the name is put into HTML,
		// chat markup and message templates ("{product}").
		if unicode.IsControl(r) || strings.ContainsRune("<>{}`*_~|[]\\", r) {
			return fmt.Errorf("%s: character %q is not allowed", field, r)
		}
	}
	return nil
}

func validateFooter(v string) error {
	if utf8.RuneCountInString(v) > maxFooterLen || !utf8.ValidString(v) {
		return fmt.Errorf("at most %d characters of valid UTF-8", maxFooterLen)
	}
	for _, r := range v {
		if r != '\n' && unicode.IsControl(r) {
			return fmt.Errorf("character %q is not allowed", r)
		}
	}
	return nil
}

// ValidateURL accepts "" or an absolute https URL with a host and no
// credentials. Links in emails and on the sign-in page must not downgrade
// to http or run script (javascript:, data:).
func ValidateURL(v string) error {
	if v == "" {
		return nil
	}
	if len(v) > maxURLLen {
		return fmt.Errorf("longer than %d characters", maxURLLen)
	}
	u, err := url.Parse(v)
	if err != nil {
		return errors.New("not a URL")
	}
	if u.Scheme != "https" {
		return fmt.Errorf("%q: must be an https URL", v)
	}
	if u.Host == "" || u.Hostname() == "" {
		return fmt.Errorf("%q: has no host", v)
	}
	if u.User != nil {
		return fmt.Errorf("%q: must not carry credentials", v)
	}
	for _, r := range v {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return fmt.Errorf("%q: contains spaces or control characters", v)
		}
	}
	return nil
}

func validateEmail(v string) error {
	if v == "" {
		return nil
	}
	a, err := mail.ParseAddress(v)
	if err != nil || a.Address != v || a.Name != "" {
		return fmt.Errorf("%q: want a bare address such as support@example.com", v)
	}
	return nil
}

// AssetPath is where the API serves a brand image.
const AssetPath = "/api/v1/brand/assets/"

// Public is the brand as the public GET /api/v1/brand returns it: nothing
// secret, nothing tenant-specific. An image URL is "" when the built-in
// image applies; otherwise it carries the image's version so a changed
// image is fetched again.
type Public struct {
	Name         string `json:"name"`
	ShortName    string `json:"short_name"`
	PrimaryColor string `json:"primary_color"`
	DocsURL      string `json:"docs_url"`
	WebsiteURL   string `json:"website_url"`
	SupportURL   string `json:"support_url"`
	SupportEmail string `json:"support_email"`
	TermsURL     string `json:"terms_url"`
	PrivacyURL   string `json:"privacy_url"`
	EmailFooter  string `json:"email_footer"`
	PoweredBy    bool   `json:"powered_by"`
	LogoLightURL string `json:"logo_light_url"`
	LogoDarkURL  string `json:"logo_dark_url"`
	FaviconURL   string `json:"favicon_url"`
}

// Public returns the public view of the brand.
func (b Brand) Public() Public {
	url := func(k AssetKind) string {
		a, ok := b.Assets[k]
		if !ok {
			return ""
		}
		return AssetPath + string(k) + "?v=" + a.ETag
	}
	p := Public{
		Name:         b.DisplayName(),
		ShortName:    b.Short(),
		PrimaryColor: b.PrimaryColor,
		DocsURL:      b.Docs(),
		WebsiteURL:   b.WebsiteURL,
		SupportURL:   b.SupportURL,
		SupportEmail: b.SupportEmail,
		TermsURL:     b.TermsURL,
		PrivacyURL:   b.PrivacyURL,
		EmailFooter:  b.EmailFooter,
		PoweredBy:    b.ShowPoweredBy(),
		LogoLightURL: url(AssetLogoLight),
		LogoDarkURL:  url(AssetLogoDark),
		FaviconURL:   url(AssetFavicon),
	}
	if p.LogoDarkURL == "" {
		p.LogoDarkURL = p.LogoLightURL
	}
	return p
}
