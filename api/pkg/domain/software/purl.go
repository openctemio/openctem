package software

// Package URL identity of catalog packages. Design: api/docs/rfcs/RFC-070-software-components-inventory.md.

import (
	"errors"
	"net/url"
	"regexp"
	"strings"
)

// Package URL limits, matching the catalog columns.
const (
	MaxPURLType      = 32
	MaxPURLNamespace = 256
	MaxPURLName      = 256
	MaxPackageVer    = 128
)

// Package URL types the parser treats specially.
const (
	typeNPM   = "npm"
	typePyPI  = "pypi"
	typeMaven = "maven"
)

// ErrInvalidPURL is returned for a string that is not a usable package URL.
var ErrInvalidPURL = errors.New("invalid package URL")

var purlTypeRe = regexp.MustCompile(`^[a-z][a-z0-9.+-]*$`)

// PURL is a parsed package URL (pkg:type/namespace/name@version?qualifiers#subpath).
// Type, Namespace and Name are the package identity; Version and the
// distribution qualifiers identify the version.
type PURL struct {
	Type       string
	Namespace  string
	Name       string
	Version    string
	Qualifiers map[string]string
}

// lowerCaseTypes are the package URL types whose namespace and name are case
// insensitive (the package URL specification lower-cases them).
var lowerCaseTypes = map[string]bool{"npm": true, "pypi": true, "github": true, "bitbucket": true, "composer": true}

// ParsePURL parses and canonicalises a package URL. Percent-encoded segments
// are decoded; the subpath is dropped; a PyPI name is lower-cased with "_"
// replaced by "-".
func ParsePURL(s string) (PURL, error) {
	s = strings.TrimSpace(s)
	if len(s) < 5 || !strings.EqualFold(s[:4], "pkg:") {
		return PURL{}, ErrInvalidPURL
	}
	body := strings.TrimLeft(s[4:], "/")
	if i := strings.IndexByte(body, '#'); i >= 0 {
		body = body[:i]
	}
	var p PURL
	if i := strings.IndexByte(body, '?'); i >= 0 {
		p.Qualifiers = parseQualifiers(body[i+1:])
		body = body[:i]
	}
	if at := strings.LastIndexByte(body, '@'); at >= 0 && at > strings.LastIndexByte(body, '/') {
		v, err := url.PathUnescape(body[at+1:])
		if err != nil {
			return PURL{}, ErrInvalidPURL
		}
		p.Version = strings.TrimSpace(v)
		body = body[:at]
	}
	segs := strings.Split(strings.Trim(body, "/"), "/")
	if len(segs) < 2 {
		return PURL{}, ErrInvalidPURL
	}
	p.Type = strings.ToLower(segs[0])
	decoded := make([]string, 0, len(segs)-1)
	for _, seg := range segs[1:] {
		d, err := url.PathUnescape(seg)
		if err != nil || d == "" {
			return PURL{}, ErrInvalidPURL
		}
		decoded = append(decoded, d)
	}
	p.Name = decoded[len(decoded)-1]
	p.Namespace = strings.Join(decoded[:len(decoded)-1], "/")
	if lowerCaseTypes[p.Type] {
		p.Namespace = strings.ToLower(p.Namespace)
		p.Name = strings.ToLower(p.Name)
	}
	if p.Type == typePyPI {
		p.Name = strings.ReplaceAll(p.Name, "_", "-")
	}
	if err := p.validate(); err != nil {
		return PURL{}, err
	}
	return p, nil
}

func (p PURL) validate() error {
	switch {
	case len(p.Type) > MaxPURLType || !purlTypeRe.MatchString(p.Type),
		p.Name == "" || len(p.Name) > MaxPURLName,
		len(p.Namespace) > MaxPURLNamespace,
		len(p.Version) > MaxPackageVer:
		return ErrInvalidPURL
	}
	return nil
}

func parseQualifiers(q string) map[string]string {
	out := map[string]string{}
	for _, kv := range strings.Split(q, "&") {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || k == "" {
			continue
		}
		if d, err := url.QueryUnescape(v); err == nil {
			v = d
		}
		out[strings.ToLower(k)] = v
		if len(out) >= 16 {
			break
		}
	}
	return out
}

// Base is the version-less package URL: pkg:type/namespace/name.
func (p PURL) Base() string {
	var b strings.Builder
	b.WriteString("pkg:")
	b.WriteString(p.Type)
	b.WriteByte('/')
	if p.Namespace != "" {
		b.WriteString(p.Namespace)
		b.WriteByte('/')
	}
	b.WriteString(p.Name)
	return b.String()
}

// String is the canonical package URL with its version and without
// qualifiers, the form stored in software_versions.purl.
func (p PURL) String() string {
	if p.Version == "" {
		return p.Base()
	}
	return p.Base() + "@" + p.Version
}

// DistroQualifier is the build qualifier of an OS package version (the distro
// and arch qualifiers), kept apart from the upstream version.
func (p PURL) DistroQualifier() string {
	switch p.Type {
	case "deb", "rpm", "apk":
	default:
		return ""
	}
	parts := make([]string, 0, 2)
	for _, k := range []string{"distro", "arch"} {
		if v := strings.TrimSpace(p.Qualifiers[k]); v != "" {
			parts = append(parts, v)
		}
	}
	return clip(strings.Join(parts, "/"), 64)
}

// SchemeForType is the version scheme of a package URL type.
func SchemeForType(t string) string {
	switch t {
	case typeNPM:
		return typeNPM
	case "pypi":
		return "pep440"
	case typeMaven:
		return typeMaven
	case "golang":
		return "go"
	case "deb", "rpm", "apk":
		return t
	case "cargo", "nuget":
		return "semver"
	default:
		return "generic"
	}
}

// ecosystemTypes maps the ecosystem labels producers send to package URL types.
var ecosystemTypes = map[string]string{
	"npm": "npm", "yarn": "npm", "pnpm": "npm", "node": "npm",
	"maven": "maven", "gradle": "maven", "sbt": "maven", "java": "maven",
	"pypi": "pypi", "pip": "pypi", "python": "pypi", "poetry": "pypi", "pipenv": "pypi",
	"go": "golang", "golang": "golang", "gomod": "golang", "gobinary": "golang",
	"cargo": "cargo", "rust": "cargo", "crates.io": "cargo",
	"nuget": "nuget", "dotnet": "nuget",
	"rubygems": "gem", "gem": "gem", "bundler": "gem", "ruby": "gem",
	"composer": "composer", "packagist": "composer", "php": "composer",
	"cocoapods": "cocoapods", "hex": "hex", "pub": "pub", "swiftpm": "swift", "swift": "swift",
	"cran": "cran", "conan": "conan", "homebrew": "brew",
	"debian": "deb", "ubuntu": "deb", "deb": "deb", "rpm": "rpm", "redhat": "rpm", "centos": "rpm",
	"alpine": "apk", "apk": "apk",
}

// PURLTypeForEcosystem maps an ecosystem label to a package URL type
// ("generic" when unknown).
func PURLTypeForEcosystem(eco string) string {
	if t, ok := ecosystemTypes[strings.ToLower(strings.TrimSpace(eco))]; ok {
		return t
	}
	return "generic"
}

// typeEcosystems is the display ecosystem of a package URL type.
var typeEcosystems = map[string]string{
	"npm": "npm", "maven": "maven", "pypi": "pypi", "golang": "go", "cargo": "cargo",
	"nuget": "nuget", "gem": "rubygems", "composer": "composer", "cocoapods": "cocoapods",
	"hex": "hex", "pub": "pub", "swift": "swiftpm", "cran": "cran", "conan": "conan",
	"brew": "homebrew", "deb": "deb", "rpm": "rpm", "apk": "apk", "oci": "oci",
	"docker": "oci", "github": "github", "generic": "generic",
}

// EcosystemForType is the display ecosystem of a package URL type; unknown
// types display as themselves.
func EcosystemForType(t string) string {
	if e, ok := typeEcosystems[t]; ok {
		return e
	}
	return t
}

// SyntheticPURL builds a package URL for an entry that has none, from its
// ecosystem, name and version.
func SyntheticPURL(ecosystem, name, version string) (PURL, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return PURL{}, ErrInvalidPURL
	}
	t := PURLTypeForEcosystem(ecosystem)
	p := PURL{Type: t, Version: strings.TrimSpace(version)}
	switch {
	case t == typeMaven && strings.Contains(name, ":"):
		p.Namespace, p.Name, _ = strings.Cut(name, ":")
	case t == "golang" && strings.Contains(name, "/"):
		i := strings.LastIndexByte(name, '/')
		p.Namespace, p.Name = name[:i], name[i+1:]
	case t == typeNPM && strings.HasPrefix(name, "@") && strings.Contains(name, "/"):
		p.Namespace, p.Name, _ = strings.Cut(name, "/")
	default:
		p.Name = name
	}
	if lowerCaseTypes[p.Type] {
		p.Namespace = strings.ToLower(p.Namespace)
		p.Name = strings.ToLower(p.Name)
	}
	if p.Type == typePyPI {
		p.Name = strings.ReplaceAll(p.Name, "_", "-")
	}
	if err := p.validate(); err != nil {
		return PURL{}, err
	}
	return p, nil
}

// PURLTypeForFilter maps a filter value (a display ecosystem such as "go" or
// "rubygems", or a package URL type) to a package URL type.
func PURLTypeForFilter(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if _, ok := typeEcosystems[v]; ok {
		return v
	}
	return PURLTypeForEcosystem(v)
}
