package software

import (
	"strings"
	"unicode"

	"github.com/openctemio/openctem/api/pkg/domain/vulnmatch"
)

// Sources of an observation (asset_software.source).
const (
	SourceTechnology = "technology"
	SourceService    = "service"
	SourceOpenPort   = "open_port"
	SourceOS         = "os"
)

// Limits on observed strings.
const (
	MaxNameLen      = 200
	MaxEvidenceLen  = 512
	MaxQualifierLen = 64
	MaxLocationLen  = 64
)

// Base confidences and adjustments (RFC-066 §6.2).
const (
	ConfidenceCPE           = 80
	ConfidenceCuratedName   = 65
	ConfidencePrivateName   = 50
	AdjustPartialVersion    = -25
	AdjustDistroBuild       = -30
	AdjustLowToolConfidence = -15
	lowToolConfidence       = 50
)

// Observation is one product an asset was seen running, as a producer
// reported it. Name or CPE identifies the product; Version may be empty.
type Observation struct {
	Name      string
	Version   string
	CPE       string
	Port      int
	Transport string
	Location  string
	Source    string
	Evidence  string
	// ToolConfidence is the producer's own confidence (0-100), 0 = not given.
	ToolConfidence int
}

// Identity is how the catalog looks a product up: by CPE (part, vendor,
// product) or, without one, by a normalised name. It is comparable.
type Identity struct {
	Part       string
	CPEVendor  string
	CPEProduct string
	Name       string
	// Edition is the CPE sw_edition, when the observation gives one.
	Edition string
}

// HasCPE reports whether the identity is a CPE identity.
func (i Identity) HasCPE() bool { return i.CPEVendor != "" }

// CPEAlias is the alias value of a CPE identity: "part:vendor:product".
func (i Identity) CPEAlias() string { return i.Part + ":" + i.CPEVendor + ":" + i.CPEProduct }

// VersionKey identifies a version of a product.
type VersionKey struct {
	Raw        string
	Normalized string // "" when the version does not parse
	Scheme     vulnmatch.Scheme
	Qualifier  string
	Edition    string
}

// Parsed is an observation resolved to an identity and a version key, with
// its base confidence (before knowing whether a curated alias resolves the
// name: see Confidence).
type Parsed struct {
	Identity Identity
	Version  VersionKey
	// Segments is the number of version segments (0 = no usable version).
	Segments int
}

// Parse validates an observation and derives its identity and version key.
// ok is false for an observation that names nothing usable: no name and no
// CPE, a generic service name ("http", "ssh") with no product, control
// characters, or an over-long name.
func Parse(o Observation) (Parsed, bool) {
	var p Parsed
	version := o.Version
	if c := strings.TrimSpace(o.CPE); c != "" {
		if cpe, err := vulnmatch.ParseCPE(c); err == nil {
			p.Identity = Identity{Part: cpe.Part, CPEVendor: cpe.Vendor, CPEProduct: cpe.Product}
			if e := cpe.SWEdition; e != vulnmatch.Any && e != vulnmatch.NA {
				p.Identity.Edition = e
			}
			if strings.TrimSpace(version) == "" && cpe.Version != vulnmatch.Any && cpe.Version != vulnmatch.NA {
				version = cpe.Version
				if u := cpe.Update; u != vulnmatch.Any && u != vulnmatch.NA {
					version += u
				}
			}
		}
	}
	if !p.Identity.HasCPE() {
		name := NormalizeName(o.Name)
		if name == "" || genericServiceNames[name] {
			return Parsed{}, false
		}
		p.Identity = Identity{Part: "a", Name: name}
		if o.Source == SourceOS {
			p.Identity.Part = "o"
		}
	}
	ver, qual := SplitVersion(version)
	p.Version = VersionKey{Raw: ver, Scheme: vulnmatch.SchemeGeneric, Qualifier: qual, Edition: p.Identity.Edition}
	if v, ok := vulnmatch.ParseVersion(ver); ok {
		p.Version.Normalized = v.Normalized()
		p.Segments = v.Segments()
	}
	return p, true
}

// Confidence is the identity confidence of a parsed observation (RFC-066
// §6.2). resolvedGlobal tells whether the catalog resolved it to a public
// product.
func Confidence(p Parsed, o Observation, resolvedGlobal bool) int {
	c := ConfidencePrivateName
	switch {
	case p.Identity.HasCPE() && resolvedGlobal:
		c = ConfidenceCPE
	case resolvedGlobal:
		c = ConfidenceCuratedName
	}
	if p.Segments > 0 && p.Segments < 3 {
		c += AdjustPartialVersion
	}
	if p.Version.Qualifier != "" {
		c += AdjustDistroBuild
	}
	if o.ToolConfidence > 0 && o.ToolConfidence < lowToolConfidence {
		c += AdjustLowToolConfidence
	}
	switch {
	case c < 0:
		return 0
	case c > 100:
		return 100
	}
	return c
}

// NormalizeName lower-cases a product name and collapses white space. It
// returns "" for an empty or over-long name or one with control characters.
func NormalizeName(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > MaxNameLen {
		return ""
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return ""
		}
	}
	return strings.Join(strings.Fields(strings.ToLower(s)), " ")
}

// genericServiceNames are protocol names a port scanner reports as the
// "service": they name no product.
var genericServiceNames = map[string]bool{
	"http": true, "https": true, "http-proxy": true, "ssl/http": true, "ssh": true, "ftp": true,
	"ftps": true, "smtp": true, "smtps": true, "submission": true, "imap": true, "imaps": true,
	"pop3": true, "pop3s": true, "dns": true, "domain": true, "telnet": true, "rdp": true,
	"ms-wbt-server": true, "smb": true, "microsoft-ds": true, "netbios-ssn": true, "ldap": true,
	"ldaps": true, "snmp": true, "ntp": true, "sip": true, "vnc": true,
	"rpcbind": true, "msrpc": true, "tcpwrapped": true, "unknown": true, "ssl": true, "tls": true,
}

// distroMarkers are words that show a distribution build, whose upstream
// version number does not reflect back-ported fixes.
var distroMarkers = []string{
	"ubuntu", "debian", "deb", "centos", "rhel", "redhat", "red hat", "fedora", "alpine",
	"suse", "amzn", "amazon", "rocky", "almalinux", "oracle linux", "raspbian", "fips",
}

func hasDistroMarker(s string) bool {
	s = strings.ToLower(s)
	for _, m := range distroMarkers {
		if strings.Contains(s, m) {
			return true
		}
	}
	return elMarker(s)
}

// elMarker finds "el7", "el8_9" style Enterprise Linux build tags.
func elMarker(s string) bool {
	for i := 0; i+2 < len(s); i++ {
		if s[i] == 'e' && s[i+1] == 'l' && s[i+2] >= '5' && s[i+2] <= '9' &&
			(i == 0 || !isAlpha(s[i-1])) {
			return true
		}
	}
	return false
}

func isAlpha(b byte) bool { return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' }

// SplitVersion separates the upstream version from a distribution build
// qualifier: "8.2p1 Ubuntu-4ubuntu0.5" → "8.2p1", "ubuntu-4ubuntu0.5";
// "2.4.41 (Ubuntu)" → "2.4.41", "ubuntu"; "1.18.0-0ubuntu1.4" → "1.18.0",
// "0ubuntu1.4"; "1.0.2k-fips" → "1.0.2k", "fips". Trailing text that is not a
// distribution marker is dropped ("2.4.58 (Win64)" → "2.4.58", "").
func SplitVersion(s string) (version, qualifier string) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", ""
	}
	if i := strings.IndexAny(s, " \t("); i >= 0 {
		head, rest := strings.TrimSpace(s[:i]), s[i:]
		if hasDistroMarker(rest) {
			qualifier = cleanQualifier(rest)
		}
		return clip(head, vulnmatch.MaxVersionLen), qualifier
	}
	for i := 0; i < len(s); i++ {
		if s[i] == '-' || s[i] == '+' || s[i] == '~' {
			if rest := s[i+1:]; hasDistroMarker(rest) {
				return clip(s[:i], vulnmatch.MaxVersionLen), cleanQualifier(rest)
			}
		}
	}
	return clip(s, vulnmatch.MaxVersionLen), ""
}

func cleanQualifier(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	dash := false
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '+', r == '~', r == '_':
			b.WriteRune(r)
			dash = false
		case r == '-' || r == ' ' || r == '\t':
			if !dash && b.Len() > 0 {
				b.WriteByte('-')
				dash = true
			}
		}
	}
	return clip(strings.Trim(b.String(), "-"), MaxQualifierLen)
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// Banner is one product a banner or Server header names.
type Banner struct {
	Name    string
	Version string
}

// ParseBanner reads the products a banner or HTTP Server header names:
// "nginx/1.18.0 (Ubuntu)", "Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips
// PHP/5.4.16", "OpenSSH_8.2p1 Ubuntu-4ubuntu0.5", "Microsoft-IIS/10.0",
// "OpenSSH 8.2p1 Ubuntu 4ubuntu0.5". A comment in parentheses or a trailing
// distribution word stays with the version before it, so SplitVersion can
// turn it into a qualifier. At most 8 products are read.
func ParseBanner(s string) []Banner {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > MaxEvidenceLen {
		return nil
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return nil
		}
	}
	fields := strings.Fields(s)
	var out []Banner
	for i := 0; i < len(fields) && len(out) < 8; i++ {
		f := fields[i]
		name, ver := splitNameVersion(f)
		switch {
		case name != "" && ver != "":
		case startsWithDigit(f) && len(out) == 0 && i > 0:
			// "OpenSSH 8.2p1 ..." / "Apache httpd 2.4.41": the name is
			// every word before the first version-looking one.
			name, ver = strings.Join(fields[:i], " "), f
		default:
			continue
		}
		// Words that follow up to the next product are the version's
		// comment: "(Ubuntu)", "Ubuntu-4ubuntu0.5", "Ubuntu 4ubuntu0.5".
		j := i + 1
		for j < len(fields) {
			if n, v := splitNameVersion(fields[j]); n != "" && v != "" {
				break
			}
			j++
		}
		if j > i+1 {
			ver += " " + strings.Join(fields[i+1:j], " ")
		}
		out = append(out, Banner{Name: name, Version: ver})
		i = j - 1
	}
	return out
}

// splitNameVersion splits "nginx/1.18.0" and "OpenSSH_8.2p1".
func splitNameVersion(f string) (string, string) {
	for _, sep := range []string{"/", "_"} {
		if i := strings.Index(f, sep); i > 0 && i+1 < len(f) && startsWithDigit(f[i+1:]) {
			return f[:i], f[i+1:]
		}
	}
	return "", ""
}

func startsWithDigit(s string) bool {
	if s != "" && (s[0] == 'v' || s[0] == 'V') {
		s = s[1:]
	}
	return s != "" && s[0] >= '0' && s[0] <= '9'
}

// SplitTechnology splits an HTTP technology string "Name:version" (the
// version may be missing: "Cloudflare").
func SplitTechnology(s string) (name, version string) {
	s = strings.TrimSpace(s)
	if i := strings.LastIndex(s, ":"); i > 0 && startsWithDigit(s[i+1:]) {
		return strings.TrimSpace(s[:i]), strings.TrimSpace(s[i+1:])
	}
	return s, ""
}
