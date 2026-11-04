// Package toolsource holds the organization keys of the third-party sources
// scan tools query (subfinder's passive sources, for one): the catalog of
// sources the platform stores keys for, the rules a key must meet, and the
// stored key. A key is the organization's own; it is delivered only to the
// sensor holding a task of that organization's job, for the job's tool.
//
// Design: docs/architecture/tool-source-keys.md.
package toolsource

import (
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Format is how a source's key is written.
type Format string

const (
	// FormatKey is a single key or token.
	FormatKey Format = "key"
	// FormatPair is two parts joined by one colon (PairHint names them).
	FormatPair Format = "pair"
)

// MaxValueLen bounds a key.
const MaxValueLen = 1024

// MinSecretLen is the shortest secret part of a key: shorter values are not
// real keys, and the sensor redacts only values of at least this length
// reliably.
const MinSecretLen = 8

// Endpoint kinds: a key whose first part names where the tool sends it. The
// tool connects there from the sensor, so the part must name the source's
// own service and nothing else (a tenant must never point a shared sensor at
// an address of its choice).
const (
	endpointNone = iota
	// endpointHost: "HOST:KEY", HOST a DNS name the rule accepts.
	endpointHost
	// endpointURL: "https://HOST/PATH:KEY", HOST a DNS name the rule
	// accepts, no port, user information, query or fragment.
	endpointURL
)

// Source is a third-party source a tool queries with a key. ID is the
// credential name the tool's manifest declares (permissions.credentials).
type Source struct {
	ID       string
	Name     string
	Tools    []string
	Format   Format
	PairHint string
	// endpoint and hostRule restrict a first part that names a host or URL
	// (endpointHost, endpointURL).
	endpoint int
	hostRule *regexp.Regexp
}

// ToolSubfinder is the tool of the passive subdomain sources.
const ToolSubfinder = "subfinder"

// toolCapabilities are the capabilities each keyed tool implements: a job
// that names only a capability (the sensor picks the tool) may receive the
// keys of a tool that implements it.
var toolCapabilities = map[string][]string{
	ToolSubfinder: {"discover.subdomains"},
}

// JobMayUse reports whether a job whose tool is jobTool (empty when the
// job names only capability, "discover.subdomains@1") may receive the keys
// of tool.
func JobMayUse(jobTool, capability, tool string) bool {
	if tool == "" || len(ForTool(tool)) == 0 {
		return false
	}
	if jobTool != "" {
		return jobTool == tool
	}
	name, _, _ := strings.Cut(capability, "@")
	return name != "" && slices.Contains(toolCapabilities[tool], name)
}

func key(id, name string) Source {
	return Source{ID: id, Name: name, Tools: []string{ToolSubfinder}, Format: FormatKey}
}

func pair(id, name, hint string) Source {
	return Source{ID: id, Name: name, Tools: []string{ToolSubfinder}, Format: FormatPair, PairHint: hint}
}

// hostKey is a "HOST:KEY" source whose HOST must match rule.
func hostKey(id, name, hint string, rule *regexp.Regexp) Source {
	s := pair(id, name, hint)
	s.endpoint, s.hostRule = endpointHost, rule
	return s
}

// urlKey is a "https://HOST/PATH:KEY" source whose HOST must match rule.
func urlKey(id, name, hint string, rule *regexp.Regexp) Source {
	s := pair(id, name, hint)
	s.endpoint, s.hostRule = endpointURL, rule
	return s
}

var (
	// intelx: subfinder calls https://HOST/phonebook/... (2.intelx.io and
	// the like).
	intelxHost = regexp.MustCompile(`^([a-z0-9-]+\.)*intelx\.io$`)
	// zoomeye: subfinder calls https://api.HOST/...; the service's own
	// domains only.
	zoomeyeHost = regexp.MustCompile(`^zoomeye\.(ai|hk|org)$`)
	// redhuntlabs: the endpoint URL the account was given.
	redhuntlabsHost = regexp.MustCompile(`^([a-z0-9-]+\.)*redhuntlabs\.com$`)
	// urlPath is the path of an endpoint URL.
	urlPath = regexp.MustCompile(`^(/[A-Za-z0-9._~-]+)*/?$`)
)

// catalog is every source the platform keeps keys for, by id. The ids are
// subfinder's source names (its provider configuration keys).
var catalog = []Source{
	key("alienvault", "AlienVault OTX"),
	key("bevigil", "BeVigil"),
	key("bufferover", "BufferOver"),
	key("builtwith", "BuiltWith"),
	key("c99", "C99"),
	pair("censys", "Censys", "TOKEN:ORG_ID"),
	key("certspotter", "Cert Spotter"),
	key("chaos", "Chaos"),
	key("chinaz", "Chinaz"),
	key("digitalyama", "DigitalYama"),
	key("dnsdb", "DNSDB"),
	key("dnsdumpster", "DNSDumpster"),
	pair("dnsrepo", "DNSRepo", "TOKEN:API_KEY"),
	pair("domainsproject", "Domains Project", "USERNAME:PASSWORD"),
	key("driftnet", "Driftnet"),
	pair("facebook", "Facebook CT", "APP_ID:APP_SECRET"),
	pair("fofa", "FOFA", "EMAIL:KEY"),
	key("fullhunt", "FullHunt"),
	key("github", "GitHub"),
	key("gitlab", "GitLab"),
	key("hackertarget", "HackerTarget"),
	hostKey("intelx", "Intelligence X", "HOST:KEY", intelxHost),
	key("leakix", "LeakIX"),
	key("merklemap", "MerkleMap"),
	key("netlas", "Netlas"),
	key("onyphe", "Onyphe"),
	key("profundis", "Profundis"),
	key("pugrecon", "PugRecon"),
	key("quake", "Quake"),
	key("reconeer", "Reconeer"),
	urlKey("redhuntlabs", "RedHunt Labs", "ENDPOINT_URL:KEY", redhuntlabsHost),
	key("robtex", "Robtex"),
	key("rsecloud", "RSECloud"),
	key("securitytrails", "SecurityTrails"),
	key("shodan", "Shodan"),
	key("threatbook", "ThreatBook"),
	key("urlscan", "urlscan.io"),
	key("virustotal", "VirusTotal"),
	key("whoisxmlapi", "WhoisXML API"),
	key("windvane", "Windvane"),
	hostKey("zoomeyeapi", "ZoomEye", "HOST:KEY", zoomeyeHost),
}

// Catalog returns every source, ordered by id.
func Catalog() []Source {
	out := make([]Source, len(catalog))
	for i, s := range catalog {
		s.Tools = slices.Clone(s.Tools)
		out[i] = s
	}
	return out
}

// Lookup returns the source id names.
func Lookup(id string) (Source, bool) {
	i := slices.IndexFunc(catalog, func(s Source) bool { return s.ID == id })
	if i < 0 {
		return Source{}, false
	}
	s := catalog[i]
	s.Tools = slices.Clone(s.Tools)
	return s, true
}

// ForTool returns the ids of the sources tool queries with a key.
func ForTool(tool string) []string {
	var out []string
	for _, s := range catalog {
		if slices.Contains(s.Tools, tool) {
			out = append(out, s.ID)
		}
	}
	return out
}

// ValidateValue checks a key before it is stored: 1 to MaxValueLen visible
// ASCII characters (no spaces, no line breaks: a key reaches a tool's
// configuration file and never a command line), a secret part of at least
// MinSecretLen characters, for a pair exactly one colon between two
// non-empty parts, and for a source whose first part names where the tool
// connects, that host or URL on the source's own service only (no IP
// address, port, user information or other host). Errors never repeat the
// value.
func (s Source) ValidateValue(v string) error {
	if v == "" {
		return valueError("TOOL_SOURCE_KEY_EMPTY", "the key is empty")
	}
	if len(v) > MaxValueLen {
		return valueError("TOOL_SOURCE_KEY_TOO_LONG", fmt.Sprintf("the key is longer than %d characters", MaxValueLen))
	}
	for i := 0; i < len(v); i++ {
		if v[i] < 0x21 || v[i] > 0x7e {
			return valueError("TOOL_SOURCE_KEY_INVALID", "the key may contain only visible ASCII characters, without spaces")
		}
	}
	formatErr := valueError("TOOL_SOURCE_KEY_FORMAT", "the key must be written as "+s.PairHint)
	switch {
	case s.Format != FormatPair:
		// a single key
	case s.endpoint == endpointURL:
		// "https://HOST/PATH:KEY": exactly the scheme's colon and the
		// separator (subfinder splits the value on every colon).
		parts := strings.Split(v, ":")
		if len(parts) != 3 || parts[0] != "https" || parts[2] == "" {
			return formatErr
		}
		if !s.endpointURLAllowed("https:" + parts[1]) {
			return valueError("TOOL_SOURCE_KEY_ENDPOINT", "the endpoint must be an https URL on the "+s.Name+" service")
		}
	default:
		a, b, ok := strings.Cut(v, ":")
		if !ok || a == "" || b == "" || strings.Contains(b, ":") {
			return formatErr
		}
		if s.endpoint == endpointHost && !s.hostAllowed(a) {
			return valueError("TOOL_SOURCE_KEY_ENDPOINT", "the host must be a "+s.Name+" host name")
		}
	}
	if len(s.secretPart(v)) < MinSecretLen {
		return valueError("TOOL_SOURCE_KEY_TOO_SHORT", fmt.Sprintf("the key is shorter than %d characters", MinSecretLen))
	}
	return nil
}

func valueError(code, msg string) error {
	return shared.NewDomainError(code, msg, shared.ErrValidation)
}

// hostAllowed reports whether host is a DNS name the source's rule accepts
// (never an IP literal, a port or user information: the rule is anchored
// and allows letters, digits, hyphens and dots only).
func (s Source) hostAllowed(host string) bool {
	return s.hostRule != nil && s.hostRule.MatchString(host)
}

func (s Source) endpointURLAllowed(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return false
	}
	if u.Port() != "" || u.Host != u.Hostname() || !s.hostAllowed(u.Hostname()) {
		return false
	}
	return urlPath.MatchString(u.EscapedPath())
}

// secretPart is the part of a value that is the secret: the whole key, or
// the last part of a pair.
func (s Source) secretPart(v string) string {
	if s.Format != FormatPair {
		return v
	}
	if i := strings.LastIndexByte(v, ':'); i >= 0 {
		return v[i+1:]
	}
	return v
}

// Last4 is the part of a key shown after it is saved: the last four
// characters of its secret part (the second part of a pair, never a user
// name or app id), nothing when that part is shorter than 12 (too much of
// it).
func (s Source) Last4(v string) string {
	sec := s.secretPart(v)
	if len(sec) < 12 {
		return ""
	}
	return sec[len(sec)-4:]
}
