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

// Source is a third-party source a tool queries with a key. ID is the
// credential name the tool's manifest declares (permissions.credentials).
type Source struct {
	ID       string
	Name     string
	Tools    []string
	Format   Format
	PairHint string
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
	key("dnsrepo", "DNSRepo"),
	pair("domainsproject", "Domains Project", "USERNAME:PASSWORD"),
	key("driftnet", "Driftnet"),
	pair("facebook", "Facebook CT", "APP_ID:APP_SECRET"),
	pair("fofa", "FOFA", "EMAIL:KEY"),
	key("fullhunt", "FullHunt"),
	key("github", "GitHub"),
	key("gitlab", "GitLab"),
	key("hackertarget", "HackerTarget"),
	pair("intelx", "Intelligence X", "HOST:KEY"),
	key("leakix", "LeakIX"),
	key("merklemap", "MerkleMap"),
	key("netlas", "Netlas"),
	key("onyphe", "Onyphe"),
	key("profundis", "Profundis"),
	key("pugrecon", "PugRecon"),
	key("quake", "Quake"),
	key("reconeer", "Reconeer"),
	key("redhuntlabs", "RedHunt Labs"),
	key("robtex", "Robtex"),
	key("rsecloud", "RSECloud"),
	key("securitytrails", "SecurityTrails"),
	key("shodan", "Shodan"),
	key("threatbook", "ThreatBook"),
	key("urlscan", "urlscan.io"),
	key("virustotal", "VirusTotal"),
	key("whoisxmlapi", "WhoisXML API"),
	key("windvane", "Windvane"),
	key("zoomeyeapi", "ZoomEye"),
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
// configuration file and never a command line), and for a pair exactly one
// colon between two non-empty parts.
func (s Source) ValidateValue(v string) error {
	if v == "" {
		return shared.NewDomainError("TOOL_SOURCE_KEY_EMPTY", "the key is empty", shared.ErrValidation)
	}
	if len(v) > MaxValueLen {
		return shared.NewDomainError("TOOL_SOURCE_KEY_TOO_LONG", fmt.Sprintf("the key is longer than %d characters", MaxValueLen), shared.ErrValidation)
	}
	for i := 0; i < len(v); i++ {
		if v[i] < 0x21 || v[i] > 0x7e {
			return shared.NewDomainError("TOOL_SOURCE_KEY_INVALID", "the key may contain only visible ASCII characters, without spaces", shared.ErrValidation)
		}
	}
	if s.Format == FormatPair {
		a, b, ok := strings.Cut(v, ":")
		if !ok || a == "" || b == "" || strings.Contains(b, ":") {
			return shared.NewDomainError("TOOL_SOURCE_KEY_FORMAT", "the key must be written as "+s.PairHint, shared.ErrValidation)
		}
	}
	return nil
}

// Last4 is the part of a key shown after it is saved: its last four
// characters, nothing for a key shorter than 12 (too much of it).
func Last4(v string) string {
	if len(v) < 12 {
		return ""
	}
	return v[len(v)-4:]
}
