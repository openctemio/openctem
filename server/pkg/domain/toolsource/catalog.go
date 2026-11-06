// Package toolsource holds the organization keys of the third-party sources
// scan tools query (subfinder's passive sources, for one): the platform's
// view of the provider registry, the rules a key must meet, and the stored
// key. A key is the organization's own; it reaches only the sensor holding a
// task of that organization's job, through the sealed task secrets fetch.
//
// The registry itself (ids, formats, hosts, the tools that use each source)
// is the contract's (github.com/openctemio/contract/secretref): the platform
// validates a key on save with the same code the sensor uses when it receives
// one. This package maps the contract's refusals to the platform's error
// codes.
//
// Design: docs/architecture/task-secrets.md.
package toolsource

import (
	"errors"
	"slices"
	"strings"

	"github.com/openctemio/contract/secretref"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Format is how a source's key is written.
type Format string

const (
	// FormatKey is a single key or token.
	FormatKey Format = secretref.FormatKey
	// FormatPair is two parts joined by one colon (PairHint names them).
	FormatPair Format = secretref.FormatPair
)

// MaxValueLen bounds a key.
const MaxValueLen = secretref.MaxKeyLen

// MinSecretLen is the shortest secret part of a key.
const MinSecretLen = secretref.MinSecretLen

// Source is a third-party source a tool queries with a key. ID is the
// provider id of the registry and the credential name the tool's manifest
// declares.
type Source struct {
	ID       string
	Name     string
	Tools    []string
	Format   Format
	PairHint string

	p secretref.Provider
}

func sourceOf(p secretref.Provider) Source {
	return Source{ID: p.ID, Name: p.Display, Tools: slices.Clone(p.Tools), Format: Format(p.Format), PairHint: p.PairHint, p: p}
}

// ToolSubfinder is the tool of the passive subdomain sources.
const ToolSubfinder = "subfinder"

// toolCapabilities are the capabilities each keyed tool implements: a job
// that names only a capability (the sensor picks the tool) may receive the
// keys of a tool that implements it.
var toolCapabilities = map[string][]string{
	ToolSubfinder: {"discover.subdomains"},
}

// KeyedTools are the tools the registry lists keys for, sorted.
func KeyedTools() []string {
	var out []string
	for _, p := range secretref.Providers() {
		for _, t := range p.Tools {
			if !slices.Contains(out, t) {
				out = append(out, t)
			}
		}
	}
	slices.Sort(out)
	return out
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

// ProvidersForJob returns the provider ids whose keys a job may use (the
// union over the keyed tools the job may run), sorted.
func ProvidersForJob(jobTool, capability string) []string {
	var out []string
	for _, tool := range KeyedTools() {
		if !JobMayUse(jobTool, capability, tool) {
			continue
		}
		for _, id := range ForTool(tool) {
			if !slices.Contains(out, id) {
				out = append(out, id)
			}
		}
	}
	slices.Sort(out)
	return out
}

// Catalog returns every source, ordered by id.
func Catalog() []Source {
	ps := secretref.Providers()
	out := make([]Source, len(ps))
	for i, p := range ps {
		out[i] = sourceOf(p)
	}
	return out
}

// Lookup returns the source id names.
func Lookup(id string) (Source, bool) {
	p, ok := secretref.LookupProvider(id)
	if !ok {
		return Source{}, false
	}
	return sourceOf(p), true
}

// ForTool returns the ids of the sources tool queries with a key.
func ForTool(tool string) []string { return secretref.ProvidersForTool(tool) }

// keyErrorCodes map the contract's key refusals to the platform's codes.
var keyErrorCodes = map[string]string{
	secretref.KeyEmpty:    "TOOL_SOURCE_KEY_EMPTY",
	secretref.KeyTooLong:  "TOOL_SOURCE_KEY_TOO_LONG",
	secretref.KeyInvalid:  "TOOL_SOURCE_KEY_INVALID",
	secretref.KeyFormat:   "TOOL_SOURCE_KEY_FORMAT",
	secretref.KeyEndpoint: "TOOL_SOURCE_KEY_ENDPOINT",
	secretref.KeyTooShort: "TOOL_SOURCE_KEY_TOO_SHORT",
}

// ValidateValue checks a key before it is stored, with the registry's rules
// (secretref.Provider.ValidateKey): visible ASCII without spaces, bounded,
// a long enough secret part, the pair format, and an endpoint on the
// source's own service only. Errors never repeat the value.
func (s Source) ValidateValue(v string) error {
	err := s.p.ValidateKey(v)
	if err == nil {
		return nil
	}
	var ke *secretref.KeyError
	if errors.As(err, &ke) {
		if code, ok := keyErrorCodes[ke.Code]; ok {
			return shared.NewDomainError(code, ke.Msg, shared.ErrValidation)
		}
	}
	return shared.NewDomainError("TOOL_SOURCE_KEY_INVALID", "the key is not valid for this source", shared.ErrValidation)
}

// Last4 is the part of a key shown after it is saved: the last four
// characters of its secret part, nothing when that part is shorter than 12.
func (s Source) Last4(v string) string { return s.p.Last4(v) }
