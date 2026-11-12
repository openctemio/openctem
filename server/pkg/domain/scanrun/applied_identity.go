package scanrun

// What a step's requests were sent with (result metadata http_identity,
// docs/architecture/scan-identification.md): the User-Agent, the
// identification headers and query parameter, each with its source and
// whether it was applied. Sensor supplied: parsed defensively, bounded,
// single-line, secret-looking values masked again, and only ever shown;
// nothing in the platform decides anything from it.

import (
	"encoding/json"
	"regexp"

	"github.com/openctemio/contract/identity"

	"github.com/openctemio/openctem/server/pkg/safetext"
)

// Bounds of the applied identification a step keeps.
const (
	MaxAppliedIdentities = 8
	MaxAppliedHeaders    = 16
	maxAppliedBytes      = 16 * 1024
	maxAppliedToolRunes  = 64
	maxAppliedNameRunes  = 64
	maxAppliedValueRunes = 256
	maxAppliedShortRunes = 32
	maxAppliedReason     = 160
)

// MaskedIdentityValue replaces the value of a secret-looking name.
const MaskedIdentityValue = "****"

// Carriers of the identification: the tool itself, or the task's forwarder
// for a tool that cannot carry it.
const (
	CarrierTool      = "tool"
	CarrierForwarder = "forwarder"
)

// identitySecretNameRE marks a header or parameter name whose value may be a
// secret (the sensor masks these already; this is the platform's own line).
var identitySecretNameRE = regexp.MustCompile(`(?i)(token|secret|key|pass|auth|cred|session|signature|cookie|bearer)`)

// AppliedHeader is one header of the applied identification.
type AppliedHeader struct {
	Name    string `json:"name"`
	Value   string `json:"value"`
	Source  string `json:"source,omitempty"`
	Applied bool   `json:"applied"`
	Reason  string `json:"reason,omitempty"`
}

// AppliedQuery is the query parameter and whether the tool carried it.
type AppliedQuery struct {
	Name    string `json:"name"`
	Value   string `json:"value"`
	Applied bool   `json:"applied"`
	Reason  string `json:"reason,omitempty"`
}

// AppliedIdentity is what one task's requests were sent with.
type AppliedIdentity struct {
	Tool            string          `json:"tool,omitempty"`
	UserAgent       string          `json:"user_agent,omitempty"`
	UserAgentSource string          `json:"user_agent_source,omitempty"`
	UserAgentPool   int             `json:"user_agent_pool,omitempty"`
	UserAgentReason string          `json:"user_agent_reason,omitempty"`
	Headers         []AppliedHeader `json:"headers,omitempty"`
	Query           *AppliedQuery   `json:"query,omitempty"`
	Required        bool            `json:"required,omitempty"`
	Carrier         string          `json:"carrier,omitempty"`
}

func appliedText(s string, n int) string { return safetext.SingleLine(s, n) }

func maskIdentity(name, value string) string {
	if value != "" && identitySecretNameRE.MatchString(name) {
		return MaskedIdentityValue
	}
	return value
}

// ParseAppliedIdentity reads result metadata http_identity: one object or a
// list of them. Malformed or oversized input yields what could be read (or
// nothing), never an error.
func ParseAppliedIdentity(raw json.RawMessage) []AppliedIdentity {
	if len(raw) == 0 || len(raw) > maxAppliedBytes {
		return nil
	}
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		items = []json.RawMessage{raw}
	}
	var out []AppliedIdentity
	for _, it := range items {
		if len(out) >= MaxAppliedIdentities {
			break
		}
		if a, ok := parseOneApplied(it); ok {
			out = append(out, a)
		}
	}
	return out
}

func parseOneApplied(raw json.RawMessage) (AppliedIdentity, bool) {
	var in struct {
		Tool            string          `json:"tool"`
		UserAgent       string          `json:"user_agent"`
		UserAgentSource string          `json:"user_agent_source"`
		UserAgentPool   int             `json:"user_agent_pool"`
		UserAgentReason string          `json:"user_agent_reason"`
		Headers         []AppliedHeader `json:"headers"`
		Query           *AppliedQuery   `json:"query"`
		Required        bool            `json:"required"`
		Carrier         string          `json:"carrier"`
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		return AppliedIdentity{}, false
	}
	a := AppliedIdentity{
		Tool:            appliedText(in.Tool, maxAppliedToolRunes),
		UserAgent:       appliedText(in.UserAgent, maxAppliedValueRunes),
		UserAgentSource: appliedText(in.UserAgentSource, maxAppliedShortRunes),
		UserAgentReason: appliedText(in.UserAgentReason, maxAppliedReason),
		Required:        in.Required,
	}
	if in.UserAgentPool > 1 && in.UserAgentPool <= identity.MaxUserAgents {
		a.UserAgentPool = in.UserAgentPool
	}
	if in.Carrier == CarrierTool || in.Carrier == CarrierForwarder {
		a.Carrier = in.Carrier
	}
	for _, h := range in.Headers {
		if len(a.Headers) >= MaxAppliedHeaders {
			break
		}
		name := appliedText(h.Name, maxAppliedNameRunes)
		if name == "" {
			continue
		}
		a.Headers = append(a.Headers, AppliedHeader{Name: name, Value: maskIdentity(name, appliedText(h.Value, maxAppliedValueRunes)),
			Source: appliedText(h.Source, maxAppliedShortRunes), Applied: h.Applied, Reason: appliedText(h.Reason, maxAppliedReason)})
	}
	if q := in.Query; q != nil {
		if name := appliedText(q.Name, maxAppliedNameRunes); name != "" {
			a.Query = &AppliedQuery{Name: name, Value: maskIdentity(name, appliedText(q.Value, maxAppliedValueRunes)),
				Applied: q.Applied, Reason: appliedText(q.Reason, maxAppliedReason)}
		}
	}
	if a.Tool == "" && a.UserAgent == "" && len(a.Headers) == 0 && a.Query == nil {
		return AppliedIdentity{}, false
	}
	return a, true
}
