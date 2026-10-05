package sensor

// The dispatch pre-check (research/25 §3.6, RFC-040 §5.7): the platform
// does not hand a sensor a job its reported local policy would refuse.
// Accepts is the one check that poll, claim and the scan-trigger preflight
// share, so the three can never disagree.
//
// The check only ever narrows what the platform dispatches. The report it
// reads comes from the sensor (an untrusted process, sanitized on ingest):
// a sensor that lies about its policy can only make the platform withhold
// jobs from itself, never receive more than without a report. The sensor
// keeps enforcing its own policy whatever the platform decides.

import (
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// Refusal layers: which layer decided that a job may not run on a sensor.
const (
	// RefusalLayerLocal is the sensor-local policy its network owner
	// installed (the sensor's last report).
	RefusalLayerLocal = "local"
	// RefusalLayerManaged is a platform-side setting of the tenant (the
	// managed layer of research/25 §3.1), such as the requirement that
	// private targets go only to sensors with a local policy.
	RefusalLayerManaged = "managed"
)

// Refusal rules the platform-side layer uses. Local-policy rules carry the
// policy key the sensor would name (checks.allow, tools.allow, …).
const (
	RuleKillSwitch            = "kill_switch"
	RuleChecksAllow           = "checks.allow"
	RuleToolsAllow            = "tools.allow"
	RuleAllowCustomTemplates  = "allow_custom_templates"
	RuleAllowInteractsh       = "allow_interactsh"
	RulePortsAllow            = "ports.allow"
	RuleTargetsAllowPrivate   = "targets.allow_private"
	RulePrivateNeedsLocalPlcy = "private_targets_require_local_policy"
)

// DispatchRefusal says why a sensor must not get a job: the layer and rule
// that refuse it and a short, operator-facing detail.
type DispatchRefusal struct {
	Layer  string `json:"layer"`
	Rule   string `json:"rule"`
	Detail string `json:"detail"`
}

func (r *DispatchRefusal) Error() string {
	return fmt.Sprintf("refused by the %s policy (%s): %s", r.Layer, r.Rule, r.Detail)
}

// Job is what the pre-check reads from a command: the same fields the
// sensor's admission check (sdk-go core.AdmitCommand) reads.
type Job struct {
	// Type is the command type (scan, collect, validate, …).
	Type string
	// Tool is the canonical, lower-case tool name; "" when the job names
	// none.
	Tool string
	// Interactsh: the job turns out-of-band callbacks on (config
	// allow_interactsh is boolean true, the only value the sensor honors).
	Interactsh bool
	// CustomTemplates is how many custom templates the job carries.
	CustomTemplates int
	// Ports is the job's port list setting (config "ports"); "" = none.
	Ports string
	// Private: a target is private, loopback, link-local or CGNAT, or a
	// host name of a private namespace (HasPrivateTarget).
	Private bool
	// PrivateAddress: a target is a literal private address or range, which
	// an enforced policy refuses unless it allows private ranges.
	PrivateAddress bool
}

// retiredTools maps a replaced tool name to its replacement, as the sensor
// SDK does (sdk-go core.CanonicalScannerName).
var retiredTools = map[string]string{"gitleaks": "betterleaks"}

// CanonicalTool is the tool name the sensor's policy compares: trimmed,
// lower case, a retired name mapped to its replacement.
func CanonicalTool(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	if to, ok := retiredTools[n]; ok {
		return to
	}
	return n
}

// JobOf reads a command payload the way the sensor's admission check does.
// A payload it cannot read yields a job with only the type: the sensor
// refuses such a payload itself, and the platform does not guess.
func JobOf(cmdType string, payload json.RawMessage) Job {
	job := Job{Type: strings.ToLower(strings.TrimSpace(cmdType))}
	if len(payload) == 0 {
		return job
	}
	var p struct {
		Scanner         string            `json:"scanner"`
		ScannerName     string            `json:"scanner_name"`
		PreferredTool   string            `json:"preferred_tool"`
		Collector       string            `json:"collector"`
		ExecutorKind    string            `json:"executor_kind"`
		Config          map[string]any    `json:"config"`
		CustomTemplates []json.RawMessage `json:"custom_templates"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		job.Private = true // unreadable: fail closed, as HasPrivateTarget does
		return job
	}
	for _, s := range []string{p.Scanner, p.ScannerName, p.PreferredTool} {
		if s = strings.TrimSpace(s); s != "" {
			job.Tool = CanonicalTool(s)
			break
		}
	}
	if job.Tool == "" {
		switch job.Type {
		case "collect":
			job.Tool = CanonicalTool(p.Collector)
		case "validate":
			if strings.EqualFold(strings.TrimSpace(p.ExecutorKind), "nuclei") {
				job.Tool = "nuclei"
			}
		}
	}
	job.Interactsh = ConfigAsksInteractsh(p.Config)
	job.CustomTemplates = len(p.CustomTemplates)
	job.Ports = portSetting(p.Config["ports"])
	job.Private = HasPrivateTarget(payload)
	job.PrivateAddress = HasPrivateAddress(payload)
	return job
}

// ConfigAsksInteractsh reports whether a job or scanner configuration turns
// out-of-band callbacks on. The sensor honors only boolean true; a string
// "true" is counted too, so a configuration that a later reader might
// coerce is never sent past a check that said no.
func ConfigAsksInteractsh(cfg map[string]any) bool {
	switch v := cfg["allow_interactsh"].(type) {
	case bool:
		return v
	case string:
		return strings.EqualFold(strings.TrimSpace(v), "true")
	}
	return false
}

func portSetting(v any) string {
	switch x := v.(type) {
	case string:
		return strings.TrimSpace(x)
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	}
	return ""
}

// OptIns are the tenant's platform-side switches for the two job features
// a sensor without a local policy allows by default (research/25 D3): the
// platform sends a job that turns out-of-band callbacks on, or that carries
// custom templates, only when the tenant enabled it. Both default to off
// for every tenant; turning one on is an administrator action, audited and
// alerted (D9).
type OptIns struct {
	AllowInteractsh      bool `json:"allow_interactsh"`
	AllowCustomTemplates bool `json:"allow_custom_templates"`
}

// Refusal returns the managed-layer refusal of a job these opt-ins do not
// allow, or nil.
func (o OptIns) Refusal(job Job) *DispatchRefusal {
	if job.Interactsh && !o.AllowInteractsh {
		return &DispatchRefusal{Layer: RefusalLayerManaged, Rule: RuleAllowInteractsh,
			Detail: "the organization does not send jobs with out-of-band callbacks (interactsh); an owner can enable them in the security settings"}
	}
	if job.CustomTemplates > 0 && !o.AllowCustomTemplates {
		return &DispatchRefusal{Layer: RefusalLayerManaged, Rule: RuleAllowCustomTemplates,
			Detail: "the organization does not send custom templates to sensors; an owner can enable them in the security settings"}
	}
	return nil
}

// DispatchOptions are the tenant's platform-side settings the pre-check
// applies on top of the sensor's report.
type DispatchOptions struct {
	// RequireLocalPolicyForPrivate keeps jobs with private targets away
	// from sensors without an enforced local policy (RFC-040 Q3 (a)).
	RequireLocalPolicyForPrivate bool
	// OptIns, when set, are the tenant's interactsh and custom-template
	// switches (D3). nil: not evaluated by this caller.
	OptIns *OptIns
}

// Accepts reports whether a sensor whose last local-policy report is r may
// get job: nil when it may, else the refusal. It mirrors the sensor's own
// admission check for what the report shows (kill switch, checks, tools,
// custom templates, interactsh, ports, private ranges); target allow and
// deny lists are reported as counts only (research/25 D6), so they are
// left to the sensor.
//
// A sensor without a report (an SDK before RFC-040, protocol v1) or with
// no local policy accepts everything the policy would decide: the absent
// policy allows both opt-ins (owner decision Q4 (a)).
func Accepts(r *LocalPolicyReport, job Job, opts DispatchOptions) *DispatchRefusal {
	if r != nil && r.KillSwitch {
		return &DispatchRefusal{Layer: RefusalLayerLocal, Rule: RuleKillSwitch,
			Detail: "the sensor owner engaged the local kill switch; the sensor runs no job"}
	}
	if opts.OptIns != nil {
		if ref := opts.OptIns.Refusal(job); ref != nil {
			return ref
		}
	}
	if job.Private && opts.RequireLocalPolicyForPrivate && !r.Enforced() {
		return &DispatchRefusal{Layer: RefusalLayerManaged, Rule: RulePrivateNeedsLocalPlcy,
			Detail: "the organization sends jobs with private targets only to sensors that enforce a local policy"}
	}
	if !r.Enforced() || r.Summary == nil {
		return nil
	}
	s := r.Summary
	if s.Checks != nil && job.Type != "health_check" && !slices.Contains(s.Checks, job.Type) {
		return &DispatchRefusal{Layer: RefusalLayerLocal, Rule: RuleChecksAllow,
			Detail: fmt.Sprintf("%q jobs are not allowed on this sensor", job.Type)}
	}
	if s.Tools != nil {
		switch {
		case job.Tool != "" && !slices.Contains(s.Tools, job.Tool):
			return &DispatchRefusal{Layer: RefusalLayerLocal, Rule: RuleToolsAllow,
				Detail: fmt.Sprintf("%s is not allowed on this sensor", job.Tool)}
		case job.Tool == "" && (job.Type == "scan" || job.Type == "collect"):
			return &DispatchRefusal{Layer: RefusalLayerLocal, Rule: RuleToolsAllow,
				Detail: "the job names no tool and this sensor allows only listed tools"}
		}
	}
	if job.CustomTemplates > 0 && !s.AllowCustomTemplates {
		return &DispatchRefusal{Layer: RefusalLayerLocal, Rule: RuleAllowCustomTemplates,
			Detail: "the job carries custom templates; this sensor's local policy does not allow them"}
	}
	if job.Interactsh && !s.AllowInteractsh {
		return &DispatchRefusal{Layer: RefusalLayerLocal, Rule: RuleAllowInteractsh,
			Detail: "the job asks for out-of-band callbacks (interactsh); this sensor's local policy does not allow them"}
	}
	if job.Ports != "" && s.Ports != "" {
		if p, ok := firstPortOutside(job.Ports, s.Ports); ok {
			return &DispatchRefusal{Layer: RefusalLayerLocal, Rule: RulePortsAllow,
				Detail: fmt.Sprintf("the job's ports include %d, which this sensor's local policy does not allow (%s)", p, s.Ports)}
		}
	}
	if job.PrivateAddress && !s.AllowPrivate {
		return &DispatchRefusal{Layer: RefusalLayerLocal, Rule: RuleTargetsAllowPrivate,
			Detail: "the job names a private address; this sensor's local policy does not allow private ranges"}
	}
	return nil
}

type portRange struct{ lo, hi int }

// maxPortRanges bounds the work on a port list from a payload or a report.
const maxPortRanges = 256

// parsePortList parses "80,443,8000-8999". ok is false for anything else
// (named lists such as "top-100", malformed entries): the caller then does
// not decide, and leaves the job to the sensor.
func parsePortList(spec string) ([]portRange, bool) {
	parts := strings.Split(spec, ",")
	if len(parts) > maxPortRanges {
		return nil, false
	}
	out := make([]portRange, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		lo, hi, isRange := strings.Cut(part, "-")
		a, err := strconv.Atoi(strings.TrimSpace(lo))
		if err != nil || a < 1 || a > 65535 {
			return nil, false
		}
		b := a
		if isRange {
			if b, err = strconv.Atoi(strings.TrimSpace(hi)); err != nil || b < a || b > 65535 {
				return nil, false
			}
		}
		out = append(out, portRange{a, b})
	}
	return out, true
}

// firstPortOutside returns a port of the job's list that the policy's list
// does not cover; ok is false when every port is covered or either list
// cannot be read exactly.
func firstPortOutside(jobSpec, policySpec string) (int, bool) {
	job, ok := parsePortList(jobSpec)
	if !ok {
		return 0, false
	}
	allowed, ok := parsePortList(policySpec)
	if !ok {
		return 0, false
	}
	for _, j := range job {
		p := j.lo
		for p <= j.hi {
			next := 0
			for _, a := range allowed {
				if p >= a.lo && p <= a.hi {
					next = a.hi + 1
					break
				}
			}
			if next == 0 {
				return p, true
			}
			p = next
		}
	}
	return 0, false
}

// Layers a sensor may name in a structured refusal (v2 fail "refusal",
// research/25 §3.6). A closed set: anything else is stored as "unknown".
var sensorRefusalLayers = map[string]bool{
	"builtin": true, RefusalLayerLocal: true, RefusalLayerManaged: true, "scope": true, "platform_tool_gate": true,
}

// SanitizeRefusal reduces a sensor-reported refusal to safe, bounded
// values: a known layer (else "unknown"), a well-formed rule (else
// "unknown"), a printable detail of at most 300 characters. nil stays nil.
func SanitizeRefusal(r *DispatchRefusal) *DispatchRefusal {
	if r == nil {
		return nil
	}
	out := &DispatchRefusal{Layer: "unknown", Rule: "unknown", Detail: sanitizeWarning(r.Detail)}
	if l := strings.ToLower(strings.TrimSpace(r.Layer)); sensorRefusalLayers[l] {
		out.Layer = l
	}
	if rule := strings.TrimSpace(r.Rule); len(rule) <= maxLocalPolicyNameLen && localPolicyRuleRE.MatchString(rule) {
		out.Rule = rule
	}
	return out
}

// RefusalOf returns the refusal a failed command reports: the structured
// one when the sensor sent it (sanitized), else one parsed from a failure
// reason with the local-policy prefix (older SDKs). nil when the failure
// is not a policy refusal.
func RefusalOf(structured *DispatchRefusal, errorMessage string) *DispatchRefusal {
	if structured != nil {
		return SanitizeRefusal(structured)
	}
	rule, ok := LocalPolicyRefusal(errorMessage)
	if !ok {
		return nil
	}
	detail := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(errorMessage), LocalPolicyRefusalPrefix))
	if _, rest, found := strings.Cut(detail, ":"); found {
		detail = strings.TrimSpace(rest)
	} else {
		detail = ""
	}
	return &DispatchRefusal{Layer: RefusalLayerLocal, Rule: rule, Detail: sanitizeWarning(detail)}
}

// Message is the failure reason a refusal is recorded with. A local-policy
// refusal keeps the prefix older readers parse ("refused by local policy:
// <rule>: <detail>").
func (r *DispatchRefusal) Message() string {
	head := "refused by the " + r.Layer + " policy: "
	if r.Layer == RefusalLayerLocal {
		head = LocalPolicyRefusalPrefix
	}
	if r.Detail == "" {
		return head + r.Rule
	}
	return head + r.Rule + ": " + r.Detail
}
