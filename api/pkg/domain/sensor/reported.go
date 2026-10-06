package sensor

// Sensor-reported capabilities (docs/rfcs/RFC-029-sensor-protocol-v2-and-sdk-stability.md
// §4.3.1). A sensor reports on its heartbeat which tools it really has, the
// capabilities it serves and how many jobs it runs at once. What it reports
// is the truth for dispatch; what an administrator sets on the sensor
// (Tools, Capabilities, MaxConcurrentJobs) can only NARROW it:
//
//	effective tools        = reported installed tools ∩ admin tools (admin list empty: all reported)
//	effective capabilities = reported ∩ admin capabilities          (likewise)
//	effective max jobs     = min(reported ceiling, admin limit, reported slots)
//
// The reported ceiling (max_concurrent_jobs) is the sensor operator's cap;
// the reported slots (capacity.slots_total, load.go) are what the sensor can
// run now, sized from its CPU and memory (RFC-033: Kubernetes' capacity vs
// allocatable). Dispatch never counts on more than the slots.
//
// A sensor that reports nothing (an SDK from before the report) keeps the
// administrator's values, so nothing changes for it. The same rule is
// computed by the database (generated columns effective_tools,
// effective_capabilities, effective_max_jobs, migration 000253) for the
// dispatch queries; sensor_reported_caps_db_test.go keeps the two in step.

import (
	"regexp"
	"slices"
	"strings"
	"time"
)

// Limits on a capability report. Anything beyond them is dropped: the report
// comes from an untrusted process.
const (
	MaxReportedTools        = 64
	MaxReportedCapabilities = 64
	MaxReportedNameLen      = 50 // tools.name is VARCHAR(50)
	MaxReportedCapLen       = 64
	MaxReportedVersionLen   = 64
	MaxReportedPlatformLen  = 32
	// MaxReportedToolCapabilities bounds one tool's capability list.
	MaxReportedToolCapabilities = 32
	// MaxReportedJobs is the highest concurrency a sensor may report; an
	// administrator cannot set more either.
	MaxReportedJobs = 100
)

// CapabilityValidate is the capability of a sensor that runs validation
// jobs; "validate:<tool>" is validation with that tool.
const CapabilityValidate = "validate"

// CapabilityRetest prefixes the capability of a tool that re-checks its own
// findings: "retest:<tool>" (a tool-contract retest handler, RFC-039 tool
// retest). It is kept only for a known tool.
const CapabilityRetest = "retest"

// Tool kinds a sensor reports (sdk-go core.ToolKind).
const (
	ToolKindScanner   = "scanner"
	ToolKindCollector = "collector"
)

// ReportedTool is one tool on a sensor's reported inventory.
type ReportedTool struct {
	Name string `json:"name"`
	// Kind is "scanner" or "collector"; "" when the sensor did not say.
	Kind      string `json:"kind,omitempty"`
	Version   string `json:"version,omitempty"`
	Installed bool   `json:"installed"`
	// Capabilities are what this tool serves besides its own name ("dast",
	// "validate:nuclei"), known names only; nil when the sensor did not say
	// (sdk-go before v0.13 reports only the sensor's flat list).
	Capabilities []string `json:"capabilities,omitempty"`
	// Content is the scanner content the tool scans with (RFC-031,
	// content.go); nil when the sensor reported none for it.
	Content []ReportedContent `json:"content,omitempty"`
}

// CapabilityReport is what a sensor last reported, sanitized. A nil slice
// (or 0) means the sensor never reported that part.
type CapabilityReport struct {
	Tools             []ReportedTool
	Capabilities      []string
	MaxConcurrentJobs int
	// NoCeiling: the sensor said it has no operator ceiling (an SDK that
	// reports its slots and no max_concurrent_jobs), so a ceiling stored
	// from an older SDK (which sent its upper bound, 64) is cleared. Not
	// stored; MaxConcurrentJobs is 0 then.
	NoCeiling bool
	OS        string
	Arch      string
	// ReportedAt is when the report was last written; nil before the first.
	ReportedAt *time.Time
}

// HasReport reports whether any dispatch-relevant part was reported.
func (r CapabilityReport) HasReport() bool {
	return r.Tools != nil || r.Capabilities != nil || r.MaxConcurrentJobs > 0
}

// InstalledToolNames returns the names of the reported tools that are
// installed; nil when the sensor did not report tools.
func (r CapabilityReport) InstalledToolNames() []string {
	if r.Tools == nil {
		return nil
	}
	out := make([]string, 0, len(r.Tools))
	for _, t := range r.Tools {
		if t.Installed {
			out = append(out, t.Name)
		}
	}
	return out
}

// effectiveList is the narrowing rule: reported nil → declared; declared
// empty → reported; else reported ∩ declared, in reported order. It never
// returns nil.
func effectiveList(declared, reported []string) []string {
	if reported == nil {
		return append(make([]string, 0, len(declared)), declared...)
	}
	if len(declared) == 0 {
		return append(make([]string, 0, len(reported)), reported...)
	}
	allowed := make(map[string]struct{}, len(declared))
	for _, d := range declared {
		allowed[d] = struct{}{}
	}
	out := make([]string, 0, len(reported))
	for _, r := range reported {
		if _, ok := allowed[r]; ok {
			out = append(out, r)
		}
	}
	return out
}

// EffectiveTools is the tools dispatch may send this sensor jobs for.
func (a *Sensor) EffectiveTools() []string {
	return effectiveList(a.Tools, a.Reported.InstalledToolNames())
}

// EffectiveCapabilities is the capabilities dispatch and the command poll
// use for this sensor.
func (a *Sensor) EffectiveCapabilities() []string {
	return effectiveList(a.Capabilities, a.Reported.Capabilities)
}

// EffectiveMaxConcurrentJobs is the sensor's capacity for dispatch: the
// smallest of the ceiling it reported, the administrator's limit and the
// slots it last reported (what it can run now); a value that was not
// reported does not count. Without any it is the administrator's limit.
// The same rule as the generated column effective_max_jobs (migration
// 000257); the last reported slots count however old they are, like the
// column (the free-slot rule, FreeSlots, ignores a stale load report).
func (a *Sensor) EffectiveMaxConcurrentJobs() int {
	limit := 0
	for _, n := range []int{a.Reported.MaxConcurrentJobs, a.MaxConcurrentJobs, a.Load.SlotsTotal()} {
		if n > 0 && (limit == 0 || n < limit) {
			limit = n
		}
	}
	if limit == 0 {
		return a.MaxConcurrentJobs
	}
	return limit
}

// CapabilityMismatch lists what an administrator set that the sensor's own
// report contradicts. Display hints only; dispatch already uses the
// effective values.
type CapabilityMismatch struct {
	// ToolsNotInstalled are tools the administrator set that the sensor
	// reports as not installed or does not report at all.
	ToolsNotInstalled []string `json:"tools_not_installed,omitempty"`
	// CapabilitiesNotReported are capabilities the administrator set that
	// the sensor does not report.
	CapabilitiesNotReported []string `json:"capabilities_not_reported,omitempty"`
}

// IsEmpty reports whether there is nothing to show.
func (m CapabilityMismatch) IsEmpty() bool {
	return len(m.ToolsNotInstalled) == 0 && len(m.CapabilitiesNotReported) == 0
}

// CapabilityMismatch compares the administrator's settings with the report.
// Parts the sensor did not report are not compared. A concurrency limit above
// the reported cap is not a mismatch: every sensor gets the default limit,
// and the API shows both numbers.
func (a *Sensor) CapabilityMismatch() CapabilityMismatch {
	var m CapabilityMismatch
	if a.Reported.Tools != nil {
		m.ToolsNotInstalled = missingFrom(a.Tools, a.Reported.InstalledToolNames())
	}
	if a.Reported.Capabilities != nil {
		m.CapabilitiesNotReported = missingFrom(a.Capabilities, a.Reported.Capabilities)
	}
	return m
}

// missingFrom returns the elements of want that are not in have.
func missingFrom(want, have []string) []string {
	set := make(map[string]struct{}, len(have))
	for _, h := range have {
		set[h] = struct{}{}
	}
	var out []string
	for _, w := range want {
		if _, ok := set[w]; !ok {
			out = append(out, w)
		}
	}
	return out
}

// =============================================================================
// Sanitizing a report
// =============================================================================

var (
	reportedNameRe     = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)
	reportedCapRe      = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]*$`)
	reportedVersionRe  = regexp.MustCompile(`[^A-Za-z0-9.+_~:-]+`)
	reportedPlatformRe = regexp.MustCompile(`[^a-z0-9_]+`)
)

// CapabilityReportInput is a capability report as a heartbeat carried it,
// not yet trusted. nil Tools / Capabilities and MaxConcurrentJobs 0 mean
// "not reported".
type CapabilityReportInput struct {
	Tools             []ReportedTool
	Capabilities      []string
	MaxConcurrentJobs int
	OS                string
	Arch              string
}

// IsEmpty reports whether the heartbeat carried no report at all.
func (in CapabilityReportInput) IsEmpty() bool {
	return in.Tools == nil && in.Capabilities == nil && in.MaxConcurrentJobs == 0 && in.OS == "" && in.Arch == ""
}

// CatalogCandidates returns the well-formed tool names a report mentions
// (its tools, its capabilities and the tool of each "validate:<tool>"), to
// look up in the tool catalog, and its well-formed capability names, to look
// up in the capability registry. Lowercase, deduplicated, capped.
func (in CapabilityReportInput) CatalogCandidates() (tools, capabilities []string) {
	seenT := map[string]bool{}
	addTool := func(n string) {
		if validToolName(n) && !seenT[n] && len(tools) < MaxReportedTools+MaxReportedCapabilities {
			seenT[n] = true
			tools = append(tools, n)
		}
	}
	for i, t := range in.Tools {
		if i >= MaxReportedTools {
			break
		}
		addTool(strings.ToLower(strings.TrimSpace(t.Name)))
	}
	seenC := map[string]bool{}
	addCap := func(c string) {
		c = strings.ToLower(strings.TrimSpace(c))
		if !validCapName(c) || seenC[c] || len(capabilities) >= 2*MaxReportedCapabilities {
			return
		}
		seenC[c] = true
		capabilities = append(capabilities, c)
		addTool(c)
		if t, ok := strings.CutPrefix(c, CapabilityValidate+":"); ok {
			addTool(t)
		}
		if t, ok := strings.CutPrefix(c, CapabilityRetest+":"); ok {
			addTool(t)
		}
	}
	for i, c := range in.Capabilities {
		if i >= MaxReportedCapabilities {
			break
		}
		addCap(c)
	}
	// Each tool's own capabilities (sdk-go v0.13+): usually the same words
	// as the flat list, looked up once.
	for i, t := range in.Tools {
		if i >= MaxReportedTools {
			break
		}
		for j, c := range t.Capabilities {
			if j >= MaxReportedToolCapabilities {
				break
			}
			addCap(c)
		}
	}
	return tools, capabilities
}

// Sanitize keeps what is well-formed and known: tools in the tool catalog
// (knownTools), and capabilities that are in the capability registry
// (knownCaps), name a known tool, or are "validate" / "validate:<known
// tool>". Lists are capped and deduplicated, versions and the platform are
// reduced to safe tokens, and the concurrency is clamped to
// 1..MaxReportedJobs. A list that was reported stays non-nil even when
// nothing in it survives: the sensor said what it has, and none of it is
// usable.
func (in CapabilityReportInput) Sanitize(knownTools, knownCaps map[string]bool) CapabilityReport {
	var out CapabilityReport
	if in.Tools != nil {
		out.Tools = make([]ReportedTool, 0, min(len(in.Tools), MaxReportedTools))
		idx := map[string]int{}
		for i, t := range in.Tools {
			if i >= MaxReportedTools {
				break
			}
			name := strings.ToLower(strings.TrimSpace(t.Name))
			if !validToolName(name) || !knownTools[name] {
				continue
			}
			rt := ReportedTool{Name: name, Kind: sanitizeToolKind(t.Kind), Version: sanitizeReportedVersion(t.Version),
				Installed: t.Installed, Capabilities: sanitizeToolCapabilities(t.Capabilities, knownTools, knownCaps),
				Content: sanitizeToolContent(name, t.Content, time.Now())}
			if j, dup := idx[name]; dup {
				// Duplicates: installed wins, then a known version.
				if rt.Installed && !out.Tools[j].Installed {
					out.Tools[j] = rt
				} else if out.Tools[j].Version == "" {
					out.Tools[j].Version = rt.Version
				}
				continue
			}
			idx[name] = len(out.Tools)
			out.Tools = append(out.Tools, rt)
		}
	}
	if in.Capabilities != nil {
		out.Capabilities = make([]string, 0, min(len(in.Capabilities), MaxReportedCapabilities))
		seen := map[string]bool{}
		for i, c := range in.Capabilities {
			if i >= MaxReportedCapabilities {
				break
			}
			c = strings.ToLower(strings.TrimSpace(c))
			if !validCapName(c) || seen[c] || !knownCapability(c, knownTools, knownCaps) {
				continue
			}
			seen[c] = true
			out.Capabilities = append(out.Capabilities, c)
		}
	}
	if in.MaxConcurrentJobs > 0 {
		out.MaxConcurrentJobs = min(in.MaxConcurrentJobs, MaxReportedJobs)
	}
	out.OS = sanitizePlatform(in.OS)
	out.Arch = sanitizePlatform(in.Arch)
	return out
}

// sanitizeToolKind keeps a known tool kind; anything else is "".
func sanitizeToolKind(k string) string {
	switch k = strings.ToLower(strings.TrimSpace(k)); k {
	case ToolKindScanner, ToolKindCollector:
		return k
	default:
		return ""
	}
}

// sanitizeToolCapabilities keeps a tool's well-formed, known capabilities,
// deduplicated and capped; nil stays nil (not reported).
func sanitizeToolCapabilities(in []string, knownTools, knownCaps map[string]bool) []string {
	if in == nil {
		return nil
	}
	out := make([]string, 0, min(len(in), MaxReportedToolCapabilities))
	for i, c := range in {
		if i >= MaxReportedToolCapabilities {
			break
		}
		c = strings.ToLower(strings.TrimSpace(c))
		if validCapName(c) && !slices.Contains(out, c) && knownCapability(c, knownTools, knownCaps) {
			out = append(out, c)
		}
	}
	return out
}

func knownCapability(c string, knownTools, knownCaps map[string]bool) bool {
	if knownCaps[c] || knownTools[c] || c == CapabilityValidate {
		return true
	}
	if t, ok := strings.CutPrefix(c, CapabilityValidate+":"); ok {
		return knownTools[t]
	}
	if t, ok := strings.CutPrefix(c, CapabilityRetest+":"); ok {
		return knownTools[t]
	}
	return false
}

func validToolName(n string) bool {
	return n != "" && len(n) <= MaxReportedNameLen && reportedNameRe.MatchString(n)
}

func validCapName(c string) bool {
	return c != "" && len(c) <= MaxReportedCapLen && reportedCapRe.MatchString(c)
}

func sanitizeReportedVersion(v string) string {
	v = reportedVersionRe.ReplaceAllString(strings.TrimSpace(v), "")
	if len(v) > MaxReportedVersionLen {
		v = v[:MaxReportedVersionLen]
	}
	return v
}

func sanitizePlatform(p string) string {
	p = reportedPlatformRe.ReplaceAllString(strings.ToLower(strings.TrimSpace(p)), "")
	if len(p) > MaxReportedPlatformLen {
		p = p[:MaxReportedPlatformLen]
	}
	return p
}
