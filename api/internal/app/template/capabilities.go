package template

import (
	"fmt"
	"math"
	"path"
	"sort"
	"strconv"
	"strings"
)

// Capability analysis of a nuclei template (research/185 §4.2, RFC-061 K-D4).
//
// What a template can do is computed from the PARSED document, never from
// what its author declares (info.metadata.max-request, tags, a "safe"
// label): the same text can be written as block YAML, flow YAML, JSON,
// with quoted or escaped keys, so only the decoded structure counts.

// Capability names one thing a template makes the scanner do.
type Capability string

// Capabilities. The code-class ones run code on the scanner, read its disk
// or drive a browser; custom (tenant) content may never use them.
const (
	CapHTTPRead        Capability = "http.read"
	CapHTTPPayloads    Capability = "http.payloads"
	CapHTTPStateChange Capability = "http.state_change"
	CapNetRaw          Capability = "net.raw"
	CapDNSQuery        Capability = "dns.query"
	CapOOBCallback     Capability = "oob.callback"
	CapVolumeHigh      Capability = "volume.high"
	CapChainWorkflow   Capability = "chain.workflow"
	CapScriptFlow      Capability = "script.flow"
	CapScriptJS        Capability = "script.javascript"
	CapScriptCode      Capability = "script.code"
	CapBrowserHeadless Capability = "browser.headless"
	CapHostFile        Capability = "host.file"
	CapSelfContained   Capability = "targets.self_contained"
)

// Request volume limits, per target. Above VolumeHighRequests a template is
// intrusive (T2); above MaxTemplateRequests it is refused.
const (
	VolumeHighRequests  = 500
	MaxTemplateRequests = 10_000
	// maxThreads is the per-request concurrency above which a template is
	// intrusive.
	maxThreads = 25
	// defaultRaceCount is what nuclei sends for race: true without a count.
	defaultRaceCount = 10
)

// codeClassKeys are the top-level keys that make a template code-class,
// in report order. flow is JavaScript run by the engine's embedded
// interpreter (the same engine as the javascript protocol), so it is code.
var codeClassKeys = []struct { //nolint:gochecknoglobals // static table
	key, why string
	cap      Capability
}{
	{"code", "runs code on the scanner", CapScriptCode},
	{"javascript", "runs code on the scanner", CapScriptJS},
	{"flow", "runs JavaScript on the scanner", CapScriptFlow},
	{"headless", "drives a browser on the scanner", CapBrowserHeadless},
	{"file", "reads files on the scanner", CapHostFile},
}

// requestProtocols are the top-level keys holding request blocks.
var requestProtocols = []string{"http", "requests", "dns", "network", "tcp", "ssl", "websocket", "whois", "headless", "code", "javascript", "file"} //nolint:gochecknoglobals // static table

// oobHosts are public out-of-band callback domains: a template that names
// one makes its target call a third party even without the interactsh
// placeholder.
var oobHosts = []string{"oast.pro", "oast.live", "oast.site", "oast.online", "oast.fun", "oast.me", "interact.sh"} //nolint:gochecknoglobals // static table

// intrusiveHTTPMethods change state on the target.
var intrusiveHTTPMethods = map[string]bool{"PUT": true, "PATCH": true, "DELETE": true} //nolint:gochecknoglobals // static table

// WorkflowRef is one template a workflow runs.
type WorkflowRef struct {
	Field string // where in the document, e.g. workflows[0].subtemplates[1].template
	Path  string // the referenced path as written
}

// NucleiAnalysis is what static analysis found in one template.
type NucleiAnalysis struct {
	// Caps maps each capability to why it was found.
	Caps map[Capability]string
	// Requests is the estimated number of requests per target (saturating
	// at math.MaxInt32). VolumeUnknown is set when part of it cannot be
	// computed (requests built by fuzzing rules, a templated count); the
	// reason says which.
	Requests      int
	VolumeUnknown string
	// WorkflowRefs are the templates a workflow references by path;
	// WorkflowTags is set when it selects templates by tag (from whatever
	// is on the scanner's disk).
	WorkflowRefs []WorkflowRef
	WorkflowTags string
	// PayloadFiles are payload lists the template loads from files
	// (relative to the template or the template root); UnresolvedPayloads
	// those the analysis could not size.
	PayloadFiles       []string
	UnresolvedPayloads []string
}

// CodeClass returns the first code-class key in tpl and why it is refused.
func CodeClass(tpl map[string]any) (key, why string, found bool) {
	for _, c := range codeClassKeys {
		if _, ok := topKey(tpl, c.key); ok {
			return c.key, c.why, true
		}
	}
	return "", "", false
}

// IsCodeClass reports whether c runs code on the scanner, reads its disk
// or drives a browser.
func IsCodeClass(c Capability) bool {
	switch c {
	case CapScriptFlow, CapScriptJS, CapScriptCode, CapBrowserHeadless, CapHostFile:
		return true
	}
	return false
}

// SortedCaps returns the capabilities in a stable order.
func (a *NucleiAnalysis) SortedCaps() []Capability {
	out := make([]Capability, 0, len(a.Caps))
	for c := range a.Caps {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func (a *NucleiAnalysis) add(c Capability, why string) {
	if _, ok := a.Caps[c]; !ok {
		a.Caps[c] = why
	}
}

// PayloadSizer returns the number of entries of a payload list file that
// the template at its own path references, false when it cannot resolve it.
type PayloadSizer func(ref string) (int, bool)

// AnalyzeNuclei computes a parsed template's capabilities and request
// volume. sizer resolves payload list files; nil resolves none.
func AnalyzeNuclei(tpl map[string]any, sizer PayloadSizer) *NucleiAnalysis {
	a := &NucleiAnalysis{Caps: map[Capability]string{}}
	for _, c := range codeClassKeys {
		if _, ok := topKey(tpl, c.key); ok {
			a.add(c.cap, "the "+c.key+" block "+c.why)
		}
	}
	if v, ok := topKey(tpl, "self-contained"); ok {
		if b, isBool := v.(bool); !isBool || b {
			a.add(CapSelfContained, "a self-contained template carries its own targets")
		}
	}
	if why, ok := findOOB(tpl); ok {
		a.add(CapOOBCallback, why)
	}

	total := 0
	for _, proto := range requestProtocols {
		v, ok := topKey(tpl, proto)
		if !ok {
			continue
		}
		blocks, _ := v.([]any)
		switch proto {
		case "http", "requests":
			a.add(CapHTTPRead, "HTTP requests")
		case "dns":
			a.add(CapDNSQuery, "DNS queries")
		case "network", "tcp", "ssl", "websocket", "whois":
			a.add(CapNetRaw, "the "+proto+" protocol")
		}
		for i, b := range blocks {
			block, _ := b.(map[string]any)
			if block == nil {
				continue
			}
			total = satAdd(total, a.analyzeBlock(fmt.Sprintf("%s[%d]", proto, i), proto, block, sizer))
		}
	}
	a.Requests = total
	if v, ok := topKey(tpl, "workflows"); ok {
		a.add(CapChainWorkflow, "a workflow of other templates")
		a.collectWorkflow("workflows", v)
	}
	switch {
	case a.Requests > VolumeHighRequests:
		a.add(CapVolumeHigh, fmt.Sprintf("about %d requests per target", a.Requests))
	case a.VolumeUnknown != "":
		a.add(CapVolumeHigh, a.VolumeUnknown)
	}
	return a
}

// analyzeBlock classifies one request block and returns its estimated
// request count.
func (a *NucleiAnalysis) analyzeBlock(field, proto string, b map[string]any, sizer PayloadSizer) int {
	base := 1
	switch proto {
	case "http", "requests":
		base = listLen(b["path"]) + listLen(b["raw"])
		if base == 0 {
			base = 1
		}
		a.classifyHTTP(b)
	case "network", "tcp":
		if n := listLen(b["host"]); n > 0 {
			base = n
		}
	}

	if threads, ok := b["threads"]; ok {
		n, known := toInt(threads)
		switch {
		case !known:
			a.add(CapVolumeHigh, field+".threads is not a number ("+short(threads)+")")
		case n > maxThreads:
			a.add(CapVolumeHigh, fmt.Sprintf("more than %d concurrent requests", maxThreads))
		}
	}

	race := 1
	if r, _ := b["race"].(bool); r {
		race = defaultRaceCount
		a.add(CapVolumeHigh, "race requests")
	}
	if rc, ok := b["race_count"]; ok {
		a.add(CapVolumeHigh, "race requests")
		if n, known := toInt(rc); known && n > 0 {
			race = n
		} else {
			a.markUnknown(field + ".race_count is not a number")
		}
	}

	if _, ok := b["fuzzing"]; ok {
		a.add(CapHTTPPayloads, "fuzzing rules")
		a.markUnknown(field + " builds requests from fuzzing rules")
	}

	card := 1
	if p, ok := b["payloads"]; ok {
		a.add(CapHTTPPayloads, "payload lists")
		card = a.payloadCardinality(field, p, fmt.Sprint(b["attack"]), sizer)
	}
	return satMul(satMul(base, card), race)
}

// classifyHTTP marks requests that change state on the target.
func (a *NucleiAnalysis) classifyHTTP(b map[string]any) {
	method := strings.ToUpper(strings.TrimSpace(fmt.Sprint(b["method"])))
	body, _ := b["body"].(string)
	if intrusiveHTTPMethods[method] || (method == "POST" && strings.TrimSpace(body) != "") {
		a.add(CapHTTPStateChange, method+" requests with a body or that change state")
	}
	raws, _ := b["raw"].([]any)
	for _, r := range raws {
		s, _ := r.(string)
		m, body := rawRequest(s)
		if intrusiveHTTPMethods[m] || (m == "POST" && body != "") {
			a.add(CapHTTPStateChange, m+" requests with a body or that change state")
		}
	}
}

// payloadCardinality is how many combinations the payloads produce for the
// attack type: clusterbomb tries every combination, the others walk the
// lists side by side.
func (a *NucleiAnalysis) payloadCardinality(field string, p any, attack string, sizer PayloadSizer) int {
	m, _ := p.(map[string]any)
	if m == nil {
		a.markUnknown(field + ".payloads is not a map")
		return 1
	}
	names := make([]string, 0, len(m))
	for k := range m {
		names = append(names, k)
	}
	sort.Strings(names)
	clusterbomb := strings.EqualFold(strings.TrimSpace(attack), "clusterbomb")
	total := 0
	if clusterbomb {
		total = 1
	}
	for _, name := range names {
		n := 1
		switch v := m[name].(type) {
		case []any:
			n = len(v)
		case string:
			ref := strings.TrimSpace(v)
			a.PayloadFiles = append(a.PayloadFiles, ref)
			if sizer == nil {
				a.UnresolvedPayloads = append(a.UnresolvedPayloads, ref)
				a.markUnknown(field + ".payloads." + name + " loads a file")
			} else if size, ok := sizer(ref); ok {
				n = size
			} else {
				a.UnresolvedPayloads = append(a.UnresolvedPayloads, ref)
				a.markUnknown(field + ".payloads." + name + " loads a file that is not in the snapshot")
			}
		default:
			a.markUnknown(field + ".payloads." + name + " is neither a list nor a file")
		}
		if n < 1 {
			n = 1
		}
		if clusterbomb {
			total = satMul(total, n)
		} else if n > total {
			total = n
		}
	}
	if total < 1 {
		total = 1
	}
	return total
}

func (a *NucleiAnalysis) markUnknown(why string) {
	if a.VolumeUnknown == "" {
		a.VolumeUnknown = why
	}
}

// collectWorkflow records every template reference and tag selector of a
// workflow (top-level entries, subtemplates and matcher subtemplates, at
// any depth).
func (a *NucleiAnalysis) collectWorkflow(field string, v any) {
	switch x := v.(type) {
	case []any:
		for i, e := range x {
			a.collectWorkflow(fmt.Sprintf("%s[%d]", field, i), e)
		}
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			val := x[k]
			switch strings.ToLower(strings.TrimSpace(k)) {
			case "template":
				s, _ := val.(string)
				a.WorkflowRefs = append(a.WorkflowRefs, WorkflowRef{Field: field + "." + k, Path: s})
			case "tags":
				if a.WorkflowTags == "" {
					a.WorkflowTags = field + "." + k
				}
			default:
				a.collectWorkflow(field+"."+k, val)
			}
		}
	}
}

// CleanRef checks a template-relative reference (a workflow's template, a
// payload file) and returns it cleaned. Absolute paths, parent-directory
// steps, URLs and home-directory paths are refused: they reach outside the
// snapshot.
func CleanRef(ref string) (string, error) {
	r := strings.TrimSpace(ref)
	switch {
	case r == "":
		return "", fmt.Errorf("empty reference")
	case strings.ContainsAny(r, "\x00\\"):
		return "", fmt.Errorf("reference %q has a NUL byte or backslash", ref)
	case strings.Contains(r, "://"), strings.Contains(r, "{{"):
		return "", fmt.Errorf("reference %q is a URL or an expression", ref)
	case strings.HasPrefix(r, "/"), strings.HasPrefix(r, "~"):
		return "", fmt.Errorf("reference %q is an absolute path", ref)
	}
	for _, seg := range strings.Split(r, "/") {
		if seg == ".." {
			return "", fmt.Errorf("reference %q leaves the snapshot", ref)
		}
	}
	return path.Clean(r), nil
}

// findOOB walks every key and string value of the parsed template for an
// out-of-band callback: the interactsh placeholder or matcher parts in any
// spelling (case, spaces, helper calls that split the word), or a public
// callback domain.
func findOOB(v any) (string, bool) {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			if why, ok := oobText(k); ok {
				return why, true
			}
			if why, ok := findOOB(val); ok {
				return why, true
			}
		}
	case []any:
		for _, e := range x {
			if why, ok := findOOB(e); ok {
				return why, true
			}
		}
	case string:
		return oobText(x)
	}
	return "", false
}

func oobText(s string) (string, bool) {
	lower := strings.ToLower(s)
	var b strings.Builder
	for _, r := range lower {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	if strings.Contains(b.String(), "interactsh") {
		return "out-of-band callbacks (interactsh)", true
	}
	for _, h := range oobHosts {
		if strings.Contains(lower, h) {
			return "out-of-band callbacks (" + h + ")", true
		}
	}
	return "", false
}

// topKey finds a top-level key the way the engine matches it: JSON
// templates match field names case-insensitively, so keys are compared
// with Unicode case folding after trimming.
func topKey(tpl map[string]any, want string) (any, bool) {
	if v, ok := tpl[want]; ok {
		return v, true
	}
	for k, v := range tpl {
		if strings.EqualFold(strings.TrimSpace(k), want) {
			return v, true
		}
	}
	return nil, false
}

// toInt reads a whole number written as an integer, a float or a numeric
// string. A templated or otherwise non-numeric value is unknown.
func toInt(v any) (int, bool) {
	switch x := v.(type) {
	case int:
		return x, true
	case int64:
		return clampInt(float64(x)), true
	case uint64:
		return clampInt(float64(x)), true
	case float64:
		if math.IsNaN(x) {
			return 0, false
		}
		return clampInt(math.Ceil(x)), true
	case string:
		s := strings.TrimSpace(x)
		if n, err := strconv.ParseInt(s, 0, 64); err == nil {
			switch {
			case n > math.MaxInt32:
				return math.MaxInt32, true
			case n < math.MinInt32:
				return math.MinInt32, true
			}
			return int(int32(n)), true
		}
		if f, err := strconv.ParseFloat(s, 64); err == nil && !math.IsNaN(f) {
			return clampInt(math.Ceil(f)), true
		}
	}
	return 0, false
}

func clampInt(f float64) int {
	switch {
	case f > math.MaxInt32:
		return math.MaxInt32
	case f < math.MinInt32:
		return math.MinInt32
	}
	return int(f)
}

func listLen(v any) int {
	switch x := v.(type) {
	case []any:
		return len(x)
	case string:
		if strings.TrimSpace(x) != "" {
			return 1
		}
	}
	return 0
}

func satAdd(a, b int) int {
	if a > math.MaxInt32-b {
		return math.MaxInt32
	}
	return a + b
}

func satMul(a, b int) int {
	if a == 0 || b == 0 {
		return 0
	}
	if a > math.MaxInt32/b {
		return math.MaxInt32
	}
	return a * b
}

func short(v any) string {
	s := fmt.Sprint(v)
	if len(s) > 40 {
		return s[:40] + "…"
	}
	return s
}

// rawRequest is the method and body of a raw HTTP request.
func rawRequest(s string) (string, string) {
	s = strings.TrimLeft(strings.ReplaceAll(s, "\r\n", "\n"), " \n\t")
	method, _, _ := strings.Cut(s, " ")
	_, body, _ := strings.Cut(s, "\n\n")
	return strings.ToUpper(method), strings.TrimSpace(body)
}
