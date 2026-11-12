package scope

// The low-impact profile (docs/rfcs/RFC-054-scope-model.md §16): what an
// active job may do to an unclassified asset, one that no scope entry
// covers and nobody excluded or rejected, while the organization's
// unclassified-scans setting is low_impact (the default). It is defined
// once here; the platform caps every job on such a target to it (the
// claim-time re-check refuses or clamps the job), and the sensor clamps
// the tool flags again as a second line.
//
// Allowed: TCP connect to a short list of common ports at a low rate; an
// HTTP GET of "/" and "/.well-known/*"; a TLS handshake; tech and banner
// fingerprinting; nuclei templates tagged tech or exposure at severity
// info. Never: full or top-N port ranges, other paths, crawling, DAST,
// templates above info or tagged intrusive, custom templates, out-of-band
// callbacks, or a rate or concurrency above the caps.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// LowImpactPorts are the ports a low-impact job may connect to.
const LowImpactPorts = "21,22,25,53,80,110,143,443,465,587,993,995,3306,3389,5432,8080,8443"

// WebPorts are the ports a port scan of a name may reach when an address
// the name resolves to may not be probed on its own (RFC-054 §16.4).
const WebPorts = "80,443,8080,8443"

// Low-impact rate and concurrency caps (per job).
const (
	LowImpactMaxRate        = 10
	LowImpactMaxConcurrency = 2
)

// Refusal reason of a job on a low-impact target.
const LowImpactRefused = "low_impact"

// Tools the profile treats specially.
const (
	toolNaabu  = "naabu"
	toolHTTPX  = "httpx"
	toolNuclei = "nuclei"
)

// lowImpactTools are the tools a low-impact job may run. A tool outside it
// (a crawler, a DAST or brute-force tool, an operator-installed tool) never
// reaches an unclassified asset.
var lowImpactTools = map[string]bool{
	toolNaabu: true, toolHTTPX: true, toolNuclei: true, "dnsx": true, "tlsx": true,
	"subfinder": true, "rdap": true, "asn": true,
}

// lowImpactNucleiTags are the nuclei tags a low-impact job may select.
var lowImpactNucleiTags = []string{"tech", "exposure"}

// lowImpactNucleiSeverities are the severities a low-impact job may select.
var lowImpactNucleiSeverities = []string{"info"}

// LowImpactJob is what the low-impact check needs of a job: its tool, its
// config (the payload's "config" and "scanner_config" merged, the first
// value of a key winning only when both agree; see LowImpactConfig) and
// whether it carries custom templates or asks for out-of-band callbacks.
type LowImpactJob struct {
	Tool            string
	Config          map[string]any
	CustomTemplates bool
	Interactsh      bool
}

// LowImpactRefusal returns why job may not run on a low-impact target ("":
// it may). Every check fails closed: a value it cannot read refuses.
func LowImpactRefusal(job LowImpactJob) string {
	tool := strings.ToLower(strings.TrimSpace(job.Tool))
	if !lowImpactTools[tool] || job.CustomTemplates || job.Interactsh {
		return LowImpactRefused
	}
	cfg := job.Config
	if !limitAtMost(cfg, "rate_limit", LowImpactMaxRate, tool == toolNuclei || tool == toolHTTPX) ||
		!limitAtMost(cfg, "concurrency", LowImpactMaxConcurrency, tool == toolNuclei) ||
		!limitAtMost(cfg, "bulk_size", LowImpactMaxConcurrency, false) {
		return LowImpactRefused
	}
	switch tool {
	case toolNaabu:
		if present(cfg, "top_ports") || !limitAtMost(cfg, "rate", LowImpactMaxRate, true) {
			return LowImpactRefused
		}
		ports, ok := cfg["ports"].(string)
		if !ok || !PortsWithin(ports, []Constraint{{Ports: LowImpactPorts}}) {
			return LowImpactRefused
		}
	case toolHTTPX:
		if ports, ok := cfg["ports"]; ok {
			s, isStr := ports.(string)
			if !isStr || !PortsWithin(s, []Constraint{{Ports: LowImpactPorts}}) {
				return LowImpactRefused
			}
		}
		for _, p := range listValue(cfg["path"]) {
			if p != "/" && !strings.HasPrefix(p, "/.well-known/") {
				return LowImpactRefused
			}
		}
		if present(cfg, "path") && listValue(cfg["path"]) == nil {
			return LowImpactRefused
		}
	case toolNuclei:
		tags := listValue(cfg["tags"])
		sev := listValue(cfg["severity"])
		if len(tags) == 0 || len(sev) == 0 || !subset(tags, lowImpactNucleiTags) || !subset(sev, lowImpactNucleiSeverities) {
			return LowImpactRefused
		}
		for _, k := range []string{"template_ids", "templates", "workflows", "ids"} {
			if present(cfg, k) {
				return LowImpactRefused
			}
		}
	}
	return ""
}

// LowImpactClamp returns cfg narrowed to the low-impact profile for tool,
// and false when tool cannot run inside it. Ports are cut to the low-impact
// list (or set to it), rates and concurrency lowered to the caps, nuclei
// limited to info templates tagged tech or exposure; the result passes
// LowImpactRefusal. cfg is not modified.
func LowImpactClamp(tool string, cfg map[string]any) (map[string]any, bool) {
	tool = strings.ToLower(strings.TrimSpace(tool))
	if !lowImpactTools[tool] {
		return nil, false
	}
	out := make(map[string]any, len(cfg)+4)
	for k, v := range cfg {
		out[k] = v
	}
	capLimit(out, "rate_limit", LowImpactMaxRate, tool == toolNuclei || tool == toolHTTPX)
	capLimit(out, "concurrency", LowImpactMaxConcurrency, tool == toolNuclei)
	capLimit(out, "bulk_size", LowImpactMaxConcurrency, false)
	switch tool {
	case toolNaabu:
		delete(out, "top_ports")
		capLimit(out, "rate", LowImpactMaxRate, true)
		ports, _ := out["ports"].(string)
		out["ports"] = intersectPorts(ports, LowImpactPorts)
	case toolHTTPX:
		if v, ok := out["ports"]; ok {
			s, _ := v.(string)
			out["ports"] = intersectPorts(s, LowImpactPorts)
		}
		var keep []string
		for _, p := range listValue(out["path"]) {
			if p == "/" || strings.HasPrefix(p, "/.well-known/") {
				keep = append(keep, p)
			}
		}
		delete(out, "path")
		if len(keep) > 0 {
			out["path"] = keep
		}
	case toolNuclei:
		for _, k := range []string{"template_ids", "templates", "workflows", "ids"} {
			delete(out, k)
		}
		tags := intersect(listValue(out["tags"]), lowImpactNucleiTags)
		if len(tags) == 0 {
			tags = slices.Clone(lowImpactNucleiTags)
		}
		out["tags"] = tags
		out["severity"] = slices.Clone(lowImpactNucleiSeverities)
	}
	return out, true
}

// LowImpactConfig merges a payload's "config" and "scanner_config" for the
// low-impact check: a key set in only one is taken from it; a key set in
// both with different values is unreadable (ok false, fail closed).
func LowImpactConfig(config, scannerConfig map[string]any) (map[string]any, bool) {
	out := make(map[string]any, len(config)+len(scannerConfig))
	for k, v := range config {
		out[k] = v
	}
	for k, v := range scannerConfig {
		if prev, ok := out[k]; ok {
			a, _ := json.Marshal(prev)
			b, _ := json.Marshal(v)
			if !bytes.Equal(a, b) {
				return nil, false
			}
			continue
		}
		out[k] = v
	}
	return out, true
}

func present(cfg map[string]any, key string) bool {
	v, ok := cfg[key]
	return ok && v != nil
}

// limitAtMost reports whether cfg[key] is a whole number from 1 to max;
// an absent key passes unless required.
func limitAtMost(cfg map[string]any, key string, max int, required bool) bool {
	v, ok := cfg[key]
	if !ok || v == nil {
		return !required
	}
	n, ok := wholeNumber(v)
	return ok && n >= 1 && n <= max
}

func capLimit(cfg map[string]any, key string, max int, required bool) {
	v, ok := cfg[key]
	if !ok || v == nil {
		if required {
			cfg[key] = max
		}
		return
	}
	if n, ok := wholeNumber(v); ok && n >= 1 && n <= max {
		return
	}
	cfg[key] = max
}

func wholeNumber(v any) (int, bool) {
	switch x := v.(type) {
	case float64:
		if x != float64(int(x)) {
			return 0, false
		}
		return int(x), true
	case int:
		return x, true
	case int64:
		return int(x), true
	case json.Number:
		n, err := strconv.Atoi(string(x))
		return n, err == nil
	case string:
		n, err := strconv.Atoi(strings.TrimSpace(x))
		return n, err == nil
	}
	return 0, false
}

// listValue reads a list setting: a JSON array of strings or a
// comma-separated string, lower-cased and trimmed; nil when unreadable or
// empty.
func listValue(v any) []string {
	var raw []string
	switch x := v.(type) {
	case string:
		raw = strings.Split(x, ",")
	case []string:
		raw = x
	case []any:
		for _, e := range x {
			s, ok := e.(string)
			if !ok {
				return nil
			}
			raw = append(raw, s)
		}
	default:
		return nil
	}
	var out []string
	for _, s := range raw {
		if s = strings.ToLower(strings.TrimSpace(s)); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func subset(vals, allowed []string) bool {
	for _, v := range vals {
		if !slices.Contains(allowed, v) {
			return false
		}
	}
	return true
}

func intersect(vals, allowed []string) []string {
	var out []string
	for _, v := range vals {
		if slices.Contains(allowed, v) && !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	return out
}

// intersectPorts returns the ports of list (a port list; "" or unreadable:
// every port) that are in allowed, as a sorted list; allowed itself when
// none remain or the list is unreadable.
func intersectPorts(list, allowed string) string {
	want, ok := parsePorts(allowed)
	if !ok {
		return allowed
	}
	if strings.TrimSpace(list) == "" {
		return allowed
	}
	have, ok := parsePorts(list)
	if !ok {
		return allowed
	}
	var keep []string
	for _, r := range want {
		for p := r.lo; p <= r.hi; p++ {
			for _, h := range have {
				if p >= h.lo && p <= h.hi {
					keep = append(keep, fmt.Sprint(p))
					break
				}
			}
		}
	}
	if len(keep) == 0 {
		return allowed
	}
	return strings.Join(keep, ",")
}

// ClampPorts returns the ports of list that are in allowed (a sorted list);
// allowed itself when list is empty, unreadable or shares no port with it.
func ClampPorts(list, allowed string) string { return intersectPorts(list, allowed) }
