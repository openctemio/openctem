package retestcheck

// The rules a retest check's template must pass, on top of the template
// library's validator (docs/architecture/finding-retest-checks.md,
// "Validation"). A check runs against one finding's own target, so its
// requests must stay on that target: HTTP only, every path built on
// {{BaseURL}} or {{RootURL}}, raw requests addressed to {{Hostname}}, no
// redirects to other hosts, no out-of-band callbacks, no credentials.

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/openctemio/openctem/api/internal/app/contentpack"
	"github.com/openctemio/openctem/api/internal/app/template"
	cpdom "github.com/openctemio/openctem/api/pkg/domain/contentpack"
	dom "github.com/openctemio/openctem/api/pkg/domain/retestcheck"
	"github.com/openctemio/openctem/api/pkg/domain/scannertemplate"
)

// Analysis is what the rules found in a check's template.
type Analysis struct {
	Issues []dom.Issue
	// NucleiID is the template's id (the rule id the retest sends).
	NucleiID string
	// FirstPath is the path (with query) of the template's first request,
	// relative to the target ("/" when it requests the target itself): the
	// endpoint the retest must prove it requested.
	FirstPath    string
	Tier         string
	TierReason   string
	Capabilities []string
}

// Valid reports whether the template passed every rule.
func (a *Analysis) Valid() bool { return len(a.Issues) == 0 }

// allowedTopKeys are the top-level keys a check may use; anything else (other
// protocols, workflows, flow, variables that could hold hosts are fine but
// protocols are not) is refused.
var allowedTopKeys = map[string]bool{ //nolint:gochecknoglobals // static table
	"id": true, "info": true, "http": true, "requests": true, "variables": true,
	"constants": true, "stop-at-first-match": true,
}

// refusedRequestKeys are request options a check may not use: redirects to
// any host, malformed raw requests, fuzzing.
var refusedRequestKeys = map[string]string{ //nolint:gochecknoglobals // static table
	"redirects": "a check may follow redirects on its own host only (host-redirects)",
	"unsafe":    "a check sends well-formed requests only (unsafe raw requests are refused)",
	"fuzzing":   "a check reproduces one issue; fuzzing is refused",
}

// AnalyzeTemplate runs every rule on a nuclei template's content.
func AnalyzeTemplate(ctx context.Context, content []byte) *Analysis {
	a := &Analysis{Tier: dom.TierT0}
	add := func(field, code, format string, args ...any) {
		a.Issues = append(a.Issues, dom.Issue{Field: field, Code: code, Message: fmt.Sprintf(format, args...)})
	}
	if len(content) == 0 {
		add("content", "EMPTY", "the template is empty")
		return a
	}
	if int64(len(content)) > scannertemplate.TemplateTypeNuclei.MaxSize() {
		add("content", "TOO_LARGE", "the template is larger than %d bytes", scannertemplate.TemplateTypeNuclei.MaxSize())
		return a
	}
	// The library's validator: the one every upload and every delivery goes
	// through (code-class refusal, regex safety, structure).
	if res := template.ValidateTemplate(scannertemplate.TemplateTypeNuclei, content); res == nil || !res.Valid {
		if res != nil {
			for _, e := range res.Errors {
				add(nonEmpty(e.Field, "content"), e.Code, "%s", e.Message)
			}
		} else {
			add("content", "INVALID", "the template could not be validated")
		}
		return a
	}
	// Tier and credential shapes, as for a content pack.
	rep := contentpack.Lint(ctx, cpdom.KindNucleiTemplates, []cpdom.File{{Path: "check.yaml", Data: content}})
	for _, e := range rep.Errors {
		add("content", e.Code, "%s", e.Message)
	}
	for _, s := range rep.Secrets {
		add("content", "CREDENTIAL", "the template holds what %s; a check cannot hold credentials", s.Message)
	}
	a.Tier = string(rep.Tier)
	for _, w := range rep.Warnings {
		if strings.HasPrefix(w.Code, "TIER_") {
			a.TierReason = w.Message
		}
	}
	var tpl map[string]any
	if err := yaml.Unmarshal(content, &tpl); err != nil {
		add("content", "INVALID_YAML", "%v", err)
		return a
	}
	analysis := template.AnalyzeNuclei(tpl, nil)
	for _, c := range analysis.SortedCaps() {
		a.Capabilities = append(a.Capabilities, string(c))
	}
	if why, ok := analysis.Caps[template.CapOOBCallback]; ok {
		add("content", "OUT_OF_BAND", "a check cannot call out of band (%s)", why)
	}
	a.NucleiID, _ = tpl["id"].(string)
	checkTopKeys(tpl, add)
	a.FirstPath = checkRequests(tpl, add)
	return a
}

func checkTopKeys(tpl map[string]any, add func(field, code, format string, args ...any)) {
	keys := make([]string, 0, len(tpl))
	for k := range tpl {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !allowedTopKeys[strings.ToLower(k)] {
			add(k, "NOT_ALLOWED", "a check uses HTTP requests only; %q is not allowed", k)
		}
	}
}

// checkRequests checks every HTTP request block and returns the first
// request's path.
func checkRequests(tpl map[string]any, add func(field, code, format string, args ...any)) string {
	var blocks []any
	for _, key := range []string{"http", "requests"} {
		if v, ok := tpl[key].([]any); ok {
			blocks = append(blocks, v...)
		}
	}
	if len(blocks) == 0 {
		add("http", "NO_REQUEST", "the template has no HTTP request")
		return ""
	}
	first := ""
	for i, b := range blocks {
		req, ok := b.(map[string]any)
		if !ok {
			add(fmt.Sprintf("http[%d]", i), "INVALID", "a request block is not a mapping")
			continue
		}
		field := fmt.Sprintf("http[%d]", i)
		for k, why := range refusedRequestKeys {
			if v, ok := req[k]; ok && v != false {
				add(field+"."+k, "NOT_ALLOWED", "%s", why)
			}
		}
		for j, p := range stringList(req["path"]) {
			rest, ok := targetRelative(p)
			if !ok {
				add(fmt.Sprintf("%s.path[%d]", field, j), "OFF_TARGET",
					"every path must start with {{BaseURL}} or {{RootURL}} followed by / or ? (the finding's target)")
				continue
			}
			if first == "" {
				first = rest
			}
		}
		for j, raw := range stringList(req["raw"]) {
			p, err := rawTarget(raw)
			if err != "" {
				add(fmt.Sprintf("%s.raw[%d]", field, j), "OFF_TARGET", "%s", err)
				continue
			}
			if first == "" {
				first = p
			}
		}
		if len(stringList(req["path"])) == 0 && len(stringList(req["raw"])) == 0 {
			add(field, "NO_REQUEST", "the request has no path or raw request")
		}
		for name := range headerMap(req["headers"]) {
			if dom.IsCredentialHeader(name) {
				add(field+".headers."+name, "CREDENTIAL", "a check cannot hold credentials (%s)", name)
			}
		}
	}
	if first == "" {
		first = "/"
	}
	return first
}

// targetRelative returns the part of a path after {{BaseURL}} / {{RootURL}}
// when that part keeps the request on the target ("" or starting with / or
// ?), normalized to start with "/".
func targetRelative(p string) (string, bool) {
	p = strings.TrimSpace(p)
	for _, base := range []string{"{{BaseURL}}", "{{RootURL}}"} {
		rest, ok := strings.CutPrefix(p, base)
		if !ok {
			continue
		}
		switch {
		case rest == "":
			return "/", true
		case strings.HasPrefix(rest, "//"):
			return "", false
		case strings.HasPrefix(rest, "/"):
			return rest, true
		case strings.HasPrefix(rest, "?"):
			return "/" + rest, true
		}
		return "", false
	}
	return "", false
}

// rawTarget reads a raw request: an origin-form request target (a path, not
// an absolute URL) and, when a Host line is present, exactly
// "Host: {{Hostname}}". It returns the path, or why the request is refused.
func rawTarget(raw string) (string, string) {
	lines := strings.Split(strings.ReplaceAll(strings.TrimLeft(raw, "\r\n\t "), "\r\n", "\n"), "\n")
	parts := strings.Fields(lines[0])
	if len(parts) < 2 {
		return "", "the raw request has no request line"
	}
	if !strings.HasPrefix(parts[1], "/") || strings.HasPrefix(parts[1], "//") {
		return "", "the raw request must name a path on the target, not an absolute URL"
	}
	for _, l := range lines[1:] {
		l = strings.TrimSpace(l)
		if l == "" {
			break
		}
		name, value, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		if strings.EqualFold(name, "host") && strings.TrimSpace(value) != "{{Hostname}}" {
			return "", "the raw request's Host must be {{Hostname}} (the finding's target)"
		}
		if dom.IsCredentialHeader(name) {
			return "", "a check cannot hold credentials (" + name + ")"
		}
	}
	return parts[1], ""
}

func stringList(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func headerMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func nonEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
