package contentpack

import (
	"bytes"
	"context"
	"fmt"
	"path"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"

	"github.com/openctemio/openctem/api/internal/app/template"
	dom "github.com/openctemio/openctem/api/pkg/domain/contentpack"
	"github.com/openctemio/openctem/api/pkg/domain/evidence"
	"github.com/openctemio/openctem/api/pkg/domain/scannertemplate"
)

// Wordlist limits.
const (
	maxWordlistLine  = 4096
	maxWordlistLines = 10_000_000
)

// Lint checks a pack's files for its kind, classifies its tier and looks
// for credentials. Content is code (RFC-061 K-D4): a template that runs
// code on the scanner is an error, a template that sends out-of-band
// callbacks or races requests is T2. Lint parses only; it never executes
// anything and never writes the files anywhere.
func Lint(ctx context.Context, kind string, files []dom.File) dom.LintReport {
	rep := dom.LintReport{Tier: dom.TierT0, Files: len(files)}
	for _, f := range files {
		if ctx.Err() != nil {
			rep.Error("", "LINT_TIMEOUT", "lint did not finish in time")
			return rep
		}
		if utf8.Valid(f.Data) {
			for _, k := range evidence.CredentialShapes(string(f.Data)) {
				rep.Secret(f.Path, k)
			}
		}
		switch kind {
		case dom.KindNucleiTemplates:
			lintNuclei(&rep, f)
		case dom.KindSemgrepRules:
			lintSemgrep(&rep, f)
		case dom.KindWordlist:
			lintWordlist(&rep, f)
		}
	}
	switch {
	case dom.IsNamespacedKind(kind):
		rep.Tier = dom.TierT1
		rep.Warn("", "UNLINTED_KIND", fmt.Sprintf("%s has no platform linter; the pack is classified T1", kind))
	case rep.Items == 0 && len(rep.Errors) == 0:
		rep.Error("", "EMPTY_PACK", fmt.Sprintf("the pack holds no %s", kind))
	}
	return rep
}

func isYAML(p string) bool {
	ext := strings.ToLower(path.Ext(p))
	return ext == ".yaml" || ext == ".yml"
}

// lintNuclei validates every YAML file as a template (the custom-template
// validator: no code, javascript, headless or file protocols, no
// self-contained templates, safe regexes) and classifies it. Other files
// (payload lists, README) are data the templates may reference.
func lintNuclei(rep *dom.LintReport, f dom.File) {
	if !isYAML(f.Path) {
		return
	}
	res := template.ValidateTemplate(scannertemplate.TemplateTypeNuclei, f.Data)
	for _, e := range res.Errors {
		rep.Error(f.Path, e.Code, e.Field+": "+e.Message)
	}
	if res.HasErrors() {
		return
	}
	rep.Items++
	var tpl map[string]any
	if err := yaml.Unmarshal(f.Data, &tpl); err != nil {
		return // the validator parsed it already
	}
	tier, why := classifyNuclei(tpl, f.Data)
	if tier != dom.TierT0 {
		rep.Warn(f.Path, "TIER_"+string(tier), why)
	}
	rep.Tier = rep.Tier.Max(tier)
}

// t1Protocols reach beyond HTTP (RFC-061 §3.2: network and DNS at least T1).
var t1Protocols = []string{"dns", "network", "tcp", "ssl", "websocket", "whois"} //nolint:gochecknoglobals // static table

// intrusiveMethods change state on the target.
var intrusiveMethods = map[string]bool{"PUT": true, "PATCH": true, "DELETE": true} //nolint:gochecknoglobals // static table

// classifyNuclei is a template's tier and the reason.
func classifyNuclei(tpl map[string]any, raw []byte) (dom.Tier, string) {
	lower := bytes.ToLower(raw)
	if bytes.Contains(lower, []byte("interactsh")) {
		return dom.TierT2, "out-of-band callbacks (interactsh)"
	}
	if _, ok := tpl["flow"]; ok {
		return dom.TierT2, "scripted flow"
	}
	tier, why := dom.TierT0, ""
	for _, key := range []string{"http", "requests"} {
		reqs, _ := tpl[key].([]any)
		for _, r := range reqs {
			req, _ := r.(map[string]any)
			if t, w := classifyNucleiRequest(req); t.Rank() > tier.Rank() {
				tier, why = t, w
			}
		}
	}
	if tier == dom.TierT2 {
		return tier, why
	}
	for _, p := range t1Protocols {
		if _, ok := tpl[p]; ok {
			return dom.TierT1, "the " + p + " protocol"
		}
	}
	if _, ok := tpl["workflows"]; ok && tier == dom.TierT0 {
		return dom.TierT1, "a workflow of other templates"
	}
	return tier, why
}

func classifyNucleiRequest(req map[string]any) (dom.Tier, string) {
	if req == nil {
		return dom.TierT0, ""
	}
	if race, _ := req["race"].(bool); race {
		return dom.TierT2, "race requests"
	}
	if _, ok := req["race_count"]; ok {
		return dom.TierT2, "race requests"
	}
	if threads, ok := req["threads"].(int); ok && threads > 25 {
		return dom.TierT2, "more than 25 concurrent requests"
	}
	method := strings.ToUpper(fmt.Sprint(req["method"]))
	body, _ := req["body"].(string)
	if intrusiveMethods[method] || (method == "POST" && strings.TrimSpace(body) != "") {
		return dom.TierT2, method + " requests with a body or that change state"
	}
	raws, _ := req["raw"].([]any)
	for _, r := range raws {
		s, _ := r.(string)
		m, b := rawRequest(s)
		if intrusiveMethods[m] || (m == "POST" && b != "") {
			return dom.TierT2, m + " requests with a body or that change state"
		}
	}
	if _, ok := req["payloads"]; ok {
		return dom.TierT1, "payload fuzzing"
	}
	return dom.TierT0, ""
}

// rawRequest is the method and body of a raw HTTP request.
func rawRequest(s string) (string, string) {
	s = strings.TrimLeft(strings.ReplaceAll(s, "\r\n", "\n"), " \n\t")
	method, _, _ := strings.Cut(s, " ")
	_, body, _ := strings.Cut(s, "\n\n")
	return strings.ToUpper(method), strings.TrimSpace(body)
}

// lintSemgrep validates every YAML file as a rules file. Rules are passive
// (T0).
func lintSemgrep(rep *dom.LintReport, f dom.File) {
	if !isYAML(f.Path) {
		return
	}
	res := template.ValidateTemplate(scannertemplate.TemplateTypeSemgrep, f.Data)
	for _, e := range res.Errors {
		rep.Error(f.Path, e.Code, e.Field+": "+e.Message)
	}
	if !res.HasErrors() {
		rep.Items += res.RuleCount
	}
}

// lintWordlist accepts UTF-8 text without NUL bytes and with bounded lines.
func lintWordlist(rep *dom.LintReport, f dom.File) {
	if !utf8.Valid(f.Data) || bytes.IndexByte(f.Data, 0) >= 0 {
		rep.Error(f.Path, "NOT_TEXT", "a wordlist must be UTF-8 text without NUL bytes")
		return
	}
	for _, line := range strings.Split(string(f.Data), "\n") {
		if len(line) > maxWordlistLine {
			rep.Error(f.Path, "LINE_TOO_LONG", fmt.Sprintf("a line is longer than %d bytes", maxWordlistLine))
			return
		}
		if strings.TrimSpace(line) != "" {
			rep.Items++
		}
	}
	if rep.Items > maxWordlistLines {
		rep.Error(f.Path, "TOO_MANY_LINES", fmt.Sprintf("the pack holds more than %d lines", maxWordlistLines))
	}
}
