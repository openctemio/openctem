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
	rep, _ := lint(ctx, kind, files, false)
	return rep
}

// LintExcluding is Lint for an upstream release: a file that fails lint
// (a template using a refused protocol, a YAML file that is not a template)
// is left out of the pack and reported as a warning instead of refusing
// the whole release. It returns the files to leave out; the caller builds
// the pack without them, so sensors never receive them.
func LintExcluding(ctx context.Context, kind string, files []dom.File) (dom.LintReport, map[string]bool) {
	return lint(ctx, kind, files, true)
}

func lint(ctx context.Context, kind string, files []dom.File, exclude bool) (dom.LintReport, map[string]bool) {
	rep := dom.LintReport{Tier: dom.TierT0, Files: len(files)}
	excluded := map[string]bool{}
	for _, f := range files {
		if ctx.Err() != nil {
			rep.Error("", "LINT_TIMEOUT", "lint did not finish in time")
			return rep, excluded
		}
		fr := dom.LintReport{Tier: dom.TierT0}
		switch kind {
		case dom.KindNucleiTemplates:
			lintNuclei(&fr, f, exclude)
		case dom.KindSemgrepRules:
			lintSemgrep(&fr, f)
		case dom.KindWordlist:
			lintWordlist(&fr, f)
		}
		if exclude && len(fr.Errors) > 0 {
			excluded[f.Path] = true
			rep.Excluded++
			rep.Warn(f.Path, "EXCLUDED_"+fr.Errors[0].Code, fr.Errors[0].Message)
			continue
		}
		for _, e := range fr.Errors {
			rep.Error(e.Path, e.Code, e.Message)
		}
		for _, w := range fr.Warnings {
			rep.Warn(w.Path, w.Code, w.Message)
		}
		rep.Items += fr.Items
		rep.Tier = rep.Tier.Max(fr.Tier)
		if utf8.Valid(f.Data) {
			for _, k := range evidence.CredentialShapes(string(f.Data)) {
				rep.Secret(f.Path, k)
			}
		}
	}
	if kind == dom.KindWordlist && rep.Items > maxWordlistLines {
		rep.Error("", "TOO_MANY_LINES", fmt.Sprintf("the pack holds more than %d lines", maxWordlistLines))
	}
	switch {
	case dom.IsNamespacedKind(kind):
		rep.Tier = dom.TierT1
		rep.Warn("", "UNLINTED_KIND", fmt.Sprintf("%s has no platform linter; the pack is classified T1", kind))
	case rep.Items == 0 && len(rep.Errors) == 0:
		rep.Error("", "EMPTY_PACK", fmt.Sprintf("the pack holds no %s", kind))
	}
	return rep, excluded
}

func isYAML(p string) bool {
	ext := strings.ToLower(path.Ext(p))
	return ext == ".yaml" || ext == ".yml"
}

// lintNuclei validates every YAML file as a template (the custom-template
// validator: no code, javascript, headless or file protocols, no
// self-contained templates, safe regexes) and classifies it. Other files
// (payload lists, README) are data the templates may reference.
//
// upstream (a platform-managed release): attack payloads in a template's
// requests (shell fragments, file paths such as /etc/passwd: the text
// check the custom-template validator applies to the whole document) are
// what detection templates send to their targets, so they make the template
// T2 instead of refusing it. Protocols that run code on the scanner, read
// its files or drive a browser, self-contained templates and unsafe regexes
// are refused either way (structural checks on the parsed document).
func lintNuclei(rep *dom.LintReport, f dom.File, upstream bool) {
	if !isYAML(f.Path) {
		return
	}
	res := template.ValidateTemplate(scannertemplate.TemplateTypeNuclei, f.Data)
	payloads := false
	for _, e := range res.Errors {
		if upstream && e.Code == "DANGEROUS_PATTERN" && e.Field == "content" {
			payloads = true
			continue
		}
		rep.Error(f.Path, e.Code, e.Field+": "+e.Message)
	}
	if len(rep.Errors) > 0 {
		return
	}
	rep.Items++
	var tpl map[string]any
	if err := yaml.Unmarshal(f.Data, &tpl); err != nil {
		return // the validator parsed it already
	}
	tier, why := classifyNuclei(tpl, f.Data)
	if payloads {
		tier, why = dom.TierT2, "attack payloads in its requests (shell fragments or system file paths)"
	}
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
}
