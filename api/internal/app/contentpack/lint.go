package contentpack

import (
	"bytes"
	"context"
	"fmt"
	"math"
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
	var nuclei map[string]*dom.LintReport
	if kind == dom.KindNucleiTemplates {
		nuclei = lintNucleiPack(ctx, files, exclude)
	}
	for _, f := range files {
		if ctx.Err() != nil {
			rep.Error("", "LINT_TIMEOUT", "lint did not finish in time")
			return rep, excluded
		}
		fr := dom.LintReport{Tier: dom.TierT0}
		switch kind {
		case dom.KindNucleiTemplates:
			if r := nuclei[f.Path]; r != nil {
				fr = *r
			}
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

// nucleiFile is one template's lint result before workflow resolution.
type nucleiFile struct {
	path     string
	rep      *dom.LintReport
	analysis *template.NucleiAnalysis
	tier     dom.Tier
	why      string
	failed   bool // refused: errors, or left out of an upstream release
	resolved bool
	visiting bool
}

// lintNucleiPack lints every YAML file of a pack as a template (the
// custom-template validator: no code-class blocks, no self-contained
// templates, safe regexes, bounded request volume) and classifies it from
// its parsed structure (template.AnalyzeNuclei). Other files (payload
// lists, README) are data the templates may reference.
//
// References are resolved inside the pack only: a workflow's templates and
// a template's payload files must be files of the same pack, by a relative
// path that stays inside it, and a workflow's tier and request volume are
// those of what it runs. A workflow that references a template outside the
// pack, or one that was refused, is refused with it.
//
// upstream (a platform-managed release): attack payloads in a template's
// requests (shell fragments, file paths such as /etc/passwd: the text
// check the custom-template validator applies to the whole document) are
// what detection templates send to their targets, so they make the template
// T2 instead of refusing it. Code-class blocks (code, javascript, flow,
// headless, file), self-contained templates, unsafe regexes and references
// outside the pack are refused either way (structural checks on the parsed
// document).
func lintNucleiPack(ctx context.Context, files []dom.File, upstream bool) map[string]*dom.LintReport {
	byPath := make(map[string][]byte, len(files))
	for _, f := range files {
		byPath[path.Clean(f.Path)] = f.Data
	}
	out := make(map[string]*dom.LintReport, len(files))
	parsed := make(map[string]*nucleiFile, len(files))
	for _, f := range files {
		if ctx.Err() != nil {
			break
		}
		if !isYAML(f.Path) {
			continue
		}
		nf := lintNucleiFile(f, byPath, upstream)
		parsed[path.Clean(f.Path)] = nf
		out[f.Path] = nf.rep
	}
	for _, f := range files {
		if nf := parsed[path.Clean(f.Path)]; nf != nil {
			resolveWorkflow(path.Clean(f.Path), nf, parsed)
		}
	}
	for _, nf := range parsed {
		if nf.failed {
			continue
		}
		nf.rep.Items++
		if nf.tier != dom.TierT0 {
			nf.rep.Warn(nf.path, "TIER_"+string(nf.tier), nf.why)
		}
		nf.rep.Tier = nf.tier
	}
	return out
}

// lintNucleiFile validates and classifies one template on its own.
func lintNucleiFile(f dom.File, byPath map[string][]byte, upstream bool) *nucleiFile {
	nf := &nucleiFile{path: f.Path, rep: &dom.LintReport{Tier: dom.TierT0}, tier: dom.TierT0}
	dir := path.Dir(path.Clean(f.Path))
	sizer := func(ref string) (int, bool) {
		data, ok := lookupRef(byPath, dir, ref)
		if !ok {
			return 0, false
		}
		return countLines(data), true
	}
	res := template.ValidateNuclei(f.Data, template.NucleiOptions{Snapshot: true, PayloadSizer: sizer})
	payloads := false
	for _, e := range res.Errors {
		if upstream && e.Code == "DANGEROUS_PATTERN" && e.Field == "content" {
			payloads = true
			continue
		}
		nf.rep.Error(f.Path, e.Code, e.Field+": "+e.Message)
	}
	if len(nf.rep.Errors) > 0 {
		nf.failed = true
		return nf
	}
	var tpl map[string]any
	if err := yaml.Unmarshal(f.Data, &tpl); err != nil {
		nf.failed = true
		nf.rep.Error(f.Path, "INVALID_YAML", err.Error())
		return nf
	}
	nf.analysis = template.AnalyzeNuclei(tpl, sizer)
	nf.tier, nf.why = tierOf(nf.analysis)
	if payloads {
		nf.tier, nf.why = dom.TierT2, "attack payloads in its requests (shell fragments or system file paths)"
	}
	return nf
}

// resolveWorkflow resolves a workflow's references inside the pack and
// raises its tier and volume to those of what it runs. A reference to a
// file that is not in the pack, is not a template, or was refused refuses
// the workflow; so does a cycle.
func resolveWorkflow(p string, nf *nucleiFile, parsed map[string]*nucleiFile) {
	if nf.resolved || nf.failed || nf.analysis == nil || len(nf.analysis.WorkflowRefs) == 0 {
		nf.resolved = true
		return
	}
	if nf.visiting {
		nf.fail("WORKFLOW_CYCLE", "the workflow references itself")
		return
	}
	nf.visiting = true
	defer func() { nf.visiting = false; nf.resolved = true }()
	requests := nf.analysis.Requests
	dir := path.Dir(p)
	for _, ref := range nf.analysis.WorkflowRefs {
		target, key := lookupTemplate(parsed, dir, ref.Path)
		if target == nil {
			nf.fail("WORKFLOW_OUTSIDE_SNAPSHOT", fmt.Sprintf("%s: %q is not a template of this pack", ref.Field, ref.Path))
			return
		}
		if target.visiting {
			nf.fail("WORKFLOW_CYCLE", fmt.Sprintf("%s: %q leads back to this workflow", ref.Field, ref.Path))
			return
		}
		resolveWorkflow(key, target, parsed)
		if target.failed {
			nf.fail("WORKFLOW_REFERENCE_REFUSED", fmt.Sprintf("%s: %q was refused", ref.Field, ref.Path))
			return
		}
		if target.tier.Rank() > nf.tier.Rank() {
			nf.tier, nf.why = target.tier, fmt.Sprintf("runs %s (%s)", ref.Path, target.why)
		}
		requests = satAdd(requests, target.analysis.Requests)
	}
	if nf.tier == dom.TierT0 {
		nf.tier, nf.why = dom.TierT1, "a workflow of other templates"
	}
	if requests > template.MaxTemplateRequests {
		nf.fail("REQUEST_VOLUME_CAP", fmt.Sprintf("the workflow sends about %d requests per target; the limit is %d", requests, template.MaxTemplateRequests))
		return
	}
	if requests > template.VolumeHighRequests && nf.tier != dom.TierT2 {
		nf.tier, nf.why = dom.TierT2, fmt.Sprintf("about %d requests per target", requests)
	}
	nf.analysis.Requests = requests
}

func (nf *nucleiFile) fail(code, msg string) {
	nf.failed = true
	nf.rep.Error(nf.path, code, msg)
}

// lookupTemplate finds a referenced template, relative to the pack root
// first and then to the referencing file's directory.
func lookupTemplate(parsed map[string]*nucleiFile, dir, ref string) (*nucleiFile, string) {
	clean, err := template.CleanRef(ref)
	if err != nil {
		return nil, ""
	}
	for _, k := range []string{clean, path.Join(dir, clean)} {
		if nf := parsed[k]; nf != nil {
			return nf, k
		}
	}
	return nil, ""
}

// lookupRef finds a referenced data file the same way.
func lookupRef(byPath map[string][]byte, dir, ref string) ([]byte, bool) {
	clean, err := template.CleanRef(ref)
	if err != nil {
		return nil, false
	}
	for _, k := range []string{clean, path.Join(dir, clean)} {
		if d, ok := byPath[k]; ok {
			return d, true
		}
	}
	return nil, false
}

func countLines(data []byte) int {
	n := 0
	for _, line := range bytes.Split(data, []byte("\n")) {
		if len(bytes.TrimSpace(line)) > 0 {
			n++
		}
	}
	return n
}

func satAdd(a, b int) int {
	if a > math.MaxInt32-b {
		return math.MaxInt32
	}
	return a + b
}

// tierOf maps a template's capabilities to its tier and the reason
// (RFC-061 §3.2): out-of-band callbacks, state-changing requests and high
// volume are T2; payload lists, protocols beyond HTTP and DNS are T1.
func tierOf(a *template.NucleiAnalysis) (dom.Tier, string) {
	for _, c := range []template.Capability{template.CapOOBCallback, template.CapHTTPStateChange, template.CapVolumeHigh} {
		if why, ok := a.Caps[c]; ok {
			return dom.TierT2, why
		}
	}
	for _, c := range []template.Capability{template.CapHTTPPayloads, template.CapNetRaw, template.CapDNSQuery} {
		if why, ok := a.Caps[c]; ok {
			return dom.TierT1, why
		}
	}
	return dom.TierT0, ""
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
