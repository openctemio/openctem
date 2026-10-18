package contentpack

import (
	"context"
	"strings"
	"testing"

	dom "github.com/openctemio/openctem/api/pkg/domain/contentpack"
)

// Malicious packs: code-class blocks, workflows that reach outside the
// pack, hidden out-of-band callbacks, concurrency written as text and
// request floods.

const flowTemplate = `id: org-flow
info:
  name: scripted
  severity: info
flow: |
  for (let i = 0; i < 1e9; i++) { http(1) }
http:
  - method: GET
    path: ["{{BaseURL}}/"]
`

func lintFiles(t *testing.T, files map[string]string) dom.LintReport {
	t.Helper()
	fs := make([]dom.File, 0, len(files))
	for p, d := range files {
		fs = append(fs, dom.File{Path: p, Data: []byte(d)})
	}
	return Lint(context.Background(), dom.KindNucleiTemplates, fs)
}

func hasCode(issues []dom.Issue, code string) bool {
	for _, i := range issues {
		if strings.Contains(i.Code, code) {
			return true
		}
	}
	return false
}

func TestLintRefusesFlow(t *testing.T) {
	rep := lintFiles(t, map[string]string{"flow.yaml": flowTemplate})
	if !hasCode(rep.Errors, "DANGEROUS_PATTERN") {
		t.Fatalf("flow template accepted: %+v", rep)
	}
	// An upstream release leaves it out instead of refusing the release.
	rep, excluded := LintExcluding(context.Background(), dom.KindNucleiTemplates, []dom.File{
		{Path: "flow.yaml", Data: []byte(flowTemplate)},
		{Path: "ok.yaml", Data: []byte(passiveTemplate)},
	})
	if !excluded["flow.yaml"] || excluded["ok.yaml"] || len(rep.Errors) != 0 {
		t.Fatalf("excluded=%v report=%+v", excluded, rep)
	}
}

func workflow(refs ...string) string {
	var b strings.Builder
	b.WriteString("id: org-wf\ninfo:\n  name: wf\n  severity: info\nworkflows:\n")
	for _, r := range refs {
		b.WriteString("  - template: " + r + "\n")
	}
	return b.String()
}

func TestLintWorkflowReferencesStayInsidePack(t *testing.T) {
	cases := map[string]struct {
		files map[string]string
		code  string
	}{
		"not in pack":                 {map[string]string{"wf.yaml": workflow("http/cves/CVE-2021-44228.yaml"), "a.yaml": passiveTemplate}, "WORKFLOW_OUTSIDE_SNAPSHOT"},
		"parent directory":            {map[string]string{"wf/wf.yaml": workflow("../a.yaml"), "a.yaml": passiveTemplate}, "WORKFLOW_OUTSIDE_SNAPSHOT"},
		"absolute path":               {map[string]string{"wf.yaml": workflow("/root/nuclei-templates/a.yaml"), "a.yaml": passiveTemplate}, "WORKFLOW_OUTSIDE_SNAPSHOT"},
		"refused reference":           {map[string]string{"wf.yaml": workflow("flow.yaml"), "flow.yaml": flowTemplate}, "WORKFLOW_REFERENCE_REFUSED"},
		"code reference":              {map[string]string{"wf.yaml": workflow("code.yaml"), "code.yaml": codeTemplate}, "WORKFLOW_REFERENCE_REFUSED"},
		"cycle":                       {map[string]string{"wf.yaml": workflow("wf2.yaml"), "wf2.yaml": strings.Replace(workflow("wf.yaml"), "org-wf", "org-wf2", 1)}, "WORKFLOW_CYCLE"},
		"tag selector":                {map[string]string{"wf.yaml": "id: wf\ninfo: {name: wf, severity: info}\nworkflows:\n  - template: a.yaml\n    subtemplates:\n      - tags: intrusive\n", "a.yaml": passiveTemplate}, "WORKFLOW_TAG_SELECTOR"},
		"matcher subtemplate outside": {map[string]string{"wf.yaml": "id: wf\ninfo: {name: wf, severity: info}\nworkflows:\n  - template: a.yaml\n    matchers:\n      - name: x\n        subtemplates:\n          - template: other/b.yaml\n", "a.yaml": passiveTemplate}, "WORKFLOW_OUTSIDE_SNAPSHOT"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			rep := lintFiles(t, c.files)
			if !hasCode(rep.Errors, c.code) {
				t.Fatalf("want %s, got %+v", c.code, rep.Errors)
			}
		})
	}
}

// A workflow's tier is that of what it runs.
func TestLintWorkflowTierIsMaxOfReferenced(t *testing.T) {
	rep := lintFiles(t, map[string]string{"wf.yaml": workflow("oob.yaml"), "oob.yaml": oobTemplate})
	if len(rep.Errors) != 0 || rep.Tier != dom.TierT2 {
		t.Fatalf("tier %s errors %+v", rep.Tier, rep.Errors)
	}
	rep = lintFiles(t, map[string]string{"wf.yaml": workflow("./a.yaml"), "a.yaml": passiveTemplate})
	if len(rep.Errors) != 0 || rep.Tier != dom.TierT1 {
		t.Fatalf("passive workflow: tier %s errors %+v", rep.Tier, rep.Errors)
	}
	// Relative to the workflow's own directory.
	rep = lintFiles(t, map[string]string{"wf/wf.yaml": workflow("a.yaml"), "wf/a.yaml": passiveTemplate})
	if len(rep.Errors) != 0 {
		t.Fatalf("sibling reference refused: %+v", rep.Errors)
	}
}

func TestLintTierFromParsedFields(t *testing.T) {
	get := func(extra string) string {
		return "id: t\ninfo: {name: x, severity: info}\nhttp:\n  - method: GET\n    path: [\"{{BaseURL}}/{{p}}\"]\n" + extra
	}
	cases := map[string]string{
		"escaped interactsh":  "id: t\ninfo: {name: x, severity: info}\nhttp:\n  - method: GET\n    path: [\"{{BaseURL}}/?u={{\\x69nteractsh-url}}\"]\n",
		"split interactsh":    "id: t\ninfo: {name: x, severity: info}\nhttp:\n  - method: GET\n    path: ['{{BaseURL}}/?u={{concat(\"intera\",\"ctsh-url\")}}']\n",
		"threads as string":   get("    threads: \"50\"\n"),
		"threads templated":   get("    threads: \"{{n}}\"\n"),
		"threads as float":    get("    threads: 26.0\n"),
		"many payloads":       get("    payloads:\n      p: [" + strings.Repeat("a,", 600) + "a]\n"),
		"payload file volume": get("    payloads:\n      p: lists/words.txt\n"),
	}
	for name, tpl := range cases {
		t.Run(name, func(t *testing.T) {
			rep := lintFiles(t, map[string]string{"t.yaml": tpl, "lists/words.txt": strings.Repeat("w\n", 700)})
			if len(rep.Errors) != 0 || rep.Tier != dom.TierT2 {
				t.Fatalf("tier %s errors %+v", rep.Tier, rep.Errors)
			}
		})
	}
}

func TestLintPayloadFilesStayInsidePack(t *testing.T) {
	tpl := func(ref string) string {
		return "id: t\ninfo: {name: x, severity: info}\nhttp:\n  - method: GET\n    path: [\"{{BaseURL}}/{{p}}\"]\n    payloads:\n      p: " + ref + "\n"
	}
	for _, ref := range []string{"/etc/passwd", "../../etc/shadow", "missing.txt"} {
		rep := lintFiles(t, map[string]string{"t.yaml": tpl(ref)})
		if !hasCode(rep.Errors, "PAYLOAD_FILE_OUTSIDE_SNAPSHOT") && !hasCode(rep.Errors, "DANGEROUS_PATTERN") {
			t.Errorf("%s: %+v", ref, rep.Errors)
		}
	}
	rep := lintFiles(t, map[string]string{"t.yaml": tpl("words.txt"), "words.txt": "a\nb\n"})
	if len(rep.Errors) != 0 || rep.Tier != dom.TierT1 {
		t.Fatalf("in-pack payload file: tier %s errors %+v", rep.Tier, rep.Errors)
	}
}

func TestLintWorkflowVolumeCap(t *testing.T) {
	big := "id: big\ninfo: {name: x, severity: info}\nhttp:\n  - method: GET\n    path: [\"{{BaseURL}}/{{p}}\"]\n    payloads:\n      p: words.txt\n"
	files := map[string]string{"big.yaml": big, "words.txt": strings.Repeat("w\n", 6000), "wf.yaml": workflow("big.yaml", "big.yaml")}
	rep := lintFiles(t, files)
	if !hasCode(rep.Errors, "REQUEST_VOLUME_CAP") {
		t.Fatalf("12000-request workflow accepted: %+v", rep)
	}
}
