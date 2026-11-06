package template

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scannertemplate"
)

// Malicious custom templates: code-class blocks in every spelling the
// engine accepts, references outside the template, payload files and
// request floods are refused on the parsed document.

const httpBlock = `
http:
  - method: GET
    path: ["{{BaseURL}}/"]
    matchers:
      - type: word
        words: ["ok"]
`

func nucleiErrs(content string) []string {
	res := ValidateTemplate(scannertemplate.TemplateTypeNuclei, []byte(content))
	codes := make([]string, 0, len(res.Errors))
	for _, e := range res.Errors {
		codes = append(codes, e.Code)
	}
	return codes
}

func TestNucleiFlowIsCodeClass(t *testing.T) {
	cases := map[string]string{
		"block yaml":       "id: f\ninfo: {name: x, severity: info}\nflow: http(1) && http(2)\n" + httpBlock,
		"upper case key":   "id: f\ninfo: {name: x, severity: info}\nFLOW: http(1)\n" + httpBlock,
		"padded key":       "id: f\ninfo: {name: x, severity: info}\n\"flow \": http(1)\n" + httpBlock,
		"escaped key":      "id: f\ninfo: {name: x, severity: info}\n\"\\x66low\": http(1)\n" + httpBlock,
		"flow mapping":     `{id: f, info: {name: x, severity: info}, flow: "http(1)", http: [{method: GET, path: ["{{BaseURL}}"]}]}`,
		"json":             `{"id": "f", "info": {"name": "x", "severity": "info"}, "Flow": "http(1)", "http": [{"method": "GET", "path": ["{{BaseURL}}"]}]}`,
		"json escaped key": `{"id": "f", "info": {"name": "x", "severity": "info"}, "\u0066low": "http(1)", "http": [{"method": "GET", "path": ["{{BaseURL}}"]}]}`,
		"merge key":        "id: f\ninfo: {name: x, severity: info}\n<<: {flow: \"http(1)\"}\n" + httpBlock,
	}
	for name, tpl := range cases {
		t.Run(name, func(t *testing.T) {
			if codes := nucleiErrs(tpl); !slices.Contains(codes, "DANGEROUS_PATTERN") {
				t.Fatalf("flow template accepted: %v", codes)
			}
		})
	}
}

// A second YAML document is refused: the engine and this check must read
// the same document.
func TestNucleiSecondDocumentRefused(t *testing.T) {
	tpl := "id: ok\ninfo: {name: x, severity: info}\n" + httpBlock + "---\nid: ok\nflow: http(1)\n"
	if codes := nucleiErrs(tpl); !slices.Contains(codes, "INVALID_YAML") {
		t.Fatalf("multi-document template accepted: %v", codes)
	}
}

func TestNucleiSingleTemplateReferences(t *testing.T) {
	cases := map[string]struct{ tpl, code string }{
		"workflow template":    {"id: w\ninfo: {name: x, severity: info}\nworkflows:\n  - template: http/cves/2021/CVE-2021-44228.yaml\n", "WORKFLOW_OUTSIDE_SNAPSHOT"},
		"workflow subtemplate": {"id: w\ninfo: {name: x, severity: info}\nworkflows:\n  - template: a.yaml\n    matchers:\n      - name: m\n        subtemplates:\n          - template: /etc/nuclei/x.yaml\n", "WORKFLOW_OUTSIDE_SNAPSHOT"},
		"workflow tags":        {"id: w\ninfo: {name: x, severity: info}\nworkflows:\n  - tags: intrusive\n", "WORKFLOW_OUTSIDE_SNAPSHOT"},
		"payload file":         {"id: p\ninfo: {name: x, severity: info}\nhttp:\n  - method: GET\n    path: [\"{{BaseURL}}/{{p}}\"]\n    payloads:\n      p: helpers/wordlists/big.txt\n", "PAYLOAD_FILE_OUTSIDE_SNAPSHOT"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if codes := nucleiErrs(c.tpl); !slices.Contains(codes, c.code) {
				t.Fatalf("want %s, got %v", c.code, codes)
			}
		})
	}
}

func TestNucleiRequestVolumeCap(t *testing.T) {
	list := func(n int) string {
		items := make([]string, n)
		for i := range items {
			items[i] = fmt.Sprintf("v%d", i)
		}
		return "[" + strings.Join(items, ", ") + "]"
	}
	flood := "id: v\ninfo: {name: x, severity: info}\nhttp:\n  - method: GET\n    path: [\"{{BaseURL}}/{{a}}/{{b}}\"]\n    attack: clusterbomb\n    payloads:\n      a: " + list(200) + "\n      b: " + list(200) + "\n"
	if codes := nucleiErrs(flood); !slices.Contains(codes, "REQUEST_VOLUME_CAP") {
		t.Fatalf("40000-request template accepted: %v", codes)
	}
	// The same lists walked side by side are 200 requests.
	pitch := strings.Replace(flood, "clusterbomb", "pitchfork", 1)
	if codes := nucleiErrs(pitch); len(codes) != 0 {
		t.Fatalf("200-request template refused: %v", codes)
	}
}

func TestAnalyzeNuclei(t *testing.T) {
	parse := func(s string) map[string]any {
		tpl, err := decodeSingleDocument([]byte(s))
		if err != nil {
			t.Fatal(err)
		}
		return tpl
	}
	cases := []struct {
		name string
		tpl  string
		want Capability
		not  bool
	}{
		{"passive", "id: a\n" + httpBlock, CapHTTPRead, false},
		{"passive has no oob", "id: a\n" + httpBlock, CapOOBCallback, true},
		{"interactsh spaced and cased", "id: a\nhttp:\n  - method: GET\n    path: [\"{{BaseURL}}/?u={{ InteractSh-URL }}\"]\n", CapOOBCallback, false},
		{"interactsh split by helper", "id: a\nhttp:\n  - method: GET\n    path: ['{{BaseURL}}/?u={{concat(\"interact\",\"sh-url\")}}']\n", CapOOBCallback, false},
		{"interactsh escaped", "id: a\nhttp:\n  - method: GET\n    path: [\"{{BaseURL}}/?u={{\\x69nteractsh-url}}\"]\n", CapOOBCallback, false},
		{"interactsh in a variable", "id: a\nvariables:\n  cb: \"{{interactsh-url}}\"\nhttp:\n  - method: GET\n    path: [\"{{BaseURL}}/?u={{cb}}\"]\n", CapOOBCallback, false},
		{"interactsh matcher part", "id: a\nhttp:\n  - method: GET\n    path: [\"{{BaseURL}}\"]\n    matchers:\n      - type: word\n        part: interactsh_protocol\n        words: [dns]\n", CapOOBCallback, false},
		{"public callback domain", "id: a\nhttp:\n  - method: GET\n    path: [\"{{BaseURL}}/?u=x.oast.fun\"]\n", CapOOBCallback, false},
		{"threads as string", "id: a\nhttp:\n  - method: GET\n    threads: \"50\"\n    path: [\"{{BaseURL}}\"]\n", CapVolumeHigh, false},
		{"threads as float", "id: a\nhttp:\n  - method: GET\n    threads: 50.5\n    path: [\"{{BaseURL}}\"]\n", CapVolumeHigh, false},
		{"threads templated", "id: a\nhttp:\n  - method: GET\n    threads: \"{{t}}\"\n    path: [\"{{BaseURL}}\"]\n", CapVolumeHigh, false},
		{"threads small string", "id: a\nhttp:\n  - method: GET\n    threads: \"10\"\n    path: [\"{{BaseURL}}\"]\n", CapVolumeHigh, true},
		{"race count", "id: a\nhttp:\n  - raw: [\"GET / HTTP/1.1\\nHost: {{Hostname}}\\n\\n\"]\n    race_count: 5\n", CapVolumeHigh, false},
		{"delete", "id: a\nhttp:\n  - method: delete\n    path: [\"{{BaseURL}}\"]\n", CapHTTPStateChange, false},
		{"fuzzing", "id: a\nhttp:\n  - method: GET\n    path: [\"{{BaseURL}}\"]\n    fuzzing:\n      - part: query\n        type: postfix\n        fuzz: [\"'\"]\n", CapVolumeHigh, false},
		{"flow", "id: a\nflow: http(1)\n" + httpBlock, CapScriptFlow, false},
		{"network", "id: a\nnetwork:\n  - host: [\"{{Hostname}}\"]\n    inputs: [{data: x}]\n", CapNetRaw, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := AnalyzeNuclei(parse(c.tpl), nil)
			_, has := a.Caps[c.want]
			if has == c.not {
				t.Fatalf("capability %s present=%v, want %v (caps %v)", c.want, has, !c.not, a.SortedCaps())
			}
		})
	}
}

// Declared request counts are ignored: the estimate comes from the
// structure.
func TestAnalyzeNucleiIgnoresDeclaredVolume(t *testing.T) {
	tpl, err := decodeSingleDocument([]byte("id: a\ninfo:\n  name: x\n  severity: info\n  metadata:\n    max-request: 1\nhttp:\n  - method: GET\n    path: [\"{{BaseURL}}/{{p}}\"]\n    payloads:\n      p: [" + strings.Repeat("x,", 600) + "x]\n"))
	if err != nil {
		t.Fatal(err)
	}
	a := AnalyzeNuclei(tpl, nil)
	if a.Requests != 601 {
		t.Fatalf("requests = %d, want 601", a.Requests)
	}
	if _, ok := a.Caps[CapVolumeHigh]; !ok {
		t.Fatalf("601 requests not high volume: %v", a.SortedCaps())
	}
}

func TestCleanRef(t *testing.T) {
	for _, bad := range []string{"", "/etc/passwd", "../x.yaml", "a/../../x.yaml", "~/x.yaml", "https://example.com/x.yaml", "{{path}}/x.yaml", "a\\..\\x.yaml"} {
		if _, err := CleanRef(bad); err == nil {
			t.Errorf("CleanRef(%q) accepted", bad)
		}
	}
	for in, want := range map[string]string{"a.yaml": "a.yaml", "./dir/a.yaml": "dir/a.yaml", "dir//a.yaml": "dir/a.yaml"} {
		if got, err := CleanRef(in); err != nil || got != want {
			t.Errorf("CleanRef(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
}

func TestValidateNucleiRecordsCapabilities(t *testing.T) {
	res := ValidateNuclei([]byte("id: a\ninfo: {name: x, severity: info}\n"+httpBlock), NucleiOptions{})
	if res.HasErrors() {
		t.Fatalf("passive template refused: %v", res.Errors)
	}
	caps, _ := res.Metadata["capabilities"].([]string)
	if !slices.Equal(caps, []string{string(CapHTTPRead)}) || res.Metadata["estimated_requests"] != 1 {
		t.Fatalf("metadata = %v", res.Metadata)
	}
}
