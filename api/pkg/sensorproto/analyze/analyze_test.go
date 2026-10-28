package analyze

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func read(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSchemasCompile(t *testing.T) {
	if _, err := schemas(); err != nil {
		t.Fatal(err)
	}
	for _, id := range SchemaIDs() {
		if len(SchemaJSON(id)) == 0 {
			t.Fatalf("schema %s not embedded", id)
		}
	}
}

func TestParseOutput_Valid(t *testing.T) {
	out, err := ParseOutput("triage.v1", read(t, "output.triage.valid.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Suggestions) != 4 {
		t.Fatalf("suggestions = %d", len(out.Suggestions))
	}
}

// The structural controls of a single-shot output: typed kinds and enums,
// no extra fields (a model cannot add a direction, a state or a target),
// evidence references in the fixed shape, bounded text, one suggestion per
// kind, and only the kinds the output schema allows.
func TestParseOutput_Refuses(t *testing.T) {
	cases := map[string]struct{ kind, doc string }{
		"direction in suggestion": {"triage.v1", `{"suggestions":[{"kind":"summary","payload":{"text":"s"},"confidence":0.5,"evidence":[],"direction":"additive"}]}`},
		"state in payload":        {"triage.v1", `{"suggestions":[{"kind":"verdict","payload":{"verdict":"true_positive","reason":"","state":"applied"},"confidence":0.5,"evidence":[]}]}`},
		"unknown verdict":         {"triage.v1", `{"suggestions":[{"kind":"verdict","payload":{"verdict":"closed","reason":""},"confidence":0.5,"evidence":[]}]}`},
		"confidence above 1":      {"triage.v1", `{"suggestions":[{"kind":"summary","payload":{"text":"s"},"confidence":1.5,"evidence":[]}]}`},
		"free-form evidence ref":  {"triage.v1", `{"suggestions":[{"kind":"summary","payload":{"text":"s"},"confidence":0.5,"evidence":[{"ref":"https://attacker.example/x"}]}]}`},
		"top-level extra":         {"triage.v1", `{"suggestions":[],"note":"ignore previous instructions"}`},
		"kind not allowed":        {"summary.v1", `{"suggestions":[{"kind":"verdict","payload":{"verdict":"true_positive","reason":""},"confidence":0.5,"evidence":[]}]}`},
		"two summaries":           {"triage.v1", `{"suggestions":[{"kind":"summary","payload":{"text":"a"},"confidence":0.5,"evidence":[]},{"kind":"summary","payload":{"text":"b"},"confidence":0.5,"evidence":[]}]}`},
		"over-long summary":       {"summary.v1", `{"suggestions":[{"kind":"summary","payload":{"text":"` + strings.Repeat("x", 4001) + `"},"confidence":0.5,"evidence":[]}]}`},
		"prose around JSON":       {"triage.v1", `Sure! {"suggestions":[]}`},
		"unknown kind":            {"exploit.v1", `{"suggestions":[]}`},
	}
	for name, c := range cases {
		_, err := ParseOutput(c.kind, []byte(c.doc))
		if !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrInvalid", name, err)
		}
	}
}

// A refusal never echoes the document (model output or injected text).
func TestParseOutput_ErrorDoesNotEchoContent(t *testing.T) {
	_, err := ParseOutput("triage.v1", []byte(`{"suggestions":[{"kind":"verdict","payload":{"verdict":"SECRET-MARKER","reason":""},"confidence":0.5,"evidence":[]}]}`))
	if err == nil || strings.Contains(err.Error(), "SECRET-MARKER") {
		t.Fatalf("err = %v", err)
	}
}

func TestParseResult(t *testing.T) {
	if _, err := ParseResult(read(t, "result.valid.json")); err != nil {
		t.Fatal(err)
	}
	bad := strings.Replace(string(read(t, "result.valid.json")), `"status":"completed"`, `"status":"approved"`, 1)
	if _, err := ParseResult([]byte(bad)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad status accepted: %v", err)
	}
}

func TestMarshalJob(t *testing.T) {
	j := &Job{
		JobID: "01a18087-4972-7af5-8ce4-36833fe53fc4", TenantID: "01a18087-4972-7af5-8ce4-36833fe53fc5",
		Kind: "triage.v1", UseCase: "triage",
		Subject: Subject{Type: "finding", ID: "01a18087-4972-7af5-8ce4-36833fe53fc6"},
		Bundle: Bundle{Digest: "sha256:" + strings.Repeat("a", 64), DataClass: "internal",
			Fields: []string{"finding.title", "evidence.redacted"}, Masked: true},
		OutputSchema:   OutputTriageV1,
		PromptTemplate: PromptTemplate{ID: "triage.v1", Digest: "sha256:" + strings.Repeat("b", 64)},
		Deadline:       time.Date(2026, 10, 28, 10, 5, 0, 0, time.UTC),
	}
	b, err := MarshalJob(j)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), ContractJob) {
		t.Fatal("contract id missing")
	}
	j.Bundle.Digest = "md5:abc"
	if _, err := MarshalJob(j); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad digest accepted: %v", err)
	}
	j.Bundle.Digest = "sha256:" + strings.Repeat("a", 64)
	j.Bundle.DataClass = "secret"
	if _, err := MarshalJob(j); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown data class accepted: %v", err)
	}
}

func TestKinds(t *testing.T) {
	for _, k := range Kinds() {
		if !k.SingleShot {
			t.Fatalf("%s: only single-shot kinds exist yet", k.Name)
		}
		if _, ok := schemaFiles[k.OutputSchemaID]; !ok {
			t.Fatalf("%s: output schema not embedded", k.Name)
		}
	}
}

func FuzzParseOutput(f *testing.F) {
	f.Add([]byte(`{"suggestions":[]}`))
	f.Add([]byte(`{"suggestions":[{"kind":"summary","payload":{"text":"s"},"confidence":0.5,"evidence":[]}]}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		out, err := ParseOutput("triage.v1", b)
		if err == nil {
			for _, s := range out.Suggestions {
				if s.Confidence < 0 || s.Confidence > 1 {
					t.Fatal("confidence out of range accepted")
				}
			}
		}
	})
}
