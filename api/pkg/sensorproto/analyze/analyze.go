// Package analyze is the openctem.analyze/v1 contract: the job an AI executor
// receives, the result it returns, the typed suggestions and the output schema
// of each kind, as versioned JSON Schemas (schemas/). The built-in executor in
// the API process and analyst workers (ours or a third party's) speak the same
// contract, so results go through one validation, provenance and governance
// path. Design: docs/rfcs/RFC-131-ai-analysis.md.
//
// The schemas are the contract; the Go types mirror them for the platform.
// A kind is versioned: a new kind or version never changes an existing one.
package analyze

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// Contract identifiers.
const (
	ContractJob    = "openctem.analyze/v1"
	ContractResult = "openctem.analyze.result/v1"
)

// Schema ids (the $id of each embedded schema).
const (
	SchemaJob               = "https://openctem.io/schemas/analyze/job/v1.json"
	SchemaResult            = "https://openctem.io/schemas/analyze/result/v1.json"
	SchemaSuggestion        = "https://openctem.io/schemas/analyze/suggestion/v1.json"
	SchemaOutputTriage      = "https://openctem.io/schemas/analyze/output/triage/v1.json"
	SchemaOutputRemediation = "https://openctem.io/schemas/analyze/output/remediation/v1.json"
	SchemaOutputSummary     = "https://openctem.io/schemas/analyze/output/summary/v1.json"
)

// Output schema names as recorded on a run.
const (
	OutputTriageV1      = "openctem.ai.triage/v1"
	OutputRemediationV1 = "openctem.ai.remediation/v1"
	OutputSummaryV1     = "openctem.ai.summary/v1"
)

// MaxDocumentBytes bounds a job, result or model output document.
const MaxDocumentBytes = 256 << 10

//go:embed schemas/*.json
var schemaFS embed.FS

var schemaFiles = map[string]string{
	SchemaJob:               "schemas/job.v1.schema.json",
	SchemaResult:            "schemas/result.v1.schema.json",
	SchemaSuggestion:        "schemas/suggestion.v1.schema.json",
	SchemaOutputTriage:      "schemas/output.triage.v1.schema.json",
	SchemaOutputRemediation: "schemas/output.remediation.v1.schema.json",
	SchemaOutputSummary:     "schemas/output.summary.v1.schema.json",
}

// SchemaJSON returns an embedded schema by id (for publishing and for
// third-party tooling); nil for an unknown id.
func SchemaJSON(id string) []byte {
	f, ok := schemaFiles[id]
	if !ok {
		return nil
	}
	b, err := schemaFS.ReadFile(f)
	if err != nil {
		return nil
	}
	return b
}

// SchemaIDs lists the embedded schema ids.
func SchemaIDs() []string {
	return []string{SchemaJob, SchemaResult, SchemaSuggestion, SchemaOutputTriage, SchemaOutputRemediation, SchemaOutputSummary}
}

// Kind describes one analyze kind.
type Kind struct {
	// Name is the versioned kind, e.g. triage.v1.
	Name string
	// UseCase is the organization-level use case the kind belongs to.
	UseCase string
	// OutputSchema is the name recorded on the run and OutputSchemaID the
	// schema the model output is validated against.
	OutputSchema   string
	OutputSchemaID string
	// SingleShot kinds need one model call and no tools: the built-in
	// executor may run them in the API process. Multi-step kinds only ever
	// run on an analyst worker.
	SingleShot bool
	// SuggestionKinds are the suggestion kinds the output may contain.
	SuggestionKinds []string
}

var kinds = map[string]Kind{
	"triage.v1": {Name: "triage.v1", UseCase: "triage", OutputSchema: OutputTriageV1, OutputSchemaID: SchemaOutputTriage,
		SingleShot: true, SuggestionKinds: []string{"verdict", "severity", "remediation_steps", "summary"}},
	"remediation.v1": {Name: "remediation.v1", UseCase: "remediation", OutputSchema: OutputRemediationV1, OutputSchemaID: SchemaOutputRemediation,
		SingleShot: true, SuggestionKinds: []string{"remediation_steps"}},
	"summary.v1": {Name: "summary.v1", UseCase: "summary", OutputSchema: OutputSummaryV1, OutputSchemaID: SchemaOutputSummary,
		SingleShot: true, SuggestionKinds: []string{"summary"}},
}

// LookupKind returns a known kind.
func LookupKind(name string) (Kind, bool) {
	k, ok := kinds[name]
	return k, ok
}

// Kinds lists the known kinds.
func Kinds() []Kind {
	return []Kind{kinds["triage.v1"], kinds["remediation.v1"], kinds["summary.v1"]}
}

// Evidence cites a bundle field ("bundle:<field>") or a tool output
// ("tool:<n>").
type Evidence struct {
	Ref   string `json:"ref"`
	Quote string `json:"quote,omitempty"`
}

// Suggestion is one typed suggestion (suggestion/v1). Payload is validated
// per kind by the schema; the platform decodes it strictly again.
type Suggestion struct {
	Kind       string          `json:"kind"`
	Payload    json.RawMessage `json:"payload"`
	Confidence float64         `json:"confidence"`
	Evidence   []Evidence      `json:"evidence"`
}

// Output is a model's output for a single-shot kind (output/<kind>/v1).
type Output struct {
	Suggestions []Suggestion `json:"suggestions"`
}

// Subject is what a job is about.
type Subject struct {
	Type    string `json:"type"`
	ID      string `json:"id"`
	AssetID string `json:"asset_id,omitempty"`
}

// Bundle describes the context the executor may read.
type Bundle struct {
	Digest         string   `json:"digest"`
	DataClass      string   `json:"data_class"`
	SealedRef      string   `json:"sealed_ref,omitempty"`
	Fields         []string `json:"fields"`
	FieldsWithheld []string `json:"fields_withheld,omitempty"`
	Masked         bool     `json:"masked,omitempty"`
}

// PromptTemplate names the template the executor must use.
type PromptTemplate struct {
	ID     string `json:"id"`
	Digest string `json:"digest"`
	Ref    string `json:"ref,omitempty"`
}

// ModelPolicy is the organization's model allowlist.
type ModelPolicy struct {
	Providers []string `json:"providers,omitempty"`
	Models    []string `json:"models,omitempty"`
	Region    string   `json:"region,omitempty"`
}

// Budgets bound a job.
type Budgets struct {
	Steps        int   `json:"steps,omitempty"`
	ToolCalls    int   `json:"tool_calls,omitempty"`
	Tokens       int   `json:"tokens,omitempty"`
	Seconds      int   `json:"seconds,omitempty"`
	CostMicroUSD int64 `json:"cost_micro_usd,omitempty"`
}

// TargetBinding binds a placeholder the model sees to the real target; only
// the subject's own targets are ever bound.
type TargetBinding struct {
	Token string `json:"token"`
	Value string `json:"value"`
}

// Grant is the investigation grant of a multi-step job.
type Grant struct {
	Tools       []string        `json:"tools"`
	Targets     []TargetBinding `json:"targets"`
	TierCeiling string          `json:"tier_ceiling"`
	Budgets     Budgets         `json:"budgets"`
}

// Job is an analyze job (job/v1).
type Job struct {
	Contract       string         `json:"contract"`
	JobID          string         `json:"job_id"`
	TenantID       string         `json:"tenant_id"`
	Kind           string         `json:"kind"`
	UseCase        string         `json:"use_case"`
	Subject        Subject        `json:"subject"`
	Bundle         Bundle         `json:"bundle"`
	OutputSchema   string         `json:"output_schema"`
	PromptTemplate PromptTemplate `json:"prompt_template"`
	ModelPolicy    *ModelPolicy   `json:"model_policy,omitempty"`
	Grant          *Grant         `json:"grant,omitempty"`
	Budgets        *Budgets       `json:"budgets,omitempty"`
	Deadline       time.Time      `json:"deadline"`
}

// Usage is what an execution consumed.
type Usage struct {
	Provider  string `json:"provider"`
	Model     string `json:"model"`
	TokensIn  int    `json:"tokens_in"`
	TokensOut int    `json:"tokens_out"`
	Steps     int    `json:"steps,omitempty"`
	ToolCalls int    `json:"tool_calls,omitempty"`
}

// TemplateRef is the template an execution used.
type TemplateRef struct {
	ID       string `json:"id"`
	Digest   string `json:"digest"`
	External bool   `json:"external,omitempty"`
}

// RunRecord points at the full record of a multi-step execution.
type RunRecord struct {
	Digest    string `json:"digest"`
	UploadRef string `json:"upload_ref,omitempty"`
}

// Result is the result of a job (result/v1).
type Result struct {
	Contract    string       `json:"contract"`
	JobID       string       `json:"job_id"`
	Status      string       `json:"status"`
	ErrorCode   string       `json:"error_code,omitempty"`
	Suggestions []Suggestion `json:"suggestions"`
	Usage       Usage        `json:"usage"`
	Template    TemplateRef  `json:"template"`
	RunRecord   *RunRecord   `json:"run_record,omitempty"`
}

// ErrInvalid matches every validation failure of this package (errors.Is).
var ErrInvalid = errors.New("analyze_contract_invalid")

// InvalidError is a document that does not satisfy its schema. Message names
// the first failing location; it never echoes document content.
type InvalidError struct {
	Schema  string
	Message string
}

func (e *InvalidError) Error() string { return "invalid " + e.Schema + ": " + e.Message }

// Is makes errors.Is(err, ErrInvalid) true.
func (e *InvalidError) Is(target error) bool { return target == ErrInvalid }

var (
	compileOnce sync.Once
	compiled    map[string]*jsonschema.Schema
	compileErr  error
)

func schemas() (map[string]*jsonschema.Schema, error) {
	compileOnce.Do(func() {
		c := jsonschema.NewCompiler()
		c.AssertFormat()
		for id, f := range schemaFiles {
			b, err := schemaFS.ReadFile(f)
			if err != nil {
				compileErr = err
				return
			}
			doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
			if err != nil {
				compileErr = fmt.Errorf("%s: %w", f, err)
				return
			}
			if err := c.AddResource(id, doc); err != nil {
				compileErr = err
				return
			}
		}
		out := make(map[string]*jsonschema.Schema, len(schemaFiles))
		for id := range schemaFiles {
			s, err := c.Compile(id)
			if err != nil {
				compileErr = fmt.Errorf("compile %s: %w", id, err)
				return
			}
			out[id] = s
		}
		compiled = out
	})
	return compiled, compileErr
}

// Validate checks a document against one of the embedded schemas.
func Validate(schemaID string, doc []byte) error {
	all, err := schemas()
	if err != nil {
		return fmt.Errorf("analyze schemas: %w", err)
	}
	s, ok := all[schemaID]
	if !ok {
		return &InvalidError{Schema: schemaID, Message: "unknown schema"}
	}
	if len(doc) == 0 || len(doc) > MaxDocumentBytes {
		return &InvalidError{Schema: schemaID, Message: fmt.Sprintf("document is empty or over %d bytes", MaxDocumentBytes)}
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(doc))
	if err != nil {
		return &InvalidError{Schema: schemaID, Message: "not a JSON document"}
	}
	if err := s.Validate(inst); err != nil {
		return &InvalidError{Schema: schemaID, Message: schemaLocation(err)}
	}
	return nil
}

// schemaLocation names the most specific failing location and keyword,
// without the instance value (model output must not be echoed).
func schemaLocation(err error) string {
	var ve *jsonschema.ValidationError
	if !errors.As(err, &ve) {
		return "does not match the schema"
	}
	for len(ve.Causes) > 0 {
		ve = ve.Causes[0]
	}
	loc := "/" + strings.Join(ve.InstanceLocation, "/")
	kw := "schema"
	if ve.ErrorKind != nil {
		if p := ve.ErrorKind.KeywordPath(); len(p) > 0 {
			kw = p[len(p)-1]
		}
	}
	return loc + ": fails " + kw
}

// ParseOutput validates a model's raw output for a kind and decodes it. The
// document must be the JSON object alone.
func ParseOutput(kind string, raw []byte) (*Output, error) {
	k, ok := LookupKind(kind)
	if !ok {
		return nil, &InvalidError{Schema: kind, Message: "unknown kind"}
	}
	if err := Validate(k.OutputSchemaID, raw); err != nil {
		return nil, err
	}
	var out Output
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		return nil, &InvalidError{Schema: k.OutputSchema, Message: "does not decode"}
	}
	seen := map[string]bool{}
	for _, s := range out.Suggestions {
		if seen[s.Kind] {
			return nil, &InvalidError{Schema: k.OutputSchema, Message: "more than one suggestion of kind " + s.Kind}
		}
		seen[s.Kind] = true
	}
	return &out, nil
}

// ParseResult validates and decodes a worker's result.
func ParseResult(raw []byte) (*Result, error) {
	if err := Validate(SchemaResult, raw); err != nil {
		return nil, err
	}
	var r Result
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return nil, &InvalidError{Schema: ContractResult, Message: "does not decode"}
	}
	return &r, nil
}

// MarshalJob encodes a job and checks it against the job schema, so the
// platform never emits a job a conforming executor would refuse.
func MarshalJob(j *Job) ([]byte, error) {
	if j.Contract == "" {
		j.Contract = ContractJob
	}
	b, err := json.Marshal(j)
	if err != nil {
		return nil, fmt.Errorf("marshal job: %w", err)
	}
	if err := Validate(SchemaJob, b); err != nil {
		return nil, err
	}
	return b, nil
}
