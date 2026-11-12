// Package compliancecheck holds the state of benchmark checks per asset and
// control (docs/architecture/compliance-checks.md).
//
// A benchmark check result is a state of one control on one asset, not a
// vulnerability. Every result a scan or an import reports becomes the latest
// state of its control, with its evidence; every change of result or
// evidence is kept as history. Only a failed result (and a warning, which
// needs a person to judge) keeps a finding open.
package compliancecheck

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// Result is the evaluation of one control. The tokens are those of
// findings.compliance_result.
type Result string

// Results.
const (
	ResultPass          Result = "pass"
	ResultFail          Result = "fail"
	ResultManual        Result = "manual" // a scanner warning: a person judges it
	ResultNotApplicable Result = "not_applicable"
	ResultError         Result = "error" // the check could not run
)

// Results lists every result in display order (failed first).
func Results() []Result {
	return []Result{ResultFail, ResultManual, ResultError, ResultNotApplicable, ResultPass}
}

// IsValid reports whether r is a known result.
func (r Result) IsValid() bool {
	switch r {
	case ResultPass, ResultFail, ResultManual, ResultNotApplicable, ResultError:
		return true
	}
	return false
}

// OpensFinding reports whether the result keeps a finding open: a failure,
// and a warning (a person must judge it). A pass, a not-applicable and an
// error are states only.
func (r Result) OpensFinding() bool { return r == ResultFail || r == ResultManual }

// Outcome names why a not_applicable result was not evaluated, as the
// importer reports it in extensions["io.openctem"].compliance_outcome.
const (
	OutcomeError   = "error"
	OutcomeSkipped = "skipped"
)

// ResultOf maps a CTIS compliance finding to a result: its kind (pass, fail,
// review, not_applicable) and, for not_applicable, the importer's outcome
// (error keeps its own state; skipped stays not applicable). nativeResult is
// the scanner's own word when the report carries it (Nessus PASSED, FAILED,
// WARNING, ERROR, SKIPPED), read only when the outcome is absent, so an
// error is never folded into not applicable. ok is false for a kind that is
// no compliance result.
func ResultOf(kind, outcome, nativeResult string) (Result, bool) {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "pass":
		return ResultPass, true
	case "fail":
		return ResultFail, true
	case "review":
		return ResultManual, true
	case "not_applicable":
		switch strings.ToLower(strings.TrimSpace(outcome)) {
		case OutcomeError:
			return ResultError, true
		case OutcomeSkipped:
			return ResultNotApplicable, true
		}
		if strings.EqualFold(strings.TrimSpace(nativeResult), "ERROR") {
			return ResultError, true
		}
		return ResultNotApplicable, true
	}
	return "", false
}

// Bounds of the stored text.
const (
	MaxBenchmarkKeyLen     = 160
	MaxBenchmarkNameLen    = 500
	MaxBenchmarkVersionLen = 100
	MaxFrameworkLen        = 50
	MaxControlIDLen        = 200
	MaxControlNameLen      = 500
	MaxToolNameLen         = 100
	MaxEvidenceValueLen    = 4096
)

var reKeyRun = regexp.MustCompile(`[^a-z0-9.]+`)

// BenchmarkKey is the stable key of a benchmark: its name lowercased, every
// run of other characters one dash, at most MaxBenchmarkKeyLen bytes. It
// never contains "/" or ":" (it is part of a remediation key and of a URL
// path segment). "" for a blank name.
func BenchmarkKey(name string) string {
	k := strings.Trim(reKeyRun.ReplaceAllString(strings.ToLower(strings.TrimSpace(name)), "-"), "-.")
	if len(k) > MaxBenchmarkKeyLen {
		k = strings.TrimRight(k[:MaxBenchmarkKeyLen], "-.")
	}
	return k
}

// Evidence is what the check saw: the actual and the expected value, the
// scanner's message (the error of a check that could not run) and the audit
// file it came from. Each value is bounded to MaxEvidenceValueLen characters.
type Evidence struct {
	Actual    string `json:"actual,omitempty"`
	Expected  string `json:"expected,omitempty"`
	Message   string `json:"message,omitempty"`
	AuditFile string `json:"audit_file,omitempty"`
}

// Bounded returns e with every value trimmed and cut to its bound.
func (e Evidence) Bounded() Evidence {
	return Evidence{
		Actual:    Clip(strings.TrimSpace(e.Actual), MaxEvidenceValueLen),
		Expected:  Clip(strings.TrimSpace(e.Expected), MaxEvidenceValueLen),
		Message:   Clip(strings.TrimSpace(e.Message), MaxEvidenceValueLen),
		AuditFile: Clip(strings.TrimSpace(e.AuditFile), MaxEvidenceValueLen),
	}
}

// IsEmpty reports whether e holds nothing.
func (e Evidence) IsEmpty() bool { return e == Evidence{} }

// Hash is a stable digest of the bounded evidence ("" when empty), so a
// change of evidence with the same result is recorded as history.
func (e Evidence) Hash() string {
	b := e.Bounded()
	if b.IsEmpty() {
		return ""
	}
	raw, _ := json.Marshal(b)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// Clip cuts s to at most n characters (not bytes).
func Clip(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
}

// Observation is one result of one control on one asset, as a scan or an
// import reported it.
type Observation struct {
	AssetID shared.ID
	// Fingerprint is the finding identity of the check on its asset: a
	// failure's finding carries it, a pass of the same check shares it.
	Fingerprint      string
	BenchmarkKey     string
	BenchmarkName    string
	BenchmarkVersion string
	Framework        string
	ControlID        string
	ControlName      string
	Level            vulnerability.ComplianceLevel
	Result           Result
	// ScannerSeverity is the severity the scanner gave the result (kept: the
	// platform derives its own for a compliance finding).
	ScannerSeverity string
	Evidence        Evidence
	ToolName        string
	ObservedAt      time.Time
}

// Valid reports whether o can be stored: an asset, a benchmark, a control
// and a known result.
func (o Observation) Valid() bool {
	return !o.AssetID.IsZero() && o.BenchmarkKey != "" && strings.TrimSpace(o.ControlID) != "" && o.Result.IsValid() &&
		!o.ObservedAt.IsZero()
}

// Source of a history row.
const (
	SourceIngest   = "ingest"
	SourceBackfill = "backfill"
)

// RecordStats counts what recording a batch did.
type RecordStats struct {
	Created   int // new control states
	Changed   int // states whose result or evidence changed
	Unchanged int // same result and evidence: only the check time moved
	Older     int // observed before the stored state: kept as history only
	Invalid   int // left out: no asset, benchmark, control or result
	// Assets are the assets whose states were written (their posture is
	// refreshed).
	Assets []shared.ID
}

// Recorder stores observations: the latest state per (asset, benchmark,
// control) and a history row for the first observation and every change.
// Pinned to the tenant: an asset or finding of another tenant is never read
// or written.
type Recorder interface {
	Record(ctx context.Context, tenantID shared.ID, source string, obs []Observation) (RecordStats, error)
}
