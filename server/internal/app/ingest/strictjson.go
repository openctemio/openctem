package ingest

// Strict CTIS decoding for sensor protocol v2 results (RFC-026 §3.3 step 7,
// docs/rfcs/RFC-026-sensor-results-ingest.md).
//
// Go's encoding/json keeps the last of two duplicate member names, replaces
// invalid UTF-8 and lone surrogate escapes with U+FFFD, and has no depth
// limit. Two parsers that disagree on those points read two different
// reports from one body (a JSON parser-differential), so a payload can pass
// validation in one reading and be stored in another; to close that,
// v2 accepts only I-JSON (RFC 7493): a token-level pre-pass rejects what
// encoding/json would silently repair, then the one decoder runs with
// DisallowUnknownFields. There is no second, schema-engine parser.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/openctemio/ctis/v2"

	protov2 "github.com/openctemio/openctem/server/pkg/sensorproto/v2"
)

// Reasons the I-JSON pre-pass refuses a document. They map to 422
// invalid-json; none of them quotes the input.
var (
	ErrJSONInvalidUTF8     = errors.New("invalid UTF-8")
	ErrJSONLoneSurrogate   = errors.New("lone surrogate escape")
	ErrJSONDuplicateMember = errors.New("duplicate member name")
	ErrJSONTooDeep         = errors.New("nesting deeper than the limit")
	ErrJSONTrailingData    = errors.New("data after the top-level value")
	ErrJSONNumberRange     = errors.New("number out of range")
	ErrJSONNotObject       = errors.New("top-level value is not an object")
	// ErrJSONTooManyItems: an array, or the whole document, holds more
	// values than its bound (JSONBounds). Maps to report-too-large: the
	// sensor splits the report into smaller segments.
	ErrJSONTooManyItems = errors.New("more items than the limit")
	ErrJSONSyntax       = errors.New("syntax error")
)

// JSONBounds caps how many values a document may hold, checked by the
// streaming pre-pass before anything is decoded. Decoding allocates per value
// far more than the value's bytes on the wire (an empty object "{}" in the
// findings array becomes an 840-byte ctis.Finding), so a body within the
// byte limits could otherwise make one request allocate gigabytes. Zero
// fields are not checked.
type JSONBounds struct {
	// TopArrays caps the element count of a member array of the top-level
	// object, by member name ("findings", "assets").
	TopArrays map[string]int
	// MaxArrayLen caps every other array.
	MaxArrayLen int
	// MaxContainers caps the objects and arrays of the whole document.
	MaxContainers int
	// MaxValues caps every value of the whole document (containers
	// included).
	MaxValues int
}

// Bounds of a v2 report segment beyond the per-segment item limits: any
// other array, the containers per segment item and the values per segment
// item. A legitimate segment that exceeds them is refused as
// report-too-large, and the sensor splits it further.
const (
	reportMaxArrayLen         = 100_000
	reportContainersPerItem   = 10
	reportValuesPerItem       = 100
	reportMinItemsForPerItems = 1_000
)

// ReportBounds are the decode bounds of a report segment under limits.
func ReportBounds(limits protov2.Limits) JSONBounds {
	items := max(limits.MaxFindingsPerSegment+limits.MaxAssetsPerSegment, reportMinItemsForPerItems)
	return JSONBounds{
		TopArrays:     map[string]int{"findings": limits.MaxFindingsPerSegment, "assets": limits.MaxAssetsPerSegment},
		MaxArrayLen:   reportMaxArrayLen,
		MaxContainers: items * reportContainersPerItem,
		MaxValues:     items * reportValuesPerItem,
	}
}

// CIReportBounds are the decode bounds of a CI run upload (one report per
// request, up to MaxFindingsPerReport findings, no segments).
var CIReportBounds = JSONBounds{
	MaxArrayLen:   MaxFindingsPerReport,
	MaxContainers: 1_000_000,
	MaxValues:     5_000_000,
}

// CheckIJSON is the pre-pass: valid UTF-8, no lone surrogate escape, no
// duplicate member name in any object, nesting at most maxDepth, numbers
// representable as float64, one top-level object and nothing after it.
func CheckIJSON(data []byte, maxDepth int) error {
	return CheckIJSONBounded(data, maxDepth, JSONBounds{})
}

// CheckIJSONBounded is CheckIJSON that also enforces b, so that the decode
// that follows allocates in proportion to the limits, not to the body.
//
//nolint:cyclop,gocognit,gocyclo // one tokenizer loop; splitting it hides the state machine
func CheckIJSONBounded(data []byte, maxDepth int, b JSONBounds) error {
	if !utf8.Valid(data) {
		return ErrJSONInvalidUTF8
	}
	if err := checkSurrogates(data); err != nil {
		return err
	}

	var stack []jsonFrame
	containers, values := 0, 0

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()

	first := true
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			if first || len(stack) != 0 {
				return ErrJSONSyntax
			}
			return nil
		}
		if err != nil {
			return ErrJSONSyntax
		}
		if first {
			if d, ok := tok.(json.Delim); !ok || d != '{' {
				return ErrJSONNotObject
			}
		} else if len(stack) == 0 {
			// The top-level object closed and another token follows.
			return ErrJSONTrailingData
		}
		first = false

		// A key position in an object: tok is the member name.
		if n := len(stack); n > 0 && stack[n-1].object && stack[n-1].expectKey {
			if d, ok := tok.(json.Delim); ok && d == '}' {
				stack = stack[:n-1]
				markValueDone(stack)
				continue
			}
			key, ok := tok.(string)
			if !ok {
				return ErrJSONSyntax
			}
			if _, dup := stack[n-1].keys[key]; dup {
				return ErrJSONDuplicateMember
			}
			stack[n-1].keys[key] = struct{}{}
			stack[n-1].expectKey = false
			stack[n-1].lastKey = key
			continue
		}

		// tok starts a value unless it closes an array.
		if d, ok := tok.(json.Delim); !ok || d != ']' {
			if err := countValue(stack, d == '{' || d == '[', &containers, &values, b); err != nil {
				return err
			}
		}

		switch v := tok.(type) {
		case json.Delim:
			switch v {
			case '{':
				if len(stack) >= maxDepth {
					return ErrJSONTooDeep
				}
				stack = append(stack, jsonFrame{object: true, expectKey: true, keys: map[string]struct{}{}})
			case '[':
				if len(stack) >= maxDepth {
					return ErrJSONTooDeep
				}
				stack = append(stack, jsonFrame{limit: arrayLimit(stack, b)})
			case ']':
				if len(stack) == 0 || stack[len(stack)-1].object {
					return ErrJSONSyntax
				}
				stack = stack[:len(stack)-1]
				markValueDone(stack)
			default:
				return ErrJSONSyntax
			}
		case json.Number:
			if _, err := strconv.ParseFloat(string(v), 64); err != nil {
				return ErrJSONNumberRange
			}
			markValueDone(stack)
		default:
			markValueDone(stack)
		}
	}
}

// jsonFrame is one open object or array in the pre-pass.
type jsonFrame struct {
	object    bool
	expectKey bool
	keys      map[string]struct{}
	// lastKey is the member whose value is being read (objects).
	lastKey string
	// count and limit are the elements so far and the bound (arrays; a
	// zero limit is unbounded).
	count, limit int
}

// arrayLimit is the element bound of an array opened inside stack: the
// top-level member's own bound, else MaxArrayLen.
func arrayLimit(stack []jsonFrame, b JSONBounds) int {
	if len(stack) == 1 && stack[0].object {
		if n, ok := b.TopArrays[stack[0].lastKey]; ok {
			return n
		}
	}
	return b.MaxArrayLen
}

// countValue counts one value that starts inside stack against the
// enclosing array's bound and the document's bounds.
func countValue(stack []jsonFrame, container bool, containers, values *int, b JSONBounds) error {
	*values++
	if b.MaxValues > 0 && *values > b.MaxValues {
		return ErrJSONTooManyItems
	}
	if container {
		*containers++
		if b.MaxContainers > 0 && *containers > b.MaxContainers {
			return ErrJSONTooManyItems
		}
	}
	if n := len(stack); n > 0 && !stack[n-1].object {
		stack[n-1].count++
		if stack[n-1].limit > 0 && stack[n-1].count > stack[n-1].limit {
			return ErrJSONTooManyItems
		}
	}
	return nil
}

// markValueDone records that the value of the current object member was read,
// so the next token in that object is a member name again.
func markValueDone(stack []jsonFrame) {
	if n := len(stack); n > 0 && stack[n-1].object {
		stack[n-1].expectKey = true
	}
}

// checkSurrogates scans string literals for \uD800–\uDFFF escapes that do not
// form a high+low pair. encoding/json would replace them with U+FFFD; I-JSON
// forbids them.
func checkSurrogates(data []byte) error {
	inString := false
	for i := 0; i < len(data); i++ {
		c := data[i]
		if !inString {
			if c == '"' {
				inString = true
			}
			continue
		}
		switch c {
		case '"':
			inString = false
		case '\\':
			if i+1 >= len(data) {
				return ErrJSONSyntax
			}
			if data[i+1] != 'u' {
				i++ // skip the escaped character
				continue
			}
			cp, ok := hex4(data, i+2)
			if !ok {
				return ErrJSONSyntax
			}
			i += 5
			switch {
			case cp >= 0xD800 && cp <= 0xDBFF:
				// Must be followed by a low surrogate escape.
				if i+6 >= len(data) || data[i+1] != '\\' || data[i+2] != 'u' {
					return ErrJSONLoneSurrogate
				}
				lo, ok := hex4(data, i+3)
				if !ok || lo < 0xDC00 || lo > 0xDFFF {
					return ErrJSONLoneSurrogate
				}
				i += 6
			case cp >= 0xDC00 && cp <= 0xDFFF:
				return ErrJSONLoneSurrogate
			}
		}
	}
	return nil
}

func hex4(data []byte, at int) (rune, bool) {
	if at+4 > len(data) {
		return 0, false
	}
	var r rune
	for _, c := range data[at : at+4] {
		r <<= 4
		switch {
		case c >= '0' && c <= '9':
			r |= rune(c - '0')
		case c >= 'a' && c <= 'f':
			r |= rune(c-'a') + 10
		case c >= 'A' && c <= 'F':
			r |= rune(c-'A') + 10
		default:
			return 0, false
		}
	}
	return r, true
}

// ErrUnknownField: the document has a member its declared CTIS minor does
// not define (a newer 2.x minor's unknown members are ignored instead).
var ErrUnknownField = errors.New("unknown field")

// ErrSchemaType: a member has the wrong JSON type for its CTIS field (a
// string where a number is expected, an unparsable timestamp).
var ErrSchemaType = errors.New("member has the wrong type")

// ErrCTISVersion: the document declares no CTIS version, a malformed one, or
// another major. This receiver reads CTIS 2.x only; a 1.x document is refused
// and its producer must be upgraded (there is no conversion between majors).
var ErrCTISVersion = errors.New("unsupported CTIS version: this platform accepts CTIS 2.x only, upgrade the sensor, connector or CI integration")

// ErrInvalidReport: the decoded document breaks a CTIS 2.0 invariant
// (ctis.Report.Validate): a metadata.id that is not a UUIDv7, a UUID-shaped
// document reference, a non-canonical asset value, a finding whose asset_ref
// names no asset of the document, a URL member that is not http(s), ...
var ErrInvalidReport = errors.New("invalid CTIS 2.0 report")

// DecodeStrictReport runs the I-JSON pre-pass with bounds b, then decodes the
// flat CTIS report with ctis.Decode (CTIS 2.x only: strict for this module's
// minor or older, version-gated must-ignore for a newer 2.x minor) and checks
// it with ctis.Report.Validate. Nothing is decoded before the bounds hold.
// The ctis error text is not returned to the caller (it can quote input); it
// is wrapped so the cause stays available to logs.
func DecodeStrictReport(data []byte, maxDepth int, b JSONBounds) (*ctis.Report, error) {
	report, err := decodeCTIS(data, maxDepth, b)
	if err != nil {
		return nil, err
	}
	if err := report.Validate(); err != nil {
		return nil, withCause(ErrInvalidReport, err)
	}
	return report, nil
}

// causeError is a refusal whose text is the fixed sentinel's: the validator's
// message can quote the document, so it is kept only as the cause (errors.As,
// server logs) and never becomes what a caller or a person reads.
type causeError struct {
	sentinel error
	cause    error
}

func (e *causeError) Error() string   { return e.sentinel.Error() }
func (e *causeError) Unwrap() []error { return []error{e.sentinel, e.cause} }

// withCause returns sentinel carrying cause without exposing its text.
func withCause(sentinel, cause error) error { return &causeError{sentinel: sentinel, cause: cause} }

// DecodeReportShape is DecodeStrictReport without the semantic Validate pass:
// the bounded pre-pass and ctis.Decode only. For reading a document this
// platform stored earlier (a quarantine preview), never for accepting one.
func DecodeReportShape(data []byte, maxDepth int, b JSONBounds) (*ctis.Report, error) {
	return decodeCTIS(data, maxDepth, b)
}

func decodeCTIS(data []byte, maxDepth int, b JSONBounds) (*ctis.Report, error) {
	if err := CheckIJSONBounded(data, maxDepth, b); err != nil {
		return nil, err
	}
	if err := checkCTISVersion(data); err != nil {
		return nil, err
	}
	report, _, err := ctis.Decode(bytes.NewReader(data))
	if err != nil {
		if strings.Contains(err.Error(), "json: unknown field ") {
			return nil, ErrUnknownField
		}
		return nil, ErrSchemaType
	}
	return &report, nil
}

// checkCTISVersion refuses a document whose "version" is missing, malformed
// or of another major before the full decode, so the caller can tell a
// producer to upgrade apart from a malformed document.
func checkCTISVersion(data []byte) error {
	var head struct {
		Version *string `json:"version"`
	}
	if err := json.Unmarshal(data, &head); err != nil {
		return ErrSchemaType
	}
	if head.Version == nil || !ctis.IsCompatibleVersion(strings.TrimSpace(*head.Version)) {
		return ErrCTISVersion
	}
	return nil
}

// V2ReportError is a whole-report refusal: the problem type and, for
// schema-invalid, the per-item errors (pointers and fixed details only).
type V2ReportError struct {
	Problem protov2.ProblemType
	Errors  []protov2.ItemError
	// RetryAfter, when set, is the server's advised delay for a retryable
	// refusal (queue-full: from the tenant's drain rate).
	RetryAfter time.Duration
	// Cause is the decoder's or validator's own message, for the server log
	// only: it can quote the document and is never sent to the sensor.
	Cause error
}

func (e *V2ReportError) Error() string {
	return fmt.Sprintf("report refused: %s (%d item errors)", e.Problem, len(e.Errors))
}

// ParseV2Report decodes and structurally validates one v2 segment. A nil
// error means the segment is a complete, independently valid CTIS 2.0
// document; a *V2ReportError names the problem otherwise. metadata.id is the
// producer's idempotency key and is never compared with, or replaced by, the
// receiver's report id (the URL path binds the segment to the report).
func ParseV2Report(data []byte, limits protov2.Limits) (*ctis.Report, error) {
	report, err := decodeCTIS(data, limits.MaxJSONDepth, ReportBounds(limits))
	switch {
	case errors.Is(err, ErrJSONTooManyItems):
		return nil, &V2ReportError{Problem: protov2.ProblemReportTooLarge, Errors: []protov2.ItemError{
			item("", protov2.CodeTooMany, protov2.DetailTooMany)}}
	case errors.Is(err, ErrCTISVersion):
		return nil, &V2ReportError{Problem: protov2.ProblemVersionMismatch, Errors: []protov2.ItemError{
			item("/version", protov2.CodeInvalidValue, protov2.DetailCTISVersion)}}
	case errors.Is(err, ErrUnknownField):
		return nil, &V2ReportError{Problem: protov2.ProblemSchemaInvalid, Errors: []protov2.ItemError{{
			Pointer: "", Code: protov2.CodeUnknownField, Detail: protov2.DetailUnknownField}}}
	case errors.Is(err, ErrSchemaType):
		return nil, &V2ReportError{Problem: protov2.ProblemSchemaInvalid, Errors: []protov2.ItemError{{
			Pointer: "", Code: protov2.CodeInvalidValue, Detail: protov2.DetailInvalidValue}}}
	case err != nil:
		return nil, &V2ReportError{Problem: protov2.ProblemInvalidJSON}
	}
	if verr := ValidateReportV2(report, limits); verr != nil {
		return nil, verr
	}
	return report, nil
}

// ValidateReportV2 is the whole-report check of a v2 segment (RFC-026 §3.3
// step 8): the per-segment item limits, the platform's own requirements (a
// named tool) with a pointer per problem, then the CTIS 2.0 invariants
// (ctis.Report.Validate: UUIDv7 metadata.id, document references that are
// never UUID-shaped, canonical asset values, resolvable asset_ref, http(s)
// URL members, enums).
//
//nolint:cyclop // a flat list of independent checks
func ValidateReportV2(r *ctis.Report, limits protov2.Limits) *V2ReportError {
	if !protov2.CTISVersionMajorMatches(r.Version) {
		if strings.TrimSpace(r.Version) == "" {
			return schemaInvalid([]protov2.ItemError{item("/version", protov2.CodeRequired, protov2.DetailRequired)})
		}
		return &V2ReportError{Problem: protov2.ProblemVersionMismatch, Errors: []protov2.ItemError{
			item("/version", protov2.CodeInvalidValue, protov2.DetailCTISVersion)}}
	}
	if len(r.Findings) > limits.MaxFindingsPerSegment {
		return &V2ReportError{Problem: protov2.ProblemReportTooLarge, Errors: []protov2.ItemError{
			item("/findings", protov2.CodeTooMany, protov2.DetailTooMany)}}
	}
	if len(r.Assets) > limits.MaxAssetsPerSegment {
		return &V2ReportError{Problem: protov2.ProblemReportTooLarge, Errors: []protov2.ItemError{
			item("/assets", protov2.CodeTooMany, protov2.DetailTooMany)}}
	}

	var errs []protov2.ItemError
	add := func(e protov2.ItemError) {
		if len(errs) < protov2.MaxItemErrors {
			errs = append(errs, e)
		}
	}
	if r.Tool == nil || strings.TrimSpace(r.Tool.Name) == "" {
		add(item("/tool/name", protov2.CodeRequired, protov2.DetailRequired))
	}
	if r.Metadata.ID == "" {
		add(item("/metadata/id", protov2.CodeRequired, protov2.DetailRequired))
	} else if !ctis.IsReportID(r.Metadata.ID) {
		add(item("/metadata/id", protov2.CodeInvalidValue, protov2.DetailMetadataID))
	}
	if r.Metadata.GeneratedAt.IsZero() {
		add(item("/metadata/generated_at", protov2.CodeRequired, protov2.DetailRequired))
	}

	assetIDs := make(map[string]struct{}, len(r.Assets))
	for i := range r.Assets {
		a := &r.Assets[i]
		p := "/assets/" + strconv.Itoa(i)
		if strings.TrimSpace(a.Value) == "" {
			add(item(p+"/value", protov2.CodeRequired, protov2.DetailRequired))
		}
		if !a.Type.IsValid() {
			add(item(p+"/type", protov2.CodeInvalidValue, protov2.DetailInvalidValue))
		}
		if a.Criticality != "" && !a.Criticality.IsValid() {
			add(item(p+"/criticality", protov2.CodeInvalidValue, protov2.DetailInvalidValue))
		}
		switch {
		case a.ID == "":
			add(item(p+"/id", protov2.CodeRequired, protov2.DetailRequired))
		case ctis.IsUUIDShaped(a.ID) || !ctis.IsDocumentRef(a.ID):
			// A document reference is never a receiver's database key.
			add(item(p+"/id", protov2.CodeInvalidValue, protov2.DetailInvalidValue))
		default:
			if _, dup := assetIDs[a.ID]; dup {
				// Two assets with one id make every reference to it ambiguous.
				add(item(p+"/id", protov2.CodeInvalidValue, protov2.DetailInvalidValue))
			}
			assetIDs[a.ID] = struct{}{}
		}
	}
	for i := range r.Findings {
		f := &r.Findings[i]
		p := "/findings/" + strconv.Itoa(i)
		if strings.TrimSpace(f.Title) == "" {
			add(item(p+"/title", protov2.CodeRequired, protov2.DetailRequired))
		}
		if !f.Type.IsValid() {
			add(item(p+"/type", protov2.CodeInvalidValue, protov2.DetailInvalidValue))
		}
		if !f.Severity.IsValid() {
			add(item(p+"/severity", protov2.CodeInvalidValue, protov2.DetailInvalidValue))
		}
		if f.Status != "" && !f.Status.IsValid() {
			add(item(p+"/status", protov2.CodeInvalidValue, protov2.DetailInvalidValue))
		}
		if _, ok := assetIDs[f.AssetRef]; !ok {
			add(item(p+"/asset_ref", protov2.CodeInvalidValue, protov2.DetailInvalidValue))
		}
	}
	if len(errs) > 0 {
		return schemaInvalid(errs)
	}
	// Everything else CTIS 2.0 requires. Its message can quote the document,
	// so the sensor gets the fixed detail and the server log the cause.
	if err := r.Validate(); err != nil {
		v := schemaInvalid([]protov2.ItemError{item("", protov2.CodeInvalidValue, protov2.DetailInvalidValue)})
		v.Cause = err
		return v
	}
	return nil
}

func schemaInvalid(errs []protov2.ItemError) *V2ReportError {
	return &V2ReportError{Problem: protov2.ProblemSchemaInvalid, Errors: errs}
}

func item(pointer, code, detail string) protov2.ItemError {
	return protov2.ItemError{Pointer: pointer, Code: code, Detail: detail}
}
