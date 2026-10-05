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
	"unicode/utf8"

	"github.com/openctemio/ctis"

	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
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
	ErrJSONSyntax          = errors.New("syntax error")
)

// CheckIJSON is the pre-pass: valid UTF-8, no lone surrogate escape, no
// duplicate member name in any object, nesting at most maxDepth, numbers
// representable as float64, one top-level object and nothing after it.
//
//nolint:cyclop,gocognit // one tokenizer loop; splitting it hides the state machine
func CheckIJSON(data []byte, maxDepth int) error {
	if !utf8.Valid(data) {
		return ErrJSONInvalidUTF8
	}
	if err := checkSurrogates(data); err != nil {
		return err
	}

	var stack []jsonFrame

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
			continue
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
				stack = append(stack, jsonFrame{})
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

// ErrUnknownField: the document has a member CTIS v1 does not define.
var ErrUnknownField = errors.New("unknown field")

// ErrSchemaType: a member has the wrong JSON type for its CTIS field (a
// string where a number is expected, an unparsable timestamp).
var ErrSchemaType = errors.New("member has the wrong type")

// DecodeStrictReport runs the I-JSON pre-pass, then decodes the flat CTIS
// report (no {"report": …} wrapper on v2) rejecting unknown fields.
func DecodeStrictReport(data []byte, maxDepth int) (*ctis.Report, error) {
	if err := CheckIJSON(data, maxDepth); err != nil {
		return nil, err
	}
	var report ctis.Report
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&report); err != nil {
		if strings.HasPrefix(err.Error(), "json: unknown field ") {
			return nil, ErrUnknownField
		}
		return nil, fmt.Errorf("%w", ErrSchemaType)
	}
	return &report, nil
}

// V2ReportError is a whole-report refusal: the problem type and, for
// schema-invalid, the per-item errors (pointers and fixed details only).
type V2ReportError struct {
	Problem protov2.ProblemType
	Errors  []protov2.ItemError
}

func (e *V2ReportError) Error() string {
	return fmt.Sprintf("report refused: %s (%d item errors)", e.Problem, len(e.Errors))
}

// ParseV2Report decodes and structurally validates one v2 segment. A nil
// error means the segment is a complete, independently valid CTIS document
// for this report; a *V2ReportError names the problem otherwise.
func ParseV2Report(data []byte, reportID string, limits protov2.Limits) (*ctis.Report, error) {
	report, err := DecodeStrictReport(data, limits.MaxJSONDepth)
	switch {
	case errors.Is(err, ErrUnknownField):
		return nil, &V2ReportError{Problem: protov2.ProblemSchemaInvalid, Errors: []protov2.ItemError{{
			Pointer: "", Code: protov2.CodeUnknownField, Detail: protov2.DetailUnknownField}}}
	case errors.Is(err, ErrSchemaType):
		return nil, &V2ReportError{Problem: protov2.ProblemSchemaInvalid, Errors: []protov2.ItemError{{
			Pointer: "", Code: protov2.CodeInvalidValue, Detail: protov2.DetailInvalidValue}}}
	case err != nil:
		return nil, &V2ReportError{Problem: protov2.ProblemInvalidJSON}
	}
	if verr := ValidateReportV2(report, reportID, limits); verr != nil {
		return nil, verr
	}
	return report, nil
}

// ValidateReportV2 is the whole-report structural check of a v2 segment
// (RFC-026 §3.3 step 8): the body's CTIS major matches the media type, the
// tool is named, metadata.id is empty or the report id, the per-segment item
// limits, and the CTIS required fields and enums with a pointer per problem.
//
//nolint:cyclop // a flat list of independent checks
func ValidateReportV2(r *ctis.Report, reportID string, limits protov2.Limits) *V2ReportError {
	if !protov2.CTISVersionMajorMatches(r.Version) {
		if strings.TrimSpace(r.Version) == "" {
			return schemaInvalid([]protov2.ItemError{item("/version", protov2.CodeRequired, protov2.DetailRequired)})
		}
		return &V2ReportError{Problem: protov2.ProblemVersionMismatch}
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
	if r.Metadata.ID != "" && r.Metadata.ID != reportID {
		add(item("/metadata/id", protov2.CodeMismatch, protov2.DetailMetadataID))
	}
	if r.Metadata.Timestamp.IsZero() {
		add(item("/metadata/timestamp", protov2.CodeRequired, protov2.DetailRequired))
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
		if a.ID != "" {
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
	}
	if len(errs) > 0 {
		return schemaInvalid(errs)
	}
	return nil
}

func schemaInvalid(errs []protov2.ItemError) *V2ReportError {
	return &V2ReportError{Problem: protov2.ProblemSchemaInvalid, Errors: errs}
}

func item(pointer, code, detail string) protov2.ItemError {
	return protov2.ItemError{Pointer: pointer, Code: code, Detail: detail}
}
