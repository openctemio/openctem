package v2

import (
	"encoding/json"
	"net/http"
	"strconv"
)

// Problem types (RFC 9457) of the v2 results resource, RFC-026 §3.8. The type
// URI is ProblemTypeBase + name; the title and status are fixed per type.
// Problem detail strings are fixed templates too: they never quote sensor
// bytes (RFC 9457 §5, RFC-026 §3.7).
type ProblemType string

// ProblemTypeBase prefixes the problem type names of the results resource
// (RFC-026).
const ProblemTypeBase = "https://openctem.io/problems/ingest/"

// ProblemTypeBaseSensor prefixes the problem type names RFC-029 added for the
// rest of the sensor surface (commands, key renewal, queries). The RFC-026
// types keep their URIs and are reused on those routes where they fit.
const ProblemTypeBaseSensor = "https://openctem.io/problems/sensor/"

const (
	ProblemDigestRequired  ProblemType = "digest-required"
	ProblemDigestMismatch  ProblemType = "digest-mismatch"
	ProblemInvalidID       ProblemType = "invalid-id"
	ProblemInvalidEncoding ProblemType = "invalid-encoding"
	ProblemInvalidRequest  ProblemType = "invalid-request"

	ProblemUnauthenticated ProblemType = "unauthenticated"
	ProblemScopeDenied     ProblemType = "scope-denied"

	ProblemCommandNotFound ProblemType = "command-not-found"
	ProblemReportNotFound  ProblemType = "report-not-found"

	ProblemReportConflict        ProblemType = "report-conflict"
	ProblemReportCommitted       ProblemType = "report-committed"
	ProblemReportExpired         ProblemType = "report-expired"
	ProblemSegmentHeaderMismatch ProblemType = "segment-header-mismatch"
	ProblemSegmentSetMismatch    ProblemType = "segment-set-mismatch"
	ProblemBindingMismatch       ProblemType = "binding-mismatch"

	ProblemLengthRequired ProblemType = "length-required"

	ProblemContentTooLarge      ProblemType = "content-too-large"
	ProblemDecompressedTooLarge ProblemType = "decompressed-too-large"
	ProblemReportTooLarge       ProblemType = "report-too-large"

	ProblemUnsupportedMediaType ProblemType = "unsupported-media-type"
	ProblemUnsupportedEncoding  ProblemType = "unsupported-encoding"

	ProblemSchemaInvalid     ProblemType = "schema-invalid"
	ProblemVersionMismatch   ProblemType = "version-mismatch"
	ProblemInvalidJSON       ProblemType = "invalid-json"
	ProblemToolNotPermitted  ProblemType = "tool-not-permitted"
	ProblemRateLimited       ProblemType = "rate-limited"
	ProblemQueueFull         ProblemType = "queue-full"
	ProblemTooManyOpenReport ProblemType = "too-many-open-reports"

	ProblemInternal    ProblemType = "internal"
	ProblemUnavailable ProblemType = "unavailable"

	// RFC-029 (ProblemTypeBaseSensor).
	ProblemInvalidTransition  ProblemType = "invalid-transition"
	ProblemCommandClaimed     ProblemType = "command-claimed"
	ProblemTransitionConflict ProblemType = "transition-conflict"
	ProblemRenewalRefused     ProblemType = "renewal-refused"
	ProblemTooManyItems       ProblemType = "too-many-items"

	// RFC-033 (ProblemTypeBaseSensor).
	ProblemManifestInvalid           ProblemType = "manifest-invalid"
	ProblemManifestSchemaUnsupported ProblemType = "manifest-schema-unsupported"
	ProblemManifestNotFound          ProblemType = "manifest-not-found"

	// Config report (ProblemTypeBaseSensor).
	ProblemConfigReportInvalid ProblemType = "config-report-invalid"
)

type problemDef struct {
	status    int
	title     string
	detail    string
	retryable bool
	// base is the type URI prefix; "" means ProblemTypeBase.
	base string
}

// problemDefs is the closed table of problem types. A type that is not here
// cannot be written (NewProblem falls back to ProblemInternal).
var problemDefs = map[ProblemType]problemDef{
	ProblemDigestRequired:  {http.StatusBadRequest, "Content digest required", "Send a Content-Digest header with a sha-256 or sha-512 digest of the content as sent.", false, ""},
	ProblemDigestMismatch:  {http.StatusBadRequest, "Content digest mismatch", "The Content-Digest does not match the received content.", false, ""},
	ProblemInvalidID:       {http.StatusBadRequest, "Invalid identifier", "A path identifier is not a lower-case UUID or a segment number in range.", false, ""},
	ProblemInvalidEncoding: {http.StatusBadRequest, "Invalid content encoding", "The content could not be decoded with the declared Content-Encoding.", false, ""},
	ProblemInvalidRequest:  {http.StatusBadRequest, "Invalid request", "The request body does not match the documented shape.", false, ""},

	ProblemUnauthenticated: {http.StatusUnauthorized, "Unauthenticated", "Invalid credentials.", false, ""},
	ProblemScopeDenied:     {http.StatusForbidden, "Scope denied", "This sensor may not send results on this resource.", false, ""},

	ProblemCommandNotFound: {http.StatusNotFound, "Command not found", "No open command with this id is assigned to this sensor.", false, ""},
	ProblemReportNotFound:  {http.StatusNotFound, "Report not found", "No report with this id exists for this sensor.", false, ""},

	ProblemReportConflict:        {http.StatusConflict, "Report conflict", "A different content was already received under this report id or segment.", false, ""},
	ProblemReportCommitted:       {http.StatusConflict, "Report committed", "The report is committed; it accepts no more segments.", false, ""},
	ProblemReportExpired:         {http.StatusConflict, "Report expired", "The report expired before it was committed; send it again under a new report id.", false, ""},
	ProblemSegmentHeaderMismatch: {http.StatusConflict, "Segment header mismatch", "Every segment of a report must carry the same tool and metadata.", false, ""},
	ProblemSegmentSetMismatch:    {http.StatusConflict, "Segment set mismatch", "The committed segment count or digests do not match the received segments.", false, ""},
	ProblemBindingMismatch:       {http.StatusConflict, "Binding mismatch", "All segments and the commit of a report must use the same form and command.", false, ""},

	ProblemLengthRequired: {http.StatusLengthRequired, "Length required", "Send a Content-Length; chunked transfer coding is not accepted.", false, ""},

	ProblemContentTooLarge:      {http.StatusRequestEntityTooLarge, "Content too large", "The content exceeds the request limit; split the report into more segments.", false, ""},
	ProblemDecompressedTooLarge: {http.StatusRequestEntityTooLarge, "Decompressed content too large", "The decoded content exceeds the size or ratio limit; split the report into more segments.", false, ""},
	ProblemReportTooLarge:       {http.StatusRequestEntityTooLarge, "Report too large", "The segment or report exceeds an item or segment limit; split the report into more segments.", false, ""},

	ProblemUnsupportedMediaType: {http.StatusUnsupportedMediaType, "Unsupported media type", "The only accepted Content-Type is " + MediaTypeCTIS + ".", false, ""},
	ProblemUnsupportedEncoding:  {http.StatusUnsupportedMediaType, "Unsupported content encoding", "The accepted Content-Encoding values are gzip and zstd, one coding at most.", false, ""},

	ProblemSchemaInvalid:     {http.StatusUnprocessableEntity, "Schema invalid", "The report does not satisfy the CTIS schema or the v2 rules; see errors.", false, ""},
	ProblemVersionMismatch:   {http.StatusUnprocessableEntity, "Version mismatch", "The body's CTIS major version does not match the media type.", false, ""},
	ProblemInvalidJSON:       {http.StatusUnprocessableEntity, "Invalid JSON", "The content is not I-JSON: duplicate member names, invalid UTF-8, trailing data, excessive depth or a syntax error.", false, ""},
	ProblemToolNotPermitted:  {http.StatusUnprocessableEntity, "Tool not permitted", "The report's tool is not declared by this sensor, or is not the tool of the bound command.", false, ""},
	ProblemRateLimited:       {http.StatusTooManyRequests, "Rate limited", "Too many requests; retry after the advised delay.", true, ""},
	ProblemQueueFull:         {http.StatusTooManyRequests, "Queue full", "The tenant's ingest queue is full; retry after the advised delay.", true, ""},
	ProblemTooManyOpenReport: {http.StatusTooManyRequests, "Too many open reports", "This sensor has too many uncommitted reports; commit or delete one first.", true, ""},

	ProblemInternal:    {http.StatusInternalServerError, "Internal error", "The server failed to handle the request.", true, ""},
	ProblemUnavailable: {http.StatusServiceUnavailable, "Unavailable", "The service is temporarily unavailable; retry after the advised delay.", true, ""},

	ProblemInvalidTransition:  {http.StatusConflict, "Invalid transition", "The command's current state does not allow this transition; see state.", false, ProblemTypeBaseSensor},
	ProblemCommandClaimed:     {http.StatusConflict, "Command claimed", "Another sensor claimed this command first.", false, ProblemTypeBaseSensor},
	ProblemTransitionConflict: {http.StatusConflict, "Transition conflict", "The command already reached this state with a different result or message.", false, ProblemTypeBaseSensor},
	ProblemRenewalRefused:     {http.StatusForbidden, "Renewal refused", "This sensor may not renew its key.", false, ProblemTypeBaseSensor},
	ProblemTooManyItems:       {http.StatusUnprocessableEntity, "Too many items", "The request lists more items than the limit; split it into several requests.", false, ProblemTypeBaseSensor},

	ProblemManifestInvalid:           {http.StatusUnprocessableEntity, "Manifest invalid", "The manifest is not a JSON object with a schema member of the documented shape.", false, ProblemTypeBaseSensor},
	ProblemManifestNotFound:          {http.StatusNotFound, "Manifest not found", "This sensor has no registered manifest; PUT it first.", false, ProblemTypeBaseSensor},
	ProblemManifestSchemaUnsupported: {http.StatusUnprocessableEntity, "Manifest schema unsupported", "The manifest's schema version is not one this server reads; send schema 1.", false, ProblemTypeBaseSensor},

	ProblemConfigReportInvalid: {http.StatusUnprocessableEntity, "Config report invalid", "The config report is not a JSON object with schema 1 and a checks array.", false, ProblemTypeBaseSensor},
}

// ProblemTypes returns every defined problem type, for tests and docs.
func ProblemTypes() []ProblemType {
	out := make([]ProblemType, 0, len(problemDefs))
	for t := range problemDefs {
		out = append(out, t)
	}
	return out
}

// URI is the problem's type URI.
func (t ProblemType) URI() string {
	if def, ok := problemDefs[t]; ok && def.base != "" {
		return def.base + string(t)
	}
	return ProblemTypeBase + string(t)
}

// Status is the HTTP status of the problem type.
func (t ProblemType) Status() int { return problemDefs[t].status }

// Known reports whether t is in the closed table.
func (t ProblemType) Known() bool {
	_, ok := problemDefs[t]
	return ok
}

// ItemError is one per-item error, on a 422 problem or on the status resource.
// Pointer is an RFC 6901 JSON pointer built from indices and known field names
// only; Detail is a fixed template. Neither ever quotes sensor bytes.
type ItemError struct {
	Segment *int   `json:"segment,omitempty"`
	Pointer string `json:"pointer"`
	Code    string `json:"code"`
	Detail  string `json:"detail"`
}

// Problem is an RFC 9457 problem details document with the RFC-026
// extension members.
type Problem struct {
	Type   string      `json:"type"`
	Title  string      `json:"title"`
	Status int         `json:"status"`
	Detail string      `json:"detail"`
	Errors []ItemError `json:"errors,omitempty"`
	Limit  *int64      `json:"limit,omitempty"`
	// State is the command's current state on an invalid-transition problem
	// (RFC-029 §4.4), so a sensor can drop a canceled or expired command.
	State     string `json:"state,omitempty"`
	Retryable bool   `json:"retryable"`

	ptype  ProblemType
	accept string
}

// NewProblem builds the problem of type t with its fixed title, status and
// detail. An unknown t becomes ProblemInternal, so a typo can never put an
// undefined type on the wire.
func NewProblem(t ProblemType) *Problem {
	def, ok := problemDefs[t]
	if !ok {
		t = ProblemInternal
		def = problemDefs[t]
	}
	return &Problem{
		Type:      t.URI(),
		Title:     def.title,
		Status:    def.status,
		Detail:    def.detail,
		Retryable: def.retryable,
		ptype:     t,
	}
}

// ProblemType returns the problem's type.
func (p *Problem) ProblemType() ProblemType { return p.ptype }

// WithLimit sets the "limit" extension member (the limit a 413 exceeded).
func (p *Problem) WithLimit(n int64) *Problem {
	p.Limit = &n
	return p
}

// WithState sets the "state" extension member of an invalid-transition.
func (p *Problem) WithState(state string) *Problem {
	p.State = state
	return p
}

// WithAccept overrides the Accept header a 415 carries (the control-plane
// routes accept application/json, not CTIS).
func (p *Problem) WithAccept(mediaType string) *Problem {
	p.accept = mediaType
	return p
}

// WithErrors sets the "errors" extension member, capped at MaxItemErrors.
func (p *Problem) WithErrors(errs []ItemError) *Problem {
	if len(errs) > MaxItemErrors {
		errs = errs[:MaxItemErrors]
	}
	p.Errors = errs
	return p
}

// ProblemRecorder is implemented by a response writer that wants to know
// which problem type was written (the metrics wrapper of the v2 routes).
type ProblemRecorder interface {
	RecordProblem(ProblemType)
}

// Write sends the problem with the headers its type requires: the protocol
// header always, Accept / Accept-Encoding on a 415, Retry-After on a 429/503.
func (p *Problem) Write(w http.ResponseWriter) {
	if rec, ok := w.(ProblemRecorder); ok {
		rec.RecordProblem(p.ptype)
	}
	h := w.Header()
	h.Set("Content-Type", MediaTypeProblem)
	h.Set(HeaderProtocol, strconv.Itoa(ProtocolVersion))
	switch p.ptype {
	case ProblemUnsupportedMediaType:
		accept := MediaTypeCTIS
		if p.accept != "" {
			accept = p.accept
		}
		h.Set("Accept", accept)
	case ProblemUnsupportedEncoding:
		h.Set("Accept-Encoding", AcceptEncodingValue)
	case ProblemRateLimited, ProblemQueueFull, ProblemTooManyOpenReport, ProblemUnavailable:
		if h.Get(HeaderRetryAfter) == "" {
			h.Set(HeaderRetryAfter, DefaultRetryAfterSeconds)
		}
	}
	w.WriteHeader(p.Status)
	_ = json.NewEncoder(w).Encode(p)
}

// DefaultRetryAfterSeconds is the Retry-After of a 429/503 that sets none.
const DefaultRetryAfterSeconds = "30"
