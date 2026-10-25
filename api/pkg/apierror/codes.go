package apierror

import (
	"net/http"
	"sort"
	"strings"
	"unicode/utf8"
)

// Spec describes a registered error code: the HTTP status it is sent with
// and the English message an API client sees when the call site gives none
// (or gives one that is not fit to show). The web shows its own words for
// the code (errors.<CODE> in web/src/lib/i18n/dictionaries/{en,vi}); a test
// there fails when a registered code has no entry.
type Spec struct {
	Status  int
	Message string
}

// registry lists the codes the API sends. A code that is not here still
// works (the message is the fallback), but the web can only translate a
// registered one. Messages follow the error wording rule: say what failed
// and what to do, no ids, no internal names.
var registry = map[Code]Spec{
	CodeBadRequest:            {http.StatusBadRequest, "The request is not valid. Check the values and try again."},
	CodeUnauthorized:          {http.StatusUnauthorized, "Sign in to continue."},
	CodeForbidden:             {http.StatusForbidden, "You do not have permission to do this."},
	CodeModuleNotEnabled:      {http.StatusForbidden, "This module is not enabled for your organization."},
	CodeNotFound:              {http.StatusNotFound, "Not found. It may have been deleted, or you may not have access to it."},
	CodeConflict:              {http.StatusConflict, "This conflicts with the current state. Reload and try again."},
	CodeUnprocessableEntity:   {http.StatusUnprocessableEntity, "Some values are not valid."},
	CodeInternalError:         {http.StatusInternalServerError, "Something failed on the server. Try again; if it keeps failing, contact support with the reference."},
	CodeServiceUnavailable:    {http.StatusServiceUnavailable, "The service is not available right now. Try again in a minute."},
	CodeQueryTimeout:          {http.StatusServiceUnavailable, "This took too long to answer. Narrow the filter or search and try again."},
	CodeValidationFailed:      {http.StatusUnprocessableEntity, "Some values are not valid."},
	CodeRateLimitExceeded:     {http.StatusTooManyRequests, "Too many requests. Wait a moment and try again."},
	CodeUpstreamError:         {http.StatusBadGateway, "A service this depends on did not answer correctly. Try again later."},
	CodeMFAEnrollmentRequired: {http.StatusForbidden, "Your organization requires two-factor authentication. Sign in again to set it up."},
	CodeApprovalRequired:      {http.StatusForbidden, "This change needs an approver. Submit a request instead."},
	CodeInvalidFilter:         {http.StatusBadRequest, "The filter is not valid. Check the fields and values."},
	CodeInvalidInclude:        {http.StatusBadRequest, "The include parameter is not valid."},
	CodeInvalidQuery:          {http.StatusBadRequest, "The query is not valid."},
	CodeSelectionChanged:      {http.StatusConflict, "The selection changed since you confirmed it. Review the new count and confirm again."},
	CodeBulkTooLarge:          {http.StatusBadRequest, "Too many items for one bulk change. Narrow the selection."},
	CodeBulkNotAllowed:        {http.StatusBadRequest, "This change cannot be made in bulk. Change each item on its own."},
	CodeOperationRunning:      {http.StatusConflict, "You already have an operation running. Wait for it to finish."},
	CodeIdempotencyKeyReused:  {http.StatusUnprocessableEntity, "This idempotency key was already used for a different request."},

	// Integrations (test connection and calls to a connected service).
	CodeIntegrationNoCredentials:         {http.StatusUnprocessableEntity, "This connection has no credentials. Add them to use it."},
	CodeIntegrationCredentialsUnreadable: {http.StatusUnprocessableEntity, "The saved credentials of this connection cannot be read. Enter them again."},
	CodeIntegrationAuthFailed:            {http.StatusFailedDependency, "The service refused the credentials. Check them, or create a new token, and test again."},
	CodeIntegrationForbidden:             {http.StatusFailedDependency, "The credentials work but lack a permission this needs. Grant it on the service and test again."},
	CodeIntegrationNotFound:              {http.StatusFailedDependency, "The service did not find what this connection points at. Check the address and project."},
	CodeIntegrationUnreachable:           {http.StatusBadGateway, "The service could not be reached. Check the address and that it is online."},
	CodeIntegrationURLBlocked:            {http.StatusUnprocessableEntity, "This address is not allowed by the outbound network policy."},
	CodeIntegrationRateLimited:           {http.StatusTooManyRequests, "The service is limiting requests. Wait a minute and test again."},
	CodeIntegrationUpstreamError:         {http.StatusBadGateway, "The service answered with an error. Try again later."},
	CodeIntegrationTestFailed:            {http.StatusFailedDependency, "The connection test failed. Check the settings and test again."},

	// Codes call sites already send (ad hoc before the registry).
	CodeContentSigningUnavailable: {http.StatusServiceUnavailable, "Content signing is not available right now."},
	CodeContentRefused:            {http.StatusUnprocessableEntity, "This content was refused."},
	CodeContentBundleRefused:      {http.StatusUnprocessableEntity, "This content bundle was refused."},
	CodeTicketEgressRefused:       {http.StatusForbidden, "The organization's data policy does not allow sending this to the ticketing service."},
	CodeTicketBelowThreshold:      {http.StatusConflict, "This finding is below the ticketing threshold."},
	CodeRotationNotStalled:        {http.StatusConflict, "The rotation is not stalled."},
	CodeReleaseFeedTooLarge:       {http.StatusRequestEntityTooLarge, "The file is larger than the release feed limit."},
}

// Integration and ad hoc codes, registered above.
const (
	CodeIntegrationNoCredentials         Code = "INTEGRATION_NO_CREDENTIALS"
	CodeIntegrationCredentialsUnreadable Code = "INTEGRATION_CREDENTIALS_UNREADABLE"
	CodeIntegrationAuthFailed            Code = "INTEGRATION_AUTH_FAILED"
	CodeIntegrationForbidden             Code = "INTEGRATION_FORBIDDEN"
	CodeIntegrationNotFound              Code = "INTEGRATION_NOT_FOUND"
	CodeIntegrationUnreachable           Code = "INTEGRATION_UNREACHABLE"
	CodeIntegrationURLBlocked            Code = "INTEGRATION_URL_BLOCKED"
	CodeIntegrationRateLimited           Code = "INTEGRATION_RATE_LIMITED"
	CodeIntegrationUpstreamError         Code = "INTEGRATION_UPSTREAM_ERROR"
	CodeIntegrationTestFailed            Code = "INTEGRATION_TEST_FAILED"

	CodeContentSigningUnavailable Code = "CONTENT_SIGNING_UNAVAILABLE"
	CodeContentRefused            Code = "CONTENT_REFUSED"
	CodeContentBundleRefused      Code = "CONTENT_BUNDLE_REFUSED"
	CodeTicketEgressRefused       Code = "TICKET_EGRESS_REFUSED"
	CodeTicketBelowThreshold      Code = "TICKET_BELOW_THRESHOLD"
	CodeRotationNotStalled        Code = "ROTATION_NOT_STALLED"
	CodeReleaseFeedTooLarge       Code = "RELEASE_FEED_TOO_LARGE"
)

// statusMessages is the fallback when a code is not registered.
var statusMessages = map[int]string{
	http.StatusBadRequest:          registry[CodeBadRequest].Message,
	http.StatusUnauthorized:        registry[CodeUnauthorized].Message,
	http.StatusForbidden:           registry[CodeForbidden].Message,
	http.StatusNotFound:            registry[CodeNotFound].Message,
	http.StatusConflict:            registry[CodeConflict].Message,
	http.StatusFailedDependency:    "A connected service refused the request.",
	http.StatusUnprocessableEntity: registry[CodeValidationFailed].Message,
	http.StatusTooManyRequests:     registry[CodeRateLimitExceeded].Message,
	http.StatusBadGateway:          registry[CodeUpstreamError].Message,
	http.StatusServiceUnavailable:  registry[CodeServiceUnavailable].Message,
}

// Lookup returns the spec of a registered code.
func Lookup(code Code) (Spec, bool) {
	s, ok := registry[code]
	return s, ok
}

// Codes returns every registered code, sorted.
func Codes() []Code {
	out := make([]Code, 0, len(registry))
	for c := range registry {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// DefaultMessage is the message for a code (registered), else for the
// status, else the generic server message.
func DefaultMessage(code Code, status int) string {
	if s, ok := registry[code]; ok {
		return s.Message
	}
	if m, ok := statusMessages[status]; ok {
		return m
	}
	if status >= 400 && status < 500 {
		return registry[CodeBadRequest].Message
	}
	return registry[CodeInternalError].Message
}

// FromCode builds the error for a registered code with its status and
// default message. Prefer it to a free-text constructor: the client picks
// its own words from the code, and nothing the call site formats can reach
// the response. An unregistered code is sent as a 500 so the gap is seen.
func FromCode(code Code) *Error {
	s, ok := registry[code]
	if !ok {
		return &Error{Status: http.StatusInternalServerError, Code: CodeInternalError, Message: registry[CodeInternalError].Message}
	}
	return &Error{Status: s.Status, Code: code, Message: s.Message}
}

// Params are values the client may put in its message for a code, such as a
// name or a count (details.params). They are shown to a person, so a value
// that is an id or technical text is dropped, never sent.
type Params map[string]string

// maxParamRunes caps one parameter value.
const maxParamRunes = 200

// WithParams adds safe values for the client's message to details.params.
// Details that are not a map (or nil) are kept under details.data.
func (e *Error) WithParams(p Params) *Error {
	safe := map[string]string{}
	for k, v := range p {
		v = strings.TrimSpace(v)
		if v == "" || ContainsUUID(v) || IsTechnical(v) || utf8.RuneCountInString(v) > maxParamRunes {
			continue
		}
		safe[k] = v
	}
	if len(safe) == 0 {
		return e
	}
	switch d := e.Details.(type) {
	case nil:
		e.Details = map[string]any{"params": safe}
	case map[string]any:
		d["params"] = safe
	default:
		e.Details = map[string]any{"params": safe, "data": d}
	}
	return e
}
