package retestcheck

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"

	"gopkg.in/yaml.v3"
)

// HTTPAssertion is a declarative check: one request to the finding's target
// and the matchers that say the issue is still there. It holds no code and
// no target: the platform compiles it to a nuclei template whose request
// goes to {{BaseURL}} + Path.
type HTTPAssertion struct {
	Method            string            `json:"method"`
	Path              string            `json:"path"`
	Headers           map[string]string `json:"headers,omitempty"`
	Body              string            `json:"body,omitempty"`
	Matchers          []Matcher         `json:"matchers"`
	MatchersCondition string            `json:"matchers_condition,omitempty"`
}

// Matcher is one condition on the response.
type Matcher struct {
	Type      string   `json:"type"` // status, word, regex
	Part      string   `json:"part,omitempty"`
	Status    []int    `json:"status,omitempty"`
	Words     []string `json:"words,omitempty"`
	Regex     []string `json:"regex,omitempty"`
	Condition string   `json:"condition,omitempty"`
	Negative  bool     `json:"negative,omitempty"`
}

// Assertion limits.
const (
	maxPathLen      = 2048
	maxHeaders      = 20
	maxHeaderValue  = 1024
	maxBodyLen      = 16 * 1024
	maxMatchers     = 10
	maxValues       = 20
	maxValueLen     = 1024
	matcherStatus   = "status"
	matcherWord     = "word"
	matcherRegex    = "regex"
	conditionAnd    = "and"
	conditionOr     = "or"
	partBody        = "body"
	partHeader      = "header"
	methodPost      = "POST"
	headerNameChars = "!#$%&'*+-.^_`|~"
)

// assertionMethods are the methods an assertion may send: none changes
// state on a well-behaved server.
var assertionMethods = map[string]bool{"GET": true, "HEAD": true, methodPost: true, "OPTIONS": true} //nolint:gochecknoglobals // static table

// credentialHeaders carry credentials: a check never holds one (a
// credential reference is resolved on the sensor instead).
var credentialHeaders = map[string]bool{ //nolint:gochecknoglobals // static table
	"authorization": true, "proxy-authorization": true, "cookie": true, "x-api-key": true,
	"x-auth-token": true, "api-key": true, "x-access-token": true, "x-csrf-token": true,
}

// IsCredentialHeader reports whether a header name carries credentials.
func IsCredentialHeader(name string) bool {
	return credentialHeaders[strings.ToLower(strings.TrimSpace(name))]
}

// Issue is one validation problem, on a field.
type Issue struct {
	Field   string `json:"field"`
	Message string `json:"message"`
	Code    string `json:"code"`
}

// Validate checks the assertion and returns every problem found.
func (a *HTTPAssertion) Validate() []Issue {
	var out []Issue
	add := func(field, code, format string, args ...any) {
		out = append(out, Issue{Field: field, Code: code, Message: fmt.Sprintf(format, args...)})
	}
	if !assertionMethods[strings.ToUpper(a.Method)] {
		add("method", "METHOD", "the method must be GET, HEAD, POST or OPTIONS")
	}
	switch {
	case !strings.HasPrefix(a.Path, "/"):
		add("path", "PATH", "the path must start with / (it is relative to the finding's target)")
	case strings.HasPrefix(a.Path, "//"):
		add("path", "PATH", "the path must not start with // (that names another host)")
	case len(a.Path) > maxPathLen:
		add("path", "PATH", "the path is longer than %d characters", maxPathLen)
	case !printableNoSpace(a.Path):
		add("path", "PATH", "the path must not contain spaces or control characters")
	}
	if len(a.Headers) > maxHeaders {
		add("headers", "HEADERS", "at most %d headers", maxHeaders)
	}
	for k, v := range a.Headers {
		switch {
		case !validHeaderName(k):
			add("headers."+k, "HEADER_NAME", "%q is not a valid header name", k)
		case IsCredentialHeader(k):
			add("headers."+k, "CREDENTIAL", "a check cannot hold credentials (%s)", k)
		case strings.EqualFold(k, "host"):
			add("headers."+k, "HOST", "the Host header is the finding's target and cannot be set")
		case len(v) > maxHeaderValue || strings.ContainsAny(v, "\r\n\x00"):
			add("headers."+k, "HEADER_VALUE", "the value of %s is too long or has line breaks", k)
		}
	}
	if a.Body != "" && !strings.EqualFold(a.Method, methodPost) {
		add("body", "BODY", "only a POST request has a body")
	}
	if len(a.Body) > maxBodyLen {
		add("body", "BODY", "the body is longer than %d bytes", maxBodyLen)
	}
	if c := a.MatchersCondition; c != "" && c != conditionAnd && c != conditionOr {
		add("matchers_condition", "CONDITION", "matchers_condition must be and or or")
	}
	if len(a.Matchers) == 0 || len(a.Matchers) > maxMatchers {
		add("matchers", "MATCHERS", "between 1 and %d matchers", maxMatchers)
	}
	for i, m := range a.Matchers {
		out = append(out, m.validate(fmt.Sprintf("matchers[%d]", i))...)
	}
	for field, s := range a.strings() {
		if strings.Contains(s, "{{") || strings.Contains(s, "}}") {
			add(field, "TEMPLATE_EXPRESSION", "template expressions ({{ }}) are not allowed in a check")
		}
	}
	return out
}

func (m *Matcher) validate(field string) []Issue {
	var out []Issue
	add := func(code, format string, args ...any) {
		out = append(out, Issue{Field: field, Code: code, Message: fmt.Sprintf(format, args...)})
	}
	if c := m.Condition; c != "" && c != conditionAnd && c != conditionOr {
		add("CONDITION", "condition must be and or or")
	}
	switch m.Type {
	case matcherStatus:
		if len(m.Status) == 0 || len(m.Status) > maxValues {
			add("STATUS", "between 1 and %d status codes", maxValues)
		}
		for _, s := range m.Status {
			if s < 100 || s > 599 {
				add("STATUS", "%d is not an HTTP status code", s)
			}
		}
	case matcherWord, matcherRegex:
		if m.Part != partBody && m.Part != partHeader {
			add("PART", "part must be body or header")
		}
		vals := m.Words
		if m.Type == matcherRegex {
			vals = m.Regex
		}
		if len(vals) == 0 || len(vals) > maxValues {
			add("VALUES", "between 1 and %d values", maxValues)
		}
		for _, v := range vals {
			if v == "" || len(v) > maxValueLen {
				add("VALUES", "a value is empty or longer than %d characters", maxValueLen)
				continue
			}
			if m.Type == matcherRegex {
				if _, err := regexp.Compile(v); err != nil {
					add("REGEX", "invalid regular expression: %v", err)
				}
			}
		}
	default:
		add("TYPE", "type must be status, word or regex")
	}
	return out
}

// strings lists every free-text value with its field, for checks that apply
// to all of them.
func (a *HTTPAssertion) strings() map[string]string {
	out := map[string]string{"path": a.Path, "body": a.Body}
	for k, v := range a.Headers {
		out["headers."+k] = k + v
	}
	for i, m := range a.Matchers {
		for j, w := range m.Words {
			out[fmt.Sprintf("matchers[%d].words[%d]", i, j)] = w
		}
		for j, r := range m.Regex {
			out[fmt.Sprintf("matchers[%d].regex[%d]", i, j)] = r
		}
	}
	return out
}

func printableNoSpace(s string) bool {
	for _, r := range s {
		if r <= ' ' || r == 0x7f || !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

func validHeaderName(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for _, r := range s {
		if !(r < unicode.MaxASCII && (unicode.IsLetter(r) || unicode.IsDigit(r) || strings.ContainsRune(headerNameChars, r))) {
			return false
		}
	}
	return true
}

// nucleiDoc is the compiled template, marshaled with yaml (never string
// concatenation, so no value can add keys).
type nucleiDoc struct {
	ID   string         `yaml:"id"`
	Info nucleiInfo     `yaml:"info"`
	HTTP []nucleiReqDoc `yaml:"http"`
}

type nucleiInfo struct {
	Name     string `yaml:"name"`
	Author   string `yaml:"author"`
	Severity string `yaml:"severity"`
	Tags     string `yaml:"tags"`
}

type nucleiReqDoc struct {
	Method            string            `yaml:"method"`
	Path              []string          `yaml:"path"`
	Headers           map[string]string `yaml:"headers,omitempty"`
	Body              string            `yaml:"body,omitempty"`
	MatchersCondition string            `yaml:"matchers-condition,omitempty"`
	Matchers          []nucleiMatcher   `yaml:"matchers"`
}

type nucleiMatcher struct {
	Type      string   `yaml:"type"`
	Part      string   `yaml:"part,omitempty"`
	Status    []int    `yaml:"status,omitempty"`
	Words     []string `yaml:"words,omitempty"`
	Regex     []string `yaml:"regex,omitempty"`
	Condition string   `yaml:"condition,omitempty"`
	Negative  bool     `yaml:"negative,omitempty"`
}

// TemplateIDFor is the nuclei template id of a finding's compiled check.
func TemplateIDFor(findingID string) string {
	id := strings.ReplaceAll(findingID, "-", "")
	if len(id) > 12 {
		id = id[:12]
	}
	return "retest-check-" + id
}

// Compile turns a valid assertion into a nuclei template for findingID.
// Call Validate first; Compile refuses an invalid assertion.
func (a *HTTPAssertion) Compile(findingID string) ([]byte, error) {
	if issues := a.Validate(); len(issues) > 0 {
		return nil, fmt.Errorf("invalid assertion: %s", issues[0].Message)
	}
	req := nucleiReqDoc{
		Method:            strings.ToUpper(a.Method),
		Path:              []string{"{{BaseURL}}" + a.Path},
		Headers:           a.Headers,
		Body:              a.Body,
		MatchersCondition: a.MatchersCondition,
	}
	if len(a.Matchers) > 1 && req.MatchersCondition == "" {
		req.MatchersCondition = conditionAnd
	}
	for _, m := range a.Matchers {
		nm := nucleiMatcher{Type: m.Type, Status: m.Status, Condition: m.Condition, Negative: m.Negative}
		if m.Type != matcherStatus {
			nm.Part = m.Part
		}
		switch m.Type {
		case matcherWord:
			nm.Words = m.Words
		case matcherRegex:
			nm.Regex = m.Regex
		}
		req.Matchers = append(req.Matchers, nm)
	}
	doc := nucleiDoc{
		ID: TemplateIDFor(findingID),
		Info: nucleiInfo{Name: "Retest check for finding " + findingID, Author: "openctem",
			Severity: "info", Tags: "retest-check"},
		HTTP: []nucleiReqDoc{req},
	}
	return yaml.Marshal(doc)
}
