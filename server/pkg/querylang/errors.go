package querylang

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/openctemio/openctem/api/pkg/apierror"
)

// MaxErrors bounds the details of one Error.
const MaxErrors = 20

// ErrorDetail is one problem in a query, with the byte range of the text
// it is about (for the editor) and its 1-based line and column.
type ErrorDetail struct {
	Message string `json:"message"`
	Span
	Line   int `json:"line"`
	Column int `json:"column"`
}

// Error is an invalid query. It maps to HTTP 400 INVALID_QUERY.
// Messages never echo free text from the query.
type Error struct {
	Details []ErrorDetail
}

func (e *Error) Error() string {
	parts := make([]string, 0, len(e.Details))
	for _, d := range e.Details {
		parts = append(parts, fmt.Sprintf("%d:%d: %s", d.Line, d.Column, d.Message))
	}
	return "invalid query: " + strings.Join(parts, "; ")
}

// APIError converts the error to the user-plane envelope.
func (e *Error) APIError() *apierror.Error {
	msg := "1 query error"
	if n := len(e.Details); n != 1 {
		msg = fmt.Sprintf("%d query errors", n)
	}
	return apierror.New(http.StatusBadRequest, apierror.CodeInvalidQuery, msg).WithDetails(e.Details)
}

// AsError returns the *Error inside err, if any.
func AsError(err error) (*Error, bool) {
	var qe *Error
	if errors.As(err, &qe) {
		return qe, true
	}
	return nil, false
}

// newError is a one-detail error without line information; locate fills
// it in once the source is known.
func newError(s Span, msg string) *Error {
	return &Error{Details: []ErrorDetail{{Message: msg, Span: s}}}
}

// errList accumulates details up to MaxErrors.
type errList struct{ d []ErrorDetail }

func (l *errList) add(s Span, msg string) {
	if len(l.d) < MaxErrors {
		l.d = append(l.d, ErrorDetail{Message: msg, Span: s})
	}
}

func (l *errList) err(src string) error {
	if len(l.d) == 0 {
		return nil
	}
	e := &Error{Details: l.d}
	locate(e, src)
	return e
}

// locate fills in line and column from the byte offsets.
func locate(e *Error, src string) {
	for i := range e.Details {
		d := &e.Details[i]
		d.Start = max(0, min(d.Start, len(src)))
		d.End = max(d.Start, min(d.End, len(src)))
		d.Line, d.Column = 1, 1
		for j := 0; j < d.Start; j++ {
			if src[j] == '\n' {
				d.Line++
				d.Column = 1
			} else if src[j]&0xC0 != 0x80 { // count runes, not bytes
				d.Column++
			}
		}
	}
}
