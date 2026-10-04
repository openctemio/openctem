package filterspec

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/openctemio/openctem/api/pkg/apierror"
)

// Spec is the decoded filter: the AST both encodings produce.
type Spec struct {
	// Root is the filter tree; nil means no filter.
	Root *Node
	// Q is the free-text search ("" = none).
	Q string
	// Sort is the requested order (empty = the registry default).
	Sort []SortKey
	// Page and PerPage are the requested page (0 = the caller's default).
	Page    int
	PerPage int

	// UnknownParams lists params that were ignored (warn mode only).
	UnknownParams []string
	// AliasesUsed lists deprecated param names the request used.
	AliasesUsed []AliasUse
}

// AliasUse records one deprecated param in a request.
type AliasUse struct {
	Old string
	New string
}

// Node is a filter tree node: exactly one of All, Any, Not or Leaf.
type Node struct {
	All  []*Node
	Any  []*Node
	Not  *Node
	Leaf *Leaf
}

// Leaf compares one field.
type Leaf struct {
	Field string
	Op    Op
	// Values are typed: string (enum, string, id), int64, float64, bool or
	// time.Time. Single-valued operators hold exactly one.
	Values []any
	// src is the param name or JSON path the leaf came from, for errors.
	src     string
	srcPath bool
}

// SortKey is one sort field.
type SortKey struct {
	Field string
	Desc  bool
}

// Leaves returns the leaves of the tree in order.
func (s *Spec) Leaves() []*Leaf {
	var out []*Leaf
	var walk func(n *Node)
	walk = func(n *Node) {
		if n == nil {
			return
		}
		switch {
		case n.Leaf != nil:
			out = append(out, n.Leaf)
		case n.Not != nil:
			walk(n.Not)
		default:
			for _, c := range n.All {
				walk(c)
			}
			for _, c := range n.Any {
				walk(c)
			}
		}
	}
	walk(s.Root)
	return out
}

// Without returns a copy of the spec whose top-level AND drops every leaf on
// the named field (for facet counts "with every other filter applied").
// Leaves nested under any/not are kept.
func (s *Spec) Without(field string) *Spec {
	cp := *s
	if s.Root == nil {
		return &cp
	}
	if s.Root.Leaf != nil {
		if s.Root.Leaf.Field == field {
			cp.Root = nil
		}
		return &cp
	}
	if s.Root.All == nil {
		return &cp
	}
	kept := make([]*Node, 0, len(s.Root.All))
	for _, c := range s.Root.All {
		if c.Leaf != nil && c.Leaf.Field == field {
			continue
		}
		kept = append(kept, c)
	}
	cp.Root = &Node{All: kept}
	return &cp
}

// Detail is one filter error.
type Detail struct {
	Param  string `json:"param,omitempty"`
	Path   string `json:"path,omitempty"`
	Reason string `json:"reason"`
	Value  string `json:"value,omitempty"`
}

// Error is an invalid filter. It maps to HTTP 400 INVALID_FILTER.
type Error struct {
	Details []Detail
}

func (e *Error) Error() string {
	parts := make([]string, 0, len(e.Details))
	for _, d := range e.Details {
		where := d.Param
		if where == "" {
			where = d.Path
		}
		parts = append(parts, where+": "+d.Reason)
	}
	return "invalid filter: " + strings.Join(parts, "; ")
}

// APIError converts the error to the user-plane envelope.
func (e *Error) APIError() *apierror.Error {
	msg := "1 filter error"
	if n := len(e.Details); n != 1 {
		msg = fmt.Sprintf("%d filter errors", n)
	}
	return apierror.New(http.StatusBadRequest, apierror.CodeInvalidFilter, msg).WithDetails(e.Details)
}

// AsError returns the *Error inside err, if any.
func AsError(err error) (*Error, bool) {
	var fe *Error
	if errors.As(err, &fe) {
		return fe, true
	}
	return nil, false
}

var errUnknownParam = errors.New("unknown parameter")

// errs accumulates details up to MaxErrorDetails.
type errs struct{ d []Detail }

func (e *errs) param(name, reason, value string, freeText bool) {
	e.add(Detail{Param: safeName(name), Reason: reason, Value: echo(value, freeText)})
}

func (e *errs) path(p, reason, value string, freeText bool) {
	e.add(Detail{Path: p, Reason: reason, Value: echo(value, freeText)})
}

func (e *errs) add(d Detail) {
	if len(e.d) < MaxErrorDetails {
		e.d = append(e.d, d)
	}
}

func (e *errs) err() error {
	if len(e.d) == 0 {
		return nil
	}
	return &Error{Details: e.d}
}

// echo returns the value to show in an error: never free text, at most 64
// characters, valid UTF-8 only.
func echo(v string, freeText bool) string {
	if freeText || !utf8.ValidString(v) {
		return ""
	}
	if len(v) > 64 {
		v = v[:64]
		for !utf8.ValidString(v) {
			v = v[:len(v)-1]
		}
	}
	return v
}

// SafeName returns name when it is a plausible param name ([a-z0-9_], 1-64
// characters) and "other" otherwise, so request-controlled names never reach
// error bodies, logs or metric labels unbounded or with odd bytes.
func SafeName(name string) string { return safeName(name) }

// otherName replaces a request-controlled name that is not a plausible
// param name.
const otherName = "other"

func safeName(name string) string {
	if name == "" || len(name) > 64 {
		return otherName
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
			return otherName
		}
	}
	return name
}
