package licensepolicy

import (
	"errors"
	"strings"
)

// Op is the kind of an expression node.
type Op int

// Node kinds.
const (
	OpLicense Op = iota
	OpAnd
	OpOr
)

// Node is a parsed SPDX license expression.
type Node struct {
	Op        Op
	License   string // OpLicense: the id, e.g. "GPL-2.0-only" or "LicenseRef-acme"
	Exception string // OpLicense: the WITH exception, if any
	Children  []*Node
}

// Expression bounds: hostile input never costs more than this.
const (
	MaxExpressionLen   = 512
	maxExpressionDepth = 16
	maxExpressionTerms = 64
)

// ErrExpression is the error of an expression that does not parse.
var ErrExpression = errors.New("invalid license expression")

// Parse parses an SPDX license expression ("MIT", "MIT OR Apache-2.0",
// "(GPL-2.0-only WITH Classpath-exception-2.0) AND BSD-3-Clause"). AND binds
// tighter than OR; operators are case-insensitive.
func Parse(s string) (*Node, error) {
	if len(s) > MaxExpressionLen {
		return nil, ErrExpression
	}
	toks := tokenize(s)
	if len(toks) == 0 || len(toks) > 4*maxExpressionTerms {
		return nil, ErrExpression
	}
	p := &parser{toks: toks}
	n, err := p.or(0)
	if err != nil {
		return nil, err
	}
	if p.pos != len(p.toks) || p.terms > maxExpressionTerms {
		return nil, ErrExpression
	}
	return n, nil
}

func tokenize(s string) []string {
	var out []string
	var cur strings.Builder
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	for _, r := range s {
		switch {
		case r == '(' || r == ')':
			flush()
			out = append(out, string(r))
		case r == ' ' || r == '\t' || r == '\n' || r == '\r':
			flush()
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	return out
}

type parser struct {
	toks  []string
	pos   int
	terms int
}

func (p *parser) peekOp(op string) bool {
	return p.pos < len(p.toks) && strings.EqualFold(p.toks[p.pos], op)
}

func (p *parser) or(depth int) (*Node, error) {
	return p.binary(depth, "OR", OpOr, p.and)
}

func (p *parser) and(depth int) (*Node, error) {
	return p.binary(depth, "AND", OpAnd, p.with)
}

func (p *parser) binary(depth int, word string, op Op, next func(int) (*Node, error)) (*Node, error) {
	if depth > maxExpressionDepth {
		return nil, ErrExpression
	}
	first, err := next(depth)
	if err != nil {
		return nil, err
	}
	children := []*Node{first}
	for p.peekOp(word) {
		p.pos++
		n, err := next(depth)
		if err != nil {
			return nil, err
		}
		children = append(children, n)
	}
	if len(children) == 1 {
		return first, nil
	}
	return &Node{Op: op, Children: children}, nil
}

func (p *parser) with(depth int) (*Node, error) {
	n, err := p.atom(depth)
	if err != nil {
		return nil, err
	}
	if p.peekOp("WITH") {
		if n.Op != OpLicense || n.Exception != "" {
			return nil, ErrExpression
		}
		p.pos++
		if p.pos >= len(p.toks) || !isLicenseID(p.toks[p.pos]) {
			return nil, ErrExpression
		}
		n.Exception = p.toks[p.pos]
		p.pos++
	}
	return n, nil
}

func (p *parser) atom(depth int) (*Node, error) {
	if p.pos >= len(p.toks) {
		return nil, ErrExpression
	}
	t := p.toks[p.pos]
	if t == "(" {
		p.pos++
		n, err := p.or(depth + 1)
		if err != nil {
			return nil, err
		}
		if p.pos >= len(p.toks) || p.toks[p.pos] != ")" {
			return nil, ErrExpression
		}
		p.pos++
		return n, nil
	}
	if !isLicenseID(t) {
		return nil, ErrExpression
	}
	p.pos++
	p.terms++
	return &Node{Op: OpLicense, License: t}, nil
}
