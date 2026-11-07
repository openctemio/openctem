package query

// Search box parsing (docs/architecture/query-language.md, "Short form"):
// text, a filter document or list params in, the filter document, its
// canonical short and long text, chips and problems out. Nothing reads the
// database: parsing needs the caller's permissions, not their data scope,
// and the result is a filter, never rows.

import (
	"context"
	"errors"
	"fmt"
	"net/url"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/filterspec"
	"github.com/openctemio/openctem/api/pkg/querylang"
)

// listRegistries are the list endpoints a search box document is sent to
// (POST /findings/search): a document is checked against it too, so the
// box never hands the list a filter the list refuses.
var listRegistries = map[string]*filterspec.Registry{
	querylang.Findings.Name: vulnerability.FindingFields,
}

// CodeNotOnList is the problem code of a filter the entity's list cannot
// run (a text search inside an OR, for example).
const CodeNotOnList = "not_on_list"

// maxParseParamsBytes bounds the params input (a list URL's query string).
const maxParseParamsBytes = 8 << 10

// ParseInput is one of Text, Document or Params on an entity.
type ParseInput struct {
	Entity   string
	Text     string
	Document map[string]any
	// Params is a list URL's query string ("severity=critical&kev=true").
	Params string
}

// Chip is one top-level condition of a document.
type Chip struct {
	// Field is the canonical path ("severity", "asset.domain"); empty for
	// the text search and for the advanced chip.
	Field string `json:"field,omitempty"`
	// Op is the document operator (in, not_in, gte, ...).
	Op     string `json:"op,omitempty"`
	Values []any  `json:"values,omitempty"`
	// Text is the chip's canonical short text.
	Text string `json:"text"`
	// Kind is "condition", "text" or "advanced".
	Kind string `json:"kind"`
}

// ParseResult is a checked search box filter.
type ParseResult struct {
	Entity string `json:"entity"`
	// Form is how the text was written (short, long); empty for a document
	// or params input.
	Form  string `json:"form,omitempty"`
	Valid bool   `json:"valid"`
	// Text is the canonical short text; Query the same filter in the long
	// form ("findings where ...").
	Text  string `json:"text"`
	Query string `json:"query"`
	// Document is the version 1 FilterDocument, relative times kept.
	Document map[string]any `json:"document,omitempty"`
	// Chips are the top-level conditions, or one advanced chip when the
	// filter has groups chips cannot show (it is never flattened).
	Chips    []Chip `json:"chips"`
	Advanced bool   `json:"advanced"`
	// Params are the list's flat URL params of the filter when every chip
	// has one (old links and bookmarks keep this form).
	Params   map[string]string       `json:"params,omitempty"`
	Problems []querylang.ErrorDetail `json:"problems"`
}

// Parse checks a search box filter for the caller. A filter with problems
// is a result with Valid false (never an error); an error is an unknown
// entity (not found), a missing permission (forbidden) or a bad request.
func (s *Service) Parse(_ context.Context, c Caller, in ParseInput) (*ParseResult, error) {
	ent, ok := querylang.Lookup(in.Entity)
	if !ok {
		return nil, fmt.Errorf("%w: unknown entity", shared.ErrNotFound)
	}
	pr, err := parsePrincipal(c)
	if err != nil {
		return nil, err
	}
	if !pr.Admin && (pr.Has == nil || !pr.Has(ent.Permission)) {
		return nil, fmt.Errorf("%w: entity", shared.ErrForbidden)
	}
	inputs := 0
	for _, set := range []bool{in.Text != "", in.Document != nil, in.Params != ""} {
		if set {
			inputs++
		}
	}
	if inputs > 1 {
		return nil, fmt.Errorf("%w: give one of text, document or params", shared.ErrValidation)
	}
	res := &ParseResult{Entity: ent.Name, Chips: []Chip{}, Problems: []querylang.ErrorDetail{}}
	text := in.Text
	switch {
	case in.Document != nil || in.Params != "":
		doc, err := inputDocument(ent, in)
		if err != nil {
			return nil, err
		}
		q, err := querylang.FromDocument(ent, doc)
		if err != nil {
			return nil, fmt.Errorf("%w: the document is not a valid filter", shared.ErrValidation)
		}
		text = querylang.FormatShort(ent, q)
	default:
		res.Form = string(querylang.FormShort)
	}
	q, form, err := querylang.ParseFilter(ent, text)
	if form != "" && in.Text != "" {
		res.Form = string(form)
	}
	if err == nil {
		var plan *querylang.Plan
		plan, err = querylang.Build(q, text, pr, querylang.BuildOptions{Now: s.now})
		if err == nil {
			s.fill(res, ent, plan, text)
			return res, nil
		}
	}
	qe, ok := querylang.AsError(err)
	if !ok {
		return nil, err
	}
	res.Problems = qe.Details
	return res, nil
}

// parsePrincipal is the caller as a principal for checking a filter: the
// tenant, user, owner/admin flag and permissions. The data scope is not
// resolved (parsing reads no rows); the plan built from it is never run.
func parsePrincipal(c Caller) (querylang.Principal, error) {
	var pr querylang.Principal
	tenantID, err := shared.IDFromString(c.TenantID)
	if err != nil {
		return pr, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	var userID shared.ID
	if c.UserID != "" {
		if userID, err = shared.IDFromString(c.UserID); err != nil {
			return pr, fmt.Errorf("%w: invalid acting user", shared.ErrValidation)
		}
	}
	return querylang.Principal{TenantID: tenantID, UserID: userID, Admin: c.IsAdmin, Has: c.Has}, nil
}

func inputDocument(ent *querylang.Entity, in ParseInput) (map[string]any, error) {
	if in.Document != nil {
		return in.Document, nil
	}
	list, ok := listRegistries[ent.Name]
	if !ok {
		return nil, fmt.Errorf("%w: this entity has no list params", shared.ErrValidation)
	}
	if len(in.Params) > maxParseParamsBytes {
		return nil, fmt.Errorf("%w: params too long", shared.ErrValidation)
	}
	vals, err := url.ParseQuery(in.Params)
	if err != nil {
		return nil, fmt.Errorf("%w: params are not a query string", shared.ErrValidation)
	}
	doc, err := filterspec.ParamsDocument(vals, list, filterspec.Options{Unknown: filterspec.UnknownWarn,
		Extra: []string{"sort", "page", "per_page", "view", "group_by", "fq"}})
	if err != nil {
		var fe *filterspec.Error
		if errors.As(err, &fe) {
			return nil, fmt.Errorf("%w: the params are not a valid filter", shared.ErrValidation)
		}
		return nil, err
	}
	return doc, nil
}

// fill sets the document, texts, chips and flat params of a valid plan.
func (s *Service) fill(res *ParseResult, ent *querylang.Entity, plan *querylang.Plan, src string) {
	doc := plan.FilterDocument()
	if list, ok := listRegistries[ent.Name]; ok {
		if _, err := filterspec.ParseDocumentValue(doc, list, filterspec.Options{Unknown: filterspec.UnknownStrict}); err != nil {
			res.Problems = append(res.Problems, querylang.ErrorDetail{Code: CodeNotOnList, Line: 1, Column: 1,
				Message: "the list cannot run this filter: keep a text search at the top level, not inside OR or a negation",
				Span:    querylang.Span{Start: 0, End: len(src)}})
			return
		}
	}
	res.Valid = true
	res.Document = doc
	q, err := querylang.FromDocument(ent, doc)
	if err != nil {
		res.Valid = false
		return
	}
	res.Text = querylang.FormatShort(ent, q)
	res.Query = querylang.Format(q)
	res.Chips, res.Advanced = chipsOf(ent, doc, res.Text)
	if !res.Advanced {
		res.Params = flatParams(ent, doc)
	}
}

// chipsOf lists the top-level conditions of doc, or one advanced chip.
func chipsOf(ent *querylang.Entity, doc map[string]any, text string) ([]Chip, bool) {
	chips := []Chip{}
	var leaves []any
	if f, ok := doc["filter"].(map[string]any); ok {
		if all, isAll := f["all"].([]any); isAll {
			leaves = all
		} else {
			leaves = []any{f}
		}
	}
	for _, l := range leaves {
		m, ok := l.(map[string]any)
		if !ok || m["field"] == nil {
			return []Chip{{Kind: "advanced", Text: text}}, true
		}
		q, err := querylang.FromDocument(ent, map[string]any{"v": filterspec.DocumentVersion, "filter": m})
		if err != nil {
			return []Chip{{Kind: "advanced", Text: text}}, true
		}
		field, _ := m["field"].(string)
		op, _ := m["op"].(string)
		vals, isList := m["value"].([]any)
		if !isList {
			vals = []any{m["value"]}
		}
		chips = append(chips, Chip{Kind: "condition", Field: ent.PathOf(field), Op: op, Values: vals, Text: querylang.FormatShort(ent, q)})
	}
	if qv, ok := doc["q"].(string); ok && qv != "" {
		q, _ := querylang.FromDocument(ent, map[string]any{"v": filterspec.DocumentVersion, "q": qv})
		chips = append(chips, Chip{Kind: "text", Values: []any{qv}, Text: querylang.FormatShort(ent, q)})
	}
	return chips, false
}

// flatParams is doc as the list's flat params, or nil when a condition has
// no flat spelling.
func flatParams(ent *querylang.Entity, doc map[string]any) map[string]string {
	list, ok := listRegistries[ent.Name]
	if !ok {
		return nil
	}
	out := map[string]string{}
	if qv, ok := doc["q"].(string); ok && qv != "" {
		out["q"] = qv
	}
	var leaves []any
	if f, ok := doc["filter"].(map[string]any); ok {
		if all, isAll := f["all"].([]any); isAll {
			leaves = all
		} else {
			leaves = []any{f}
		}
	}
	for _, l := range leaves {
		m, _ := l.(map[string]any)
		field, _ := m["field"].(string)
		op, _ := m["op"].(string)
		vals, isList := m["value"].([]any)
		if !isList {
			vals = []any{m["value"]}
		}
		texts := make([]string, 0, len(vals))
		for _, v := range vals {
			texts = append(texts, fmt.Sprint(v))
		}
		name, value, ok := list.LeafParam(field, filterspec.Op(op), texts)
		if !ok {
			return nil
		}
		if _, dup := out[name]; dup {
			// Two leaves on one param name have no flat form.
			return nil
		}
		out[name] = value
	}
	return out
}
