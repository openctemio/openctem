package handler

// The filter param of the MCP list tools: the short search syntax of the
// console's search box (docs/architecture/query-language.md, "Short form"),
// e.g. `severity>=high kev=true -status:accepted` or
// `domain=*.example.com port:80,443`. It is parsed and planned by the same
// query language, as the key's owner, with the same field permissions as the
// console; the resulting document runs through the list's own registry and
// compiler, so the tenant, the data scope and every limit apply exactly as
// in the UI. Problems are reported by code and position, never by value.

import (
	"context"
	"fmt"
	"strings"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/filterspec"
	"github.com/openctemio/openctem/api/pkg/querylang"
)

// mcpFilterHint is the filter param's description in the tool schemas.
const mcpFilterHint = "the search box syntax, ANDed with the other params: field=value, field:a,b (any of), " +
	"-field:value (not), field>=value, field<7d (age), field=pre* (pattern), quoted phrases, OR and (...)"

// withMCPFilter ANDs the filter text to a list spec. An empty text returns
// the spec unchanged.
func withMCPFilter(ctx context.Context, tenantID string, ent *querylang.Entity, list *filterspec.Registry,
	spec *filterspec.Spec, text string) (*filterspec.Spec, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return spec, nil
	}
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant", shared.ErrValidation)
	}
	var uid shared.ID
	if u := actingUser(ctx); u != "" {
		if uid, err = shared.IDFromString(u); err != nil {
			return nil, fmt.Errorf("%w: invalid acting user", shared.ErrValidation)
		}
	}
	pr := querylang.Principal{TenantID: tid, UserID: uid, Admin: false,
		Has: func(p string) bool { return middleware.HasPermission(ctx, p) }}
	q, _, err := querylang.ParseFilter(ent, text)
	if err != nil {
		return nil, mcpQueryError(err)
	}
	plan, err := querylang.Build(q, text, pr, querylang.BuildOptions{})
	if err != nil {
		return nil, mcpQueryError(err)
	}
	extra, err := filterspec.ParseDocumentValue(plan.FilterDocument(), list, filterspec.Options{Unknown: filterspec.UnknownStrict})
	if err != nil {
		return nil, toolInputError{"invalid filter: the list cannot run it; keep a text search at the top level, not inside OR or a negation"}
	}
	out := *spec
	if extra.Q != "" {
		if out.Q != "" {
			return nil, toolInputError{"invalid filter: give the free text in the filter or in the search param, not both"}
		}
		out.Q = extra.Q
	}
	switch {
	case extra.Root == nil:
	case out.Root == nil:
		out.Root = extra.Root
	default:
		out.Root = &filterspec.Node{All: []*filterspec.Node{out.Root, extra.Root}}
	}
	return &out, nil
}

// mcpQueryError is a query language refusal as a tool input error: each
// problem's code, position and message (written by the parser, never the
// input's values).
func mcpQueryError(err error) error {
	qe, ok := querylang.AsError(err)
	if !ok || len(qe.Details) == 0 {
		return err
	}
	parts := make([]string, 0, len(qe.Details))
	for _, d := range qe.Details {
		parts = append(parts, fmt.Sprintf("%s at %d:%d: %s", d.Code, d.Line, d.Column, d.Message))
	}
	return toolInputError{"invalid filter: " + strings.Join(parts, "; ")}
}
