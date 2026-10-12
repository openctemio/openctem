package scan

// Sort order of the scan list (RFC-048 §3.5 naming: `sort=-last_run_at`).
// See docs/rfcs/RFC-048-list-query-contract.md.

import (
	"fmt"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ListSort is one validated sort key of the scan list. The zero value sorts by
// name, ascending (the list's historical order).
type ListSort struct {
	field string
	desc  bool
}

// listSortColumns maps each sortable field to its constant ORDER BY
// expression. Nothing from the request ever reaches the SQL text: the
// expression is chosen from this map, and a field outside it is refused.
// Nullable timestamps sort their NULLs last in both directions, so "never
// run" scans do not lead a "most recently run" list.
var listSortColumns = map[string]struct {
	asc, desc string
}{
	"name":        {asc: "name ASC", desc: "name DESC"},
	"created_at":  {asc: "created_at ASC", desc: "created_at DESC"},
	"last_run_at": {asc: "last_run_at ASC NULLS LAST", desc: "last_run_at DESC NULLS LAST"},
	"next_run_at": {asc: "next_run_at ASC NULLS LAST", desc: "next_run_at DESC NULLS LAST"},
	"total_runs":  {asc: "total_runs ASC", desc: "total_runs DESC"},
}

// ListSortFields returns the sortable fields of the scan list.
func ListSortFields() []string {
	return []string{"name", "created_at", "last_run_at", "next_run_at", "total_runs"}
}

// ParseListSort parses one sort key, `field` or `-field` (descending). An
// empty value is the default order; an unknown field is a validation error
// (RFC-048: never silently dropped). Only one key is accepted.
func ParseListSort(raw string) (ListSort, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ListSort{}, nil
	}
	if strings.Contains(raw, ",") {
		return ListSort{}, fmt.Errorf("%w: sort takes one field", shared.ErrValidation)
	}
	desc := strings.HasPrefix(raw, "-")
	field := strings.TrimPrefix(raw, "-")
	if _, ok := listSortColumns[field]; !ok {
		return ListSort{}, fmt.Errorf("%w: sort: unknown field (allowed: %s)",
			shared.ErrValidation, strings.Join(ListSortFields(), ", "))
	}
	return ListSort{field: field, desc: desc}, nil
}

// Field is the sort field ("name" for the zero value).
func (s ListSort) Field() string {
	if s.field == "" {
		return "name"
	}
	return s.field
}

// Desc reports a descending sort.
func (s ListSort) Desc() bool { return s.desc }

// OrderBy returns the ORDER BY expression, with id as the last tiebreaker so
// a page boundary is stable between requests.
func (s ListSort) OrderBy() string {
	col := listSortColumns[s.Field()]
	expr := col.asc
	if s.desc {
		expr = col.desc
	}
	return expr + ", id ASC"
}
