package scanrun

// Sort order of the runs list (RFC-048 §3.5 naming: `sort=-started_at`).
// See docs/rfcs/RFC-048-list-query-contract.md.

import (
	"context"
	"fmt"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// RunListSort is one validated sort key of the runs list. The zero value is
// newest first (created_at descending), the list's historical order.
type RunListSort struct {
	field string
	desc  bool
}

// runSortColumns maps each sortable field to constant ORDER BY expressions.
// Nothing from the request reaches the SQL text; a field outside this map is
// refused. Nullable timestamps sort their NULLs last in both directions.
var runSortColumns = map[string]struct{ asc, desc string }{
	"created_at":     {asc: "created_at ASC", desc: "created_at DESC"},
	"started_at":     {asc: "started_at ASC NULLS LAST", desc: "started_at DESC NULLS LAST"},
	"completed_at":   {asc: "completed_at ASC NULLS LAST", desc: "completed_at DESC NULLS LAST"},
	"total_findings": {asc: "total_findings ASC", desc: "total_findings DESC"},
}

// RunListSortFields returns the sortable fields of the runs list.
func RunListSortFields() []string {
	return []string{"created_at", "started_at", "completed_at", "total_findings"}
}

// ParseRunListSort parses one sort key, `field` or `-field` (descending). An
// empty value is the default order; an unknown field or more than one key is
// a validation error (RFC-048: never silently dropped).
func ParseRunListSort(raw string) (RunListSort, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return RunListSort{}, nil
	}
	if strings.Contains(raw, ",") {
		return RunListSort{}, fmt.Errorf("%w: sort takes one field", shared.ErrValidation)
	}
	desc := strings.HasPrefix(raw, "-")
	field := strings.TrimPrefix(raw, "-")
	if _, ok := runSortColumns[field]; !ok {
		return RunListSort{}, fmt.Errorf("%w: sort: unknown field (allowed: %s)",
			shared.ErrValidation, strings.Join(RunListSortFields(), ", "))
	}
	return RunListSort{field: field, desc: desc}, nil
}

// Field is the sort field ("created_at" for the zero value).
func (s RunListSort) Field() string {
	if s.field == "" {
		return "created_at"
	}
	return s.field
}

// Desc reports a descending sort (true for the zero value).
func (s RunListSort) Desc() bool { return s.field == "" || s.desc }

// OrderBy returns the ORDER BY expression, with id as the last tiebreaker so
// a page boundary is stable between requests.
func (s RunListSort) OrderBy() string {
	col := runSortColumns[s.Field()]
	expr := col.asc
	if s.Desc() {
		expr = col.desc
	}
	return expr + ", id DESC"
}

// RunScanNamer names the scans that runs belong to. Every read is scoped to
// tenantID: another tenant's scan is never named.
type RunScanNamer interface {
	ScanNames(ctx context.Context, tenantID shared.ID, scanIDs []shared.ID) (map[shared.ID]string, error)
}
