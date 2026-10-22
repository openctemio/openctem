// Package pagination provides pagination utilities.
package pagination

import "strings"

// Pagination holds pagination parameters.
type Pagination struct {
	Page    int
	PerPage int
}

// SortOrder represents the sort direction.
type SortOrder string

const (
	SortAsc  SortOrder = "ASC"
	SortDesc SortOrder = "DESC"
)

// Sort represents a sorting specification.
type Sort struct {
	Field string
	Order SortOrder
}

// SortOption represents a parsed sort option with validation.
type SortOption struct {
	sorts         []Sort
	allowedFields map[string]string // maps request field to DB column
}

// NewSortOption creates a new SortOption with allowed fields.
// allowedFields maps user-facing field names to database column names.
// Example: {"created_at": "created_at", "name": "name", "updated_at": "updated_at"}
func NewSortOption(allowedFields map[string]string) *SortOption {
	return &SortOption{
		sorts:         make([]Sort, 0),
		allowedFields: allowedFields,
	}
}

// Parse parses a sort string and validates fields.
// Format: "-created_at,name" means ORDER BY created_at DESC, name ASC
// Prefix "-" means descending order.
func (s *SortOption) Parse(sortStr string) *SortOption {
	if sortStr == "" {
		return s
	}

	parts := strings.Split(sortStr, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		order := SortAsc
		field := part

		if strings.HasPrefix(part, "-") {
			order = SortDesc
			field = part[1:]
		} else if strings.HasPrefix(part, "+") {
			field = part[1:]
		}

		// Validate field is allowed
		if dbColumn, ok := s.allowedFields[field]; ok {
			s.sorts = append(s.sorts, Sort{Field: dbColumn, Order: order})
		}
	}

	return s
}

// Sorts returns the parsed sort specifications.
func (s *SortOption) Sorts() []Sort {
	return s.sorts
}

// IsEmpty returns true if no sorts are specified.
func (s *SortOption) IsEmpty() bool {
	return len(s.sorts) == 0
}

// SQL returns the ORDER BY clause without the "ORDER BY" prefix, ending in an
// id tie-breaker so pages never repeat or skip rows that share a sort key.
// Returns empty string if no sorts.
// Example: "created_at DESC, name ASC, id ASC"
//
// The tie-breaker is the bare column "id". A query that joins another table
// with an id column, or aliases its main table, must use SQLWithTieBreaker
// with the qualified expression.
func (s *SortOption) SQL() string {
	return s.SQLWithTieBreaker("id")
}

// SQLWithTieBreaker is SQL with an explicit, qualified expression for the id
// tie-breaker (for example "a.id"). idExpr must be a trusted constant, never
// client input. The tie-breaker follows the direction of the last sort and is
// omitted when the client already sorted by that expression.
func (s *SortOption) SQLWithTieBreaker(idExpr string) string {
	if len(s.sorts) == 0 {
		return ""
	}

	parts := make([]string, 0, len(s.sorts)+1)
	hasID := false
	for _, sort := range s.sorts {
		if sort.Field == "id" || sort.Field == idExpr {
			hasID = true
		}
		parts = append(parts, sort.Field+" "+string(sort.Order))
	}
	if !hasID && idExpr != "" {
		parts = append(parts, idExpr+" "+string(s.sorts[len(s.sorts)-1].Order))
	}
	return strings.Join(parts, ", ")
}

// SQLWithDefault returns the ORDER BY clause, using defaultSort if no sorts
// specified. defaultSort must already end in a unique column.
func (s *SortOption) SQLWithDefault(defaultSort string) string {
	if sql := s.SQL(); sql != "" {
		return sql
	}
	return defaultSort
}

// SQLWithDefaultAndTieBreaker is SQLWithDefault with a qualified tie-breaker
// expression for joined or aliased queries.
func (s *SortOption) SQLWithDefaultAndTieBreaker(defaultSort, idExpr string) string {
	if sql := s.SQLWithTieBreaker(idExpr); sql != "" {
		return sql
	}
	return defaultSort
}

// New creates a new Pagination with defaults applied.
func New(page, perPage int) Pagination {
	if page < 1 {
		page = 1
	}
	if page > 100000 {
		page = 100000 // Prevent integer overflow in Offset() calculation
	}
	if perPage < 1 {
		perPage = 20
	}
	if perPage > 100 {
		perPage = 100
	}
	return Pagination{
		Page:    page,
		PerPage: perPage,
	}
}

// Offset returns the offset for database queries.
func (p Pagination) Offset() int {
	return (p.Page - 1) * p.PerPage
}

// Limit returns the limit for database queries.
func (p Pagination) Limit() int {
	return p.PerPage
}

// Result represents a paginated result set.
type Result[T any] struct {
	Data       []T   `json:"data"`
	Total      int64 `json:"total"`
	Page       int   `json:"page"`
	PerPage    int   `json:"per_page"`
	TotalPages int   `json:"total_pages"`
}

// NewResult creates a new paginated Result.
func NewResult[T any](data []T, total int64, p Pagination) Result[T] {
	if data == nil {
		data = make([]T, 0)
	}

	totalPages := int(total) / p.PerPage
	if int(total)%p.PerPage > 0 {
		totalPages++
	}

	return Result[T]{
		Data:       data,
		Total:      total,
		Page:       p.Page,
		PerPage:    p.PerPage,
		TotalPages: totalPages,
	}
}
