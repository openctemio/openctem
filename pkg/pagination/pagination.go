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

// SQL returns the ORDER BY clause without the "ORDER BY" prefix.
// Returns empty string if no sorts.
// Example: "created_at DESC, name ASC"
func (s *SortOption) SQL() string {
	if len(s.sorts) == 0 {
		return ""
	}

	parts := make([]string, 0, len(s.sorts))
	for _, sort := range s.sorts {
		parts = append(parts, sort.Field+" "+string(sort.Order))
	}
	return strings.Join(parts, ", ")
}

// SQLWithDefault returns the ORDER BY clause, using defaultSort if no sorts specified.
func (s *SortOption) SQLWithDefault(defaultSort string) string {
	if sql := s.SQL(); sql != "" {
		return sql
	}
	return defaultSort
}

// New creates a new Pagination with defaults applied.
func New(page, perPage int) Pagination {
	if page < 1 {
		page = 1
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
