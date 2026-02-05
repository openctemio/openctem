package postgres

import "strings"

// Sort order constants
const (
	sortOrderASC       = "ASC"
	sortOrderDESC      = "DESC"
	sortOrderAscLower  = "asc"
	sortOrderDescLower = "desc"
)

// Sort field constants
const (
	sortFieldName      = "name"
	sortFieldPriority  = "priority"
	sortFieldCreatedAt = "created_at"
	sortFieldUpdatedAt = "updated_at"
)

// Order by clause constants
const orderByCreatedAtDesc = " ORDER BY created_at DESC"

// escapeLikePattern escapes special characters in LIKE/ILIKE patterns.
// SECURITY: Prevents wildcard injection in user search input.
// The % and _ characters have special meaning in SQL LIKE patterns:
// - % matches any sequence of characters
// - _ matches any single character
// Without escaping, users could inject these to bypass filters or cause DoS.
func escapeLikePattern(s string) string {
	// Escape backslash first (since it's the escape character)
	s = strings.ReplaceAll(s, `\`, `\\`)
	// Escape wildcards
	s = strings.ReplaceAll(s, `%`, `\%`)
	s = strings.ReplaceAll(s, `_`, `\_`)
	return s
}

// wrapLikePattern wraps a search term with % wildcards after escaping.
// Use this for substring search: wrapLikePattern("foo") returns "%foo%"
func wrapLikePattern(s string) string {
	return "%" + escapeLikePattern(s) + "%"
}
