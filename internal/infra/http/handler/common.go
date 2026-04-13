package handler

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// URL scheme constants
const (
	schemeHTTP  = "http"
	schemeHTTPS = "https"
)

// PaginationLinks contains HATEOAS-style pagination links.
type PaginationLinks struct {
	Self  string `json:"self"`
	First string `json:"first,omitempty"`
	Prev  string `json:"prev,omitempty"`
	Next  string `json:"next,omitempty"`
	Last  string `json:"last,omitempty"`
}

// ListResponse represents a paginated list response.
// This is a generic type that can be reused across all handlers.
type ListResponse[T any] struct {
	Data       []T              `json:"data"`
	Total      int64            `json:"total"`
	Page       int              `json:"page"`
	PerPage    int              `json:"per_page"`
	TotalPages int              `json:"total_pages"`
	Links      *PaginationLinks `json:"links,omitempty"`
}

// NewPaginationLinks creates pagination links based on the current request.
// It preserves all existing query parameters while updating page number.
func NewPaginationLinks(r *http.Request, page, perPage, totalPages int) *PaginationLinks {
	if totalPages == 0 {
		return nil
	}

	baseURL := buildBaseURL(r)
	query := r.URL.Query()

	links := &PaginationLinks{
		Self:  buildPageURL(baseURL, query, page, perPage),
		First: buildPageURL(baseURL, query, 1, perPage),
	}

	if page > 1 {
		links.Prev = buildPageURL(baseURL, query, page-1, perPage)
	}

	if page < totalPages {
		links.Next = buildPageURL(baseURL, query, page+1, perPage)
	}

	if totalPages > 1 {
		links.Last = buildPageURL(baseURL, query, totalPages, perPage)
	}

	return links
}

// buildBaseURL constructs the base URL from the request.
func buildBaseURL(r *http.Request) string {
	scheme := schemeHTTPS
	if r.TLS == nil {
		// Check X-Forwarded-Proto header for reverse proxy scenarios.
		// Security: Only accept "http" or "https" to prevent injection (CWE-644).
		if proto := r.Header.Get("X-Forwarded-Proto"); proto == "http" || proto == "https" {
			scheme = proto
		} else {
			scheme = schemeHTTP
		}
	}

	host := r.Host
	if fwdHost := r.Header.Get("X-Forwarded-Host"); fwdHost != "" {
		// Security: Validate host format to prevent header injection (CWE-644).
		if isValidHostHeader(fwdHost) {
			host = fwdHost
		}
	}

	return fmt.Sprintf("%s://%s%s", scheme, host, r.URL.Path)
}

// isValidHostHeader checks if a host header value contains only safe characters.
func isValidHostHeader(host string) bool {
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	for _, r := range host {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '-' || r == ':') {
			return false
		}
	}
	return true
}

// buildPageURL builds a URL with the specified page number.
func buildPageURL(baseURL string, query url.Values, page, perPage int) string {
	// Clone the query params to avoid modifying the original
	params := make(url.Values)
	for k, v := range query {
		params[k] = v
	}

	params.Set("page", strconv.Itoa(page))
	params.Set("per_page", strconv.Itoa(perPage))

	return baseURL + "?" + params.Encode()
}

// maxQueryArrayItems caps the number of comma-separated values accepted from
// a single query parameter. Prevents DoS via `?tags=a,b,c,…10000_items` which
// would otherwise allocate unbounded slices and SQL arrays. 100 is well above
// any legitimate UI use case (filters typically select 1–20 values).
const maxQueryArrayItems = 100

// maxQueryArrayItemLen caps the length of any single value in the array.
// Defends against pathological cases like `?tags=<1MB-string>` which would
// blow up downstream LIKE patterns and SQL parameter sizes.
const maxQueryArrayItemLen = 200

// parseQueryArray parses a comma-separated query parameter into a string slice.
// Returns nil if the input is empty. Each element is trimmed of whitespace and
// truncated to maxQueryArrayItemLen. The whole list is capped at
// maxQueryArrayItems to prevent denial-of-service via huge filter strings.
func parseQueryArray(s string) []string {
	if s == "" {
		return nil
	}
	// Hard ceiling on raw input size before splitting — defense-in-depth.
	if len(s) > maxQueryArrayItems*(maxQueryArrayItemLen+1) {
		s = s[:maxQueryArrayItems*(maxQueryArrayItemLen+1)]
	}
	parts := strings.Split(s, ",")
	if len(parts) > maxQueryArrayItems {
		parts = parts[:maxQueryArrayItems]
	}
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed == "" {
			continue
		}
		if len(trimmed) > maxQueryArrayItemLen {
			trimmed = trimmed[:maxQueryArrayItemLen]
		}
		result = append(result, trimmed)
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

// parseQueryInt parses a query parameter as an integer.
// Returns defaultVal if the input is empty or invalid.
func parseQueryInt(s string, defaultVal int) int {
	if s == "" {
		return defaultVal
	}
	val, err := strconv.Atoi(s)
	if err != nil {
		return defaultVal
	}
	return val
}

// parseQueryBool parses a query parameter as a boolean pointer.
// Returns nil if the input is empty, otherwise returns a pointer to the boolean value.
// Accepts "true", "1" as true; anything else as false.
func parseQueryBool(s string) *bool {
	if s == "" {
		return nil
	}
	//nolint:goconst // "true" and "1" used intentionally as literals for clarity
	val := s == "true" || s == "1"
	return &val
}

// parseQueryIntPtr parses a query parameter as an integer pointer.
// Returns nil if the input is empty or invalid.
func parseQueryIntPtr(s string) *int {
	if s == "" {
		return nil
	}
	val, err := strconv.Atoi(s)
	if err != nil {
		return nil
	}
	return &val
}

// parseQueryBoolPtr is an alias for parseQueryBool for consistency.
func parseQueryBoolPtr(s string) *bool {
	return parseQueryBool(s)
}

func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
