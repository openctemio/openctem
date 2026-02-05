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
		// Check X-Forwarded-Proto header for reverse proxy scenarios
		if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
			scheme = proto
		} else {
			scheme = schemeHTTP
		}
	}

	host := r.Host
	if fwdHost := r.Header.Get("X-Forwarded-Host"); fwdHost != "" {
		host = fwdHost
	}

	return fmt.Sprintf("%s://%s%s", scheme, host, r.URL.Path)
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

// parseQueryArray parses a comma-separated query parameter into a string slice.
// Returns nil if the input is empty.
func parseQueryArray(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
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
