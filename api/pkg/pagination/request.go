package pagination

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
)

// MaxPerPage is the largest page a list endpoint returns. A larger per_page
// is lowered to it, so a client cannot ask the database for an unbounded page.
const MaxPerPage = 100

// ErrInvalid is returned for a page or per_page that is not a positive whole
// number. Handlers answer 400.
var ErrInvalid = errors.New("invalid pagination")

// FromRequest reads the one list paging convention every endpoint uses:
// `page` (1-based) and `per_page`. A missing value takes the default (page 1,
// per_page defaultPerPage); a value that is not a positive whole number is
// ErrInvalid rather than silently becoming the default, so a client bug does
// not look like "the first page". per_page is capped at MaxPerPage and page
// at the bound New applies.
//
// Lists that stream (logs, events) page with an opaque `cursor` instead and
// never mix the two in one endpoint.
func FromRequest(q url.Values, defaultPerPage int) (Pagination, error) {
	page, err := positiveInt(q.Get("page"), 1, "page")
	if err != nil {
		return Pagination{}, err
	}
	perPage, err := positiveInt(q.Get("per_page"), defaultPerPage, "per_page")
	if err != nil {
		return Pagination{}, err
	}
	if perPage > MaxPerPage {
		perPage = MaxPerPage
	}
	return New(page, perPage), nil
}

func positiveInt(raw string, fallback int, name string) (int, error) {
	if raw == "" {
		return fallback, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 {
		return 0, fmt.Errorf("%w: %s must be a positive whole number", ErrInvalid, name)
	}
	return n, nil
}

// Map converts the items of a result, keeping its paging fields. Handlers use
// it to answer with response DTOs in the list envelope
// {data, total, page, per_page, total_pages}.
func Map[T, U any](r Result[T], f func(T) U) Result[U] {
	data := make([]U, len(r.Data))
	for i, item := range r.Data {
		data[i] = f(item)
	}
	return Result[U]{Data: data, Total: r.Total, Page: r.Page, PerPage: r.PerPage, TotalPages: r.TotalPages}
}
