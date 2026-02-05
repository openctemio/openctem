# REST API Improvements Roadmap

Based on industry best practices from GitHub, Stripe, and Twilio APIs.

## Current Score: 8.5/10

## Priority 1: Rate Limit Headers

Add rate limit information to response headers.

```go
// middleware/ratelimit.go - Add to response
w.Header().Set("X-RateLimit-Limit", strconv.Itoa(limit))
w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(resetTime.Unix(), 10))
```

## Priority 2: Enhanced Filtering

Support advanced filtering on list endpoints.

```go
// Example: GET /api/v1/assets?filter[status]=active&filter[type]=host&sort=-created_at

type ListAssetsInput struct {
    Page       int               `query:"page"`
    PerPage    int               `query:"per_page"`
    Filters    map[string]string `query:"filter"`
    Sort       string            `query:"sort"`      // e.g., "-created_at" for DESC
    Search     string            `query:"search"`    // full-text search
}
```

## Priority 3: Pagination Links

Add HATEOAS-style links to list responses.

```go
type ListResponse[T any] struct {
    Data       []T              `json:"data"`
    Pagination PaginationMeta   `json:"pagination"`
    Links      PaginationLinks  `json:"links,omitempty"`
}

type PaginationMeta struct {
    Total      int64 `json:"total"`
    Page       int   `json:"page"`
    PerPage    int   `json:"per_page"`
    TotalPages int   `json:"total_pages"`
}

type PaginationLinks struct {
    Self  string `json:"self"`
    First string `json:"first,omitempty"`
    Prev  string `json:"prev,omitempty"`
    Next  string `json:"next,omitempty"`
    Last  string `json:"last,omitempty"`
}
```

## Priority 4: Cursor-based Pagination (Optional)

For large datasets or real-time data, consider cursor-based pagination.

```go
type CursorListResponse[T any] struct {
    Data      []T    `json:"data"`
    HasMore   bool   `json:"has_more"`
    NextCursor string `json:"next_cursor,omitempty"`
    PrevCursor string `json:"prev_cursor,omitempty"`
}

// Usage: GET /api/v1/findings?cursor=eyJpZCI6MTIzfQ==&limit=20
```

## Priority 5: Idempotency Keys (For mutations)

Stripe-style idempotency for safe retries.

```go
// middleware/idempotency.go
func IdempotencyKey() func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            if r.Method == "POST" || r.Method == "PUT" || r.Method == "PATCH" {
                key := r.Header.Get("Idempotency-Key")
                if key != "" {
                    // Check if request with this key was already processed
                    // Return cached response if found
                }
            }
            next.ServeHTTP(w, r)
        })
    }
}
```

## Priority 6: ETag Support (For caching)

```go
// Add to GET handlers
etag := calculateETag(resource)
w.Header().Set("ETag", etag)

// Check If-None-Match
if r.Header.Get("If-None-Match") == etag {
    w.WriteHeader(http.StatusNotModified)
    return
}
```

## Priority 7: Deprecation Headers

For deprecated endpoints (like /auth/token):

```go
w.Header().Set("Deprecation", "true")
w.Header().Set("Sunset", "2025-06-01")
w.Header().Set("Link", `</api/v2/auth/login>; rel="successor-version"`)
```

## Implementation Order

1. **Week 1**: Rate limit headers (easy win, high visibility)
2. **Week 2**: Enhanced filtering with sort parameter
3. **Week 3**: Pagination links
4. **Week 4**: Idempotency keys for POST/PUT/PATCH
5. **Future**: Cursor pagination, ETag caching

## Example: Complete Response Format

```json
{
  "data": [
    {
      "id": "asset-123",
      "name": "prod-web-01",
      "type": "host",
      "status": "active",
      "created_at": "2024-01-15T10:30:00Z",
      "updated_at": "2024-01-20T14:45:00Z",
      "links": {
        "self": "/api/v1/assets/asset-123",
        "findings": "/api/v1/assets/asset-123/findings"
      }
    }
  ],
  "pagination": {
    "total": 150,
    "page": 1,
    "per_page": 20,
    "total_pages": 8
  },
  "links": {
    "self": "/api/v1/assets?page=1&per_page=20",
    "first": "/api/v1/assets?page=1&per_page=20",
    "next": "/api/v1/assets?page=2&per_page=20",
    "last": "/api/v1/assets?page=8&per_page=20"
  }
}
```

## References

- [GitHub REST API](https://docs.github.com/en/rest)
- [Stripe API](https://stripe.com/docs/api)
- [Twilio API](https://www.twilio.com/docs/usage/api)
- [JSON:API Specification](https://jsonapi.org/)
- [Microsoft REST API Guidelines](https://github.com/microsoft/api-guidelines)
