### Security: the web API proxy re-encodes path segments

- The `/api/v1/*` proxy in the web app joined the decoded path segments as they were, so a `%3F` or `%23` inside a segment became a query string or fragment on the backend URL, and a `%25` was decoded twice. Each segment now has `%`, `?` and `#` percent-encoded again before the request is forwarded; every other character is forwarded as before. Traversal (`..`, `\`) was already refused.
