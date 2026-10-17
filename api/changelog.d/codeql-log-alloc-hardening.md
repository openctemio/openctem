### Security: Sanitize request-derived log values and bound result-slice allocations
- Request-derived values and error text are passed through the log sanitizers before they are logged, so a crafted name or id cannot forge log lines.
- Result slices sized from a page size are now bounded by a constant capacity hint.
