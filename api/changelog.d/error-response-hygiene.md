### Security: error responses never carry ids or internal error text

- Every error message the API writes is cleaned when it is written: SQL and driver errors, dial and DNS errors, file paths, Go runtime text and upstream bodies are replaced by the code's default message (the original is logged with the request id), and entity ids are cut out. Codes and request ids are unchanged.
- New `pkg/apierror` code registry with default messages, `FromCode` and `WithParams` (safe values only, under `details.params`), so clients choose their own words from the code.
- New CI gate `tools/lint/errleak` (shrink-only baseline) stops new code from putting `err.Error()`, a lower error's text or an id into a response message, a stored status or an audit message.
