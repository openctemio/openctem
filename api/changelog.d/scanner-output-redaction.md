### Security: credentials in scanner output are masked at ingest and on read

- Scanner output (plugin output, DAST responses) is passed through the shared secret redactor before it is stored: Authorization and bearer tokens, `Cookie` and `Set-Cookie` header values, key=value secrets, provider token shapes and private keys become a placeholder. No raw copy is kept.
- `GET /findings/{id}` masks rows stored before this change when it serves them, so existing data is covered without a migration.
- The shared redactor now also masks `Cookie` / `Set-Cookie` header values (affects ticket text and other callers).
- A secret finding's description is redacted before it is sent to the AI model.
