### Security: stored path exclusion prefixes are rewritten decoded

- Path exclusions stored with a percent-escape (`/files/My%20Docs`) are rewritten to the decoded form (`/files/My Docs`), the form new exclusions get on save and the one the sensor compares a request path with. The pattern changes with them.
- A row whose prefix does not decode cleanly is left as stored: an invalid escape, invalid UTF-8, a control character, an escaped `%`, a dot segment, or a `*` inside a segment. So is a row whose decoded pattern another exclusion of the tenant already holds. The platform still sends such rows as stored and decoded. Running the migration again changes nothing. Its down step is a no-op.
