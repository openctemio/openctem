### Security: Findings export carries an allowlist of fields, follows the list's sort and is capped

- `GET|POST /findings/export` rows (CSV and NDJSON alike) carry only the 40 allowlisted columns. NDJSON used to
  carry the whole finding; evidence (snippets, scanner output, stack traces, attachments, data flow), fix code,
  descriptions, free-form metadata and secret details are no longer exported.
- The export follows the list's `sort` (it used to be id order) and reads one database snapshot.
- Unknown filter params are `400 INVALID_FILTER` instead of being ignored.
- At most 10,000 rows per export (was 100,000); `X-Export-Max-Rows` says so and the `X-Export-Truncated`
  trailer reports a cut. Narrow the filter for larger sets; background exports come later.
- One export per user across all API replicas (a database lock; was per process). The audit row now records the
  sort and the cap.
- **Upgrade note:** scripts that read NDJSON fields outside the allowlist, or exported more than 10,000 rows in
  one request, must adapt.
