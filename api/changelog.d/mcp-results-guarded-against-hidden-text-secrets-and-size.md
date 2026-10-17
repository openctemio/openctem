### Security: MCP results are guarded against hidden text, secrets and oversize

- Every MCP tool result and prompt data message is cleaned before the AI
  assistant reads it: bidirectional, zero-width and Unicode tag characters
  (invisible text that can carry instructions) are removed, secrets (cloud
  keys, tokens, private keys, `password=` values) are redacted, each field is
  capped by kind and a result over 256 KB returns `result_too_large`.
  `safetext.Clean` now also strips tag characters, invisible math operators and
  U+180E, which hardens ticket text sent to Jira and GitHub as well.
- `explain_finding_priority` returns its text under `untrusted_data` like the
  other tools.
- The confirmation page for an assistant's write action shows cleaned text, and
  an assistant comment containing hidden characters is refused, so what the
  person approves is what is stored.
- Behaviour change: an API key or MCP connection can now make at most 60
  requests at once; the hourly rate is unchanged. Clients that burst above 60
  receive `429` and should pace requests.
- New tests keep write tools on an allowlist, keep the tool list free of tenant
  data, and assert that MCP can request but never approve.
