### Changed: a retest tells a CDN or WAF block from the server refusing the request

- A retest answered by a CDN or WAF challenge or block page is now inconclusive with the reason `edge_blocked`, naming the vendor and pointing to allowing the scanner at the edge. It never counts as a fix.
- A 401 or 403 from the server itself on an exposure-class check (exposed page, panel, API docs, config or backup file, debug endpoint, listing) now confirms the fix with "access now denied by the server", once it is seen twice (two retests in a row, or one retest plus the reachability probe). Any other class of check stays inconclusive with "access denied: cannot confirm the fix".
- The retest history on the finding is a short list, one line per attempt, instead of one long sentence.
- Migration 003408 adds `edge_blocked` and `access_denied` to the retest history's allowed reason codes.
