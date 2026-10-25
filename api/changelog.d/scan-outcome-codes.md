### Fixed: a scan step that did not cover every host says why in words

- A step that completed with hosts its sensor could not fully cover ends with code `COVERAGE_GAPS` (class `partial`), which the run page now explains instead of "this console does not describe it yet".
- The run map's step carries a structured `outcome` (hosts with their reason, and the unfinished, unreachable and skipped counts); the step panel lists each host with a translated reason and why (stopped answering, kept pushing back at the lowest rate, blocked) instead of the English summary string. The summary stays in `error_message` for API clients.
- Every coverage-gap reason, skipped-target reason, unreached reach class and failure class has en and vi text, checked by a test against the API's lists.
