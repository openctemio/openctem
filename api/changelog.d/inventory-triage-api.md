### Added: inventory triage filters, bulk "mark out of scope" and the undo of a decision

- `GET /assets` filters `scope_status` (`in_scope`, `not_covered`, `excluded`, `internal`), `discovered_by`, `discovery_technique`, `min_confidence`, `max_confidence` and `first_seen_after`; `with_triage=true` adds each row's attribution and the active-scan gate's answer (RFC-054 §15).
- `POST /scope/exclusions/bulk/preview` and `POST /scope/exclusions/bulk`: mark up to 200 names or rules out of scope at once, with a preview of the visible assets each would match; the undo is the existing bulk delete.
- `POST /easm/candidates/decisions` accepts `state: "automatic"`: forget a person's decision (the undo of "Not ours").
