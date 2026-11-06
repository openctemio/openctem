### Added: every finding a scan sends is accounted for on its receipt

- A receipt now counts what the producer sent (`received`, before any filter) and where each finding went beyond the action counts (`outcomes`): repeats merged, info matches filed as exposures, mitigated at the source, findings that named no asset of their segment, findings held by the tool's output contract, a refused reserved tool name, and the extra findings a multi-CVE finding became. Received + split always equals created + still detected + reopened + suppressed + failed + skipped + the other outcomes.
- The run page shows them under "Where the other findings went" (en, vi).
- Migration `receipt_outcomes` adds a jsonb column with a constant default to `ingest_receipts` and `ingest_receipt_tools` (no rewrite, no long lock).
