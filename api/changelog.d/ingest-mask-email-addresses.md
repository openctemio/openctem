### Security: e-mail addresses in findings are masked at ingest

- Every tool's findings keep no e-mail address: before a report is stored, fingerprinted, quarantined or logged, the local part of every address in a finding's title, description, message, snippet, tags, remediation, properties, source extras and evidence becomes `***` and the domain is kept (`jane.doe@example.com` becomes `***@example.com`, URL-encoded addresses too). A finding's identifiers (id, asset ref, fingerprints, source refs) are left alone, and marked sensitive spans and match ranges move with the text.
- Evidence masking (`evidence.Mask`) masks them as well for every other writer (retests, uploads); they never reach the encrypted secret store.
- Stored findings are not rewritten by this change.
- A code finding whose snippet holds an address is keyed on the masked snippet from now on: such a finding is reported once more under its new key and the old one closes on the next covered scan.
