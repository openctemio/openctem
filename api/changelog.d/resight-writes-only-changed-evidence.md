### Changed: a re-seen finding is written once per ingest; unchanged scanner output and template provenance write nothing

- Storing a sighting's scanner output, CVSS vectors and template provenance now skips findings whose stored values already match, instead of stamping `scanner_output_at` / `template_seen_at` and rewriting the row each time. A rescan that changes nothing leaves one row version per re-seen finding (the sighting update) instead of up to three.
- `scanner_output_at` now means "the output last changed" and `template_seen_at` "the template provenance last changed".
