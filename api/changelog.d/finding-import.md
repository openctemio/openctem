### Added: import results exported by other tools

- `POST /api/v1/findings/import` and the Findings > Import results dialog take a file exported by another tool (Nessus, Qualys with its KnowledgeBase, CycloneDX, SPDX, OSV scanner results, CSAF, OpenVEX, DefectDojo Generic Findings) or a ZIP of them. The format is detected from the content; a preview parses and counts without writing, with problems and their line numbers and the source fields not recognized.
- The import runs with the uploader's rights: findings land only on assets in their data scope, and an import never auto-resolves anything.
- VEX documents are matched against the organization's findings by vulnerability id and package; a statement about components inside a product applies only to that product's findings. Statements are stored on the matched findings; a `not_affected` statement closes open, non-human findings only under `INGEST_VEX=enforce` and for an uploader with `findings:approve`.

### Security: the import treats every file as hostile

- Parsing is done by the ctis importers (no XML entities or external resources, size, depth and record limits, safe archive reading). The endpoint is rate limited per organization, has a body limit and a timeout, and every import and preview is audited.
