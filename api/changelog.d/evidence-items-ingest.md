### Added: tools push typed evidence (CTIS 1.6 evidence_items); imports keep the HTTP proof

- Ingest reads `finding.evidence_items` from any tool, the third-party tier included: `http_exchange`, `raw_text`, `command_output`, `file_excerpt`, `screenshot`, `curl`, and any other kind, kept as text. They are capped and masked by the platform like the nuclei properties before them, whatever the tool marked.
- The API pins ctis main: a nuclei, SARIF (`webRequest`/`webResponse`), HAR or ZAP file imported through `POST /api/v1/findings/import` now keeps each finding's request, response and reproduction command as evidence.
- nuclei masks `Authorization` and `Cookie` itself (`***`); those values stay masked and are not revealable.
