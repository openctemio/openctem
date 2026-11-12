### Added: import a reconFTW results directory

- `POST /api/v1/findings/imports` now reads a ZIP that is a reconFTW results directory (detected from its layout) as one unit: subdomains, addresses, ports, live web services, URLs (as endpoints) and nuclei results are joined into one partial-coverage report. The answer lists the files skipped by policy (people and credential data under `osint/`, screenshots) and the files the importer does not know.
- Hosts the organization's scope does not cover are held as candidates for review and are never scanned; findings on them stay visible with the tag `candidate`. The scope verdict comes from the organization's scope entries, never from the target the file names.
- A recon directory never closes findings: `coverage=full` is refused for it, and a CI-run upload refuses it.
