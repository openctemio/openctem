### Added: a CI run can upload a tool's output file

- `POST /api/v1/ci/runs/{id}/results` also takes a file a tool wrote in any format the importers read (an SBOM, OSV scanner results, a DefectDojo export, a VEX document, ...) or a ZIP of them, detected from the content; CTIS stays the default. It goes through the same conversion and limits as the finding import.
- Everything is filed on the run's repository with the branch, commit and pull request of the verified token; findings the file puts on another asset are dropped and counted (`findings_dropped_out_of_scope`); VEX statements are stored on the repository's findings only and never close one.
