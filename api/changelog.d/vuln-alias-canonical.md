### Added: one finding per vulnerability across tools that name it differently

- A finding that names only an advisory id (GHSA, or an OSV id such as PYSEC- or GO-) is now keyed on the CVE the signed vulnerability feed ties it to, so a tool reporting `GHSA-…` and one reporting the CVE for the same package on the same asset give one finding. An advisory that leads to two CVEs fuses nothing, and a report's own ids never change another finding's key.
- A network or SCA finding that names several CVEs (for example a vendor advisory listing two) is one finding per CVE; the copy for the CVE it was keyed on keeps its key and triage.
- A finding stored under an advisory key takes the CVE key on its next sighting with its triage, tickets and history; when another finding already holds the CVE key, the two are linked as the same issue (rule `vuln_alias`), never merged.
- Migration `003348_vuln_id_aliases` (platform table filled by the bundle importer from the optional signed `vulnids.manifest.dsse.json`). The feed status shows `vulnids_version`, `vulnids_entries` and `vulnids_error`.
- **Upgrade note:** after the feed publishes its first alias map, run `refingerprint -vuln-aliases` (dry run) and `refingerprint -vuln-aliases -apply` in the API container to move findings that no scan reports again.
