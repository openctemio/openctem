### Added: the http and https views of one page are linked as one issue

- A DAST or template check (nuclei and similar) that reports the same rule and method at the same host, path and parameter names over http and over https, on the default ports, is linked as the same issue (rule `dast_scheme`), not merged: each scheme stays its own finding with its own evidence and status. The earliest finding is the original; the dashboard counts the page once; the second view raises no second "new finding" notification while the original is open, unless it is more severe.
- The finding page names the `vuln_asset` and `dast_scheme` link reasons (English and Vietnamese).
- Migration 20261030065958 adds the key kind `dast_point` and the rule `dast_scheme` (constraint changes only). **Upgrade note:** run `refingerprint -links` (dry run first, then `-apply`) to link findings that already exist.
