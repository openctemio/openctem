### Added: evidence by finding type, j/k navigation and shareable links in the finding drawer

- SAST findings show their data flow in the drawer: numbered source → steps → sink with file, line and code (six steps, the rest on the full page), and "Open the code" at the reported commit in GitLab, GitHub, Bitbucket or Azure DevOps.
- Secret findings show the masked value, the kind, whether the scanner verified it and where it is; the value itself is never shown (revealing stays on the full page, permission-gated and audited).
- DAST and EASM findings show the scanner's HTTP evidence (masked) in the drawer.
- `j` / `k` open the next / previous finding of the list while the drawer is open, and the open finding is kept in the address (`#finding=<id>`), so the link can be shared and a reload reopens it.
