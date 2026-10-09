### Fixed: the approvals list names each finding

- Findings > Approvals showed the first characters of the finding id. The list (`GET /api/v1/approvals`) now returns `finding_title` for each approval, read within the organization, and the page shows the title linking to the finding.
