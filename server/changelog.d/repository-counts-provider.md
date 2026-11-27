### Fixed: repository finding tab count, provider label and last scan time for repositories made by CI

- The Findings tab on a repository page counts all findings of the list (as the section title does), not the 20 loaded on the first page.
- A repository with no stored provider no longer shows as GitHub: the provider is read from the repository's host (GitHub, GitLab, Bitbucket, Azure DevOps), and a repository on any other host shows a neutral "Git" label and icon.
- A CI run's report now sets the repository's "Last scan" with the findings commit (inside the run's own organization), so a repository scanned only by CI no longer shows "Last scan: Never".
- Docs: none (corrects existing pages and an existing timestamp; no new route, field or setting)
