### Fixed: the CI/CD page explains access, break-glass and empty lists instead of dead-ending

- A developer who opens a pull request's gate link for a repository outside their access sees why: the run is not in their access, the PR comment lists what blocked it, and an administrator can grant access. Before, it said only "CI run not found".
- Empty pipeline and run lists no longer claim "No CI pipelines yet" to readers who cannot see the pipelines. A verdict filter that matches nothing says so. The empty pipeline list offers only "Connect a pipeline".
- After a break-glass, the console says to re-run the pipeline on that commit: its next run passes and the check turns green.
- The setup sections can be linked (`/ci-cd?tab=setup&section=feedback`). After installing the GitHub App, the callback returns to Pull request feedback.
- "GitHub App guide" is a link. The run list shows the verdict next to the repository, so it is visible on a phone. Pagination nouns and the Sensors page's CI runner strings are translated.
