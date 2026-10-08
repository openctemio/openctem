### Changed: a repository opens at its asset URL

- The repository workspace (overview, branches and branch compare, findings by branch and scanner, scan settings) is shown at `/assets/{id}` for a repository asset, like every other asset; `/assets/repositories/{id}` is gone, with no redirect. Links from CI pipelines and the rest of the console use `/assets/{id}`.
- **Upgrade note:** bookmarks to `/assets/repositories/{id}` answer 404; use `/assets/{id}`.
