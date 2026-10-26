### Changed: the e2e spec table merges without conflicts

- `web/e2e/README.md` uses git's union merge, so pull requests that each add a spec row no longer conflict. Spec number prefixes only order the files and need not be unique; don't renumber a spec to avoid a clash.
