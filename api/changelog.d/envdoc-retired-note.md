### Fixed: the environment variable reference shows what to do with a retired name that has no replacement

- `docs/configuration/environment-variables.md` printed "rename it to ``" for
  retired names without a replacement (such as `SCOPE_ACTIVE_PROOF`); it now
  prints the same note the API gives at startup. A replacement that contains
  `|` no longer breaks the table.
