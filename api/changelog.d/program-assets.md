### Added: bug-bounty program assets are kept apart from the organization's own

- Assets a bug-bounty program lists or covers are linked to it (`asset_program_links`, source programfeed, program-manual or program-import) and carry system tags the platform derives (`bug-bounty`, `source:…`, `platform:…`, `program:<platform>:<slug>`, `program-unattested`); no request can change them. RFC-065 §16.5.
- An asset the organization already had stays its own and only gains the link; an asset that came after the program and that no own scope entry covers is program-only. Dashboards and CTEM program metrics leave program-only assets and their findings out by default (`include_program_assets=true` includes them).
- The inventory gets a "Bug bounty" view (`program_assets=only|exclude`); tag filters also match system tags; the asset page shows a "Program target" badge with the program and whether its terms are accepted.
