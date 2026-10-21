### Fixed: a ticket mapping is no longer picked at random when the issue type is unknown
- When a caller names no issue type and a project has several published mappings, the built-in safe mapping is used instead of whichever mapping the list returned first. An explicit type still selects its own mapping (id first, then name, deterministically).
