### Added: "Add to scope" on an inventory selection

- Select assets in the inventory and choose "Add to scope": each name or public address becomes an exact scope entry in one request (one re-authentication for the batch). URLs and services are covered by their host; private and internal targets (scan zones decide), repositories and cloud accounts are skipped and counted. The result says what was added, what was already in scope and what was refused. Needs `attack_surface:scope:write`. The inventory's Scope column and "In scope" pill are translated (en, vi).
