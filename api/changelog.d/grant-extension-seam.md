### Added: extension point for things that are off unless granted

- The core asks one entitlement answer for granted extras (`Addon`, `RequireAddon` with 403 `ADDON_NOT_LICENSED` / `ADDON_LICENSE_EXPIRED`, and installation notices for banners). The Community build registers no provider: nothing is granted, there are no notices, and no Community feature, limit or security control changes.
- A build's extension registers through `internal/extension`; `cmd/server/edition_ee.go` (build tag `ee`) is the only file that imports it. No migration, no licence code and no new setting in this repository.
