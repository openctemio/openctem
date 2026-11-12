### Fixed: the port-less network finding takeover test runs on a real legacy row

- `TestNetworkFindingWithoutCVE_LegacyRowKeepsItsTriage` (red since the finding identity re-key) writes the legacy row as the previous release stored it; test-only, no behaviour change.
