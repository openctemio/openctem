### Added: dependency findings say whether the package is direct and the chain that brings it in

- A dependency finding keeps the scanner's `is_direct` and `dependency_path` (CTIS; trivy through the CI runner or an uploaded trivy report): at most 32 package ids, replaced on each sighting.
- The finding detail returns them on `component` as `dependency_type` (`direct` or `transitive`) and `dependency_path`, with `manifest_line`, the package's line in the lock file.
- ctis is updated to the version whose trivy importer reports them.
