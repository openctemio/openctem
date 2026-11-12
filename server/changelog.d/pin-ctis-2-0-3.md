### Fixed: a Nessus compliance check that could not run is kept as an error

- The CTIS importer (v2.0.3) no longer folds a Nessus compliance result of ERROR into skipped: it stays kind `not_applicable` and carries `compliance_outcome: error` (or `skipped`), so an import shows which checks could not run. No migration and no operator step.
