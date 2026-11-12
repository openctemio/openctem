### Added: delta gating for heavy workflow stages

- With the workflow setting `delta_gating` (on in the EASM recon workflows), template scans, crawls, screenshots and service detection run only on assets that are new, changed or due since the previous run of the same scan. The rest are recorded `unchanged`. A run with nothing new finishes its heavy steps at once with "nothing new since the last run".
- A partial or failed step of the previous run never counts as done. Without a previous run every asset is scanned.
