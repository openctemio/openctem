### Added: the finding drawer says which dependency brings a vulnerable package in

- The Fix card of a dependency finding reads "Direct dependency" or "Transitive via express@4.17.1 → …" (long chains keep both ends; the full chain is in the tooltip).
- The lock file shows the package's line and links to it in the repository at the scanned commit when the repository URL is known.
