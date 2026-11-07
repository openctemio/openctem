### Added: Nessus host inventory on import

- A credentialed `.nessus` import now records each host's installed packages (Software Enumeration (SSH), Windows Installed Software Enumeration), its application CPEs as technologies and software (so vulnerability matching finds CVEs from them), its listening sockets as services marked `observed_from` host or network with `bind_address` and `process`, and its SSH host key fingerprints. Compliance results keep their cross-framework references, sub-checks and check errors in the source data. A file exported without plugin details is flagged on the import result.
- ctis v2.0.2 also brings the nmap, testssl, ffuf, S3Scanner, arjun, line-list and CTIS import formats.

### Fixed: packages of a multi-host import land on their own host

- A dependency that names its asset (`asset_ref`) is stored on that asset only, and skipped when that asset was not stored; before, a file with several hosts put every package on one of them.
