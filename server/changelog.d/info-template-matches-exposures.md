### Added: info matches of template scans become exposures, counted per run

- The info-severity matches of nuclei (technology, login panels, TLS and header posture, WAF detection) are filed as info exposures of their assets instead of findings, one per template, matcher and URL, and re-seen on every scan. Each scan step run counts them ("N info observations" on the run map), so a scan that found no vulnerability still shows what it saw.
- Attack surface settings gain `info_matches_as_findings` (off by default) for organizations that want them as info findings.
- Migration 20261104162823 adds `scan_run_steps.info_observations` (constant default, no table rewrite).
