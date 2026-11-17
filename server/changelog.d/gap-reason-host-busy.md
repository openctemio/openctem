### Added: coverage-gap reason `host_busy`

- A sensor can report the coverage-gap reason `host_busy`: its own per-host connection limit stayed full for the whole wait, so part of the host was not scanned. The run ends partial and the host is not covered, but the reason says nothing about the target: it never holds findings, never counts against a proxy, and the console shows it as a sensor-side limit. The next run scans the host again.
- Docs: server/docs/architecture/asset-coverage.md, server/docs/architecture/held-findings.md
