### Added: tools show their trust and the tier the platform assigns them

- The tool view (`GET /api/v1/tools?include=availability`) reports, for each tool and each sensor that runs it:
  - `trust`: `builtin`, or `unverified` for a copy the sensor's operator installed;
  - `tier`: the tier the platform assigns a scan with the tool, from the tool contracts the tenant's sensors report (RFC-055 §5).
- The tool's trust is the lowest among its sensors, and its tier the highest.
- The workflow builder's palette, the Tools table and the tool detail show both with one shared badge. An operator-installed copy is flagged "Unverified · T2".
- A sensor whose grant ceiling is below the tool's assigned tier now counts as excluded (grant), the same rule dispatch applies.
- The view reads every sensor's current manifest in one tenant-scoped query. Another tenant's manifests never count.
