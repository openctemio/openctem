### Added: scan approval rule tester

- `POST /api/v1/organization/settings/scan-governance/test` (owner or administrator) evaluates a proposed rule set against the organization's saved scans (at most 200) without saving it: the scans it would hold for approval, those only monitor rules catch, and how many scans each rule catches (RFC-073 §4.3).
