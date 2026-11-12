### Added: Actionable and Known exploited quick views

- `GET /api/v1/findings/quick-views` adds two built-in views for the Findings board tabs: `actionable` (open P0 and P1 findings, `state=open&priority_class=P0,P1`) and `known_exploited` (open findings on the known exploited vulnerabilities list, `state=open&is_in_kev=true`).
- Like every quick view, each count is the total of `GET /findings?<params>` for the same caller (tenant, data scope and pentest membership applied), compiled in the same statement as the other views. They use only existing list filters and carry no informational filter. No migration.
