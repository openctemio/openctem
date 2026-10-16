### Added: finding lifecycle definitions API (sub-statuses and lifecycle schemes)

- New routes `/api/v1/lifecycle-sub-statuses` and `/api/v1/lifecycles` (RFC-110). An organization defines
  sub-statuses (labels bound to one canonical status and, under a closed status, one closure reason) and
  lifecycle schemes with versions: draft (edited with `If-Match`), validate, publish, roll back. A scheme
  can only add constraints to the platform's status rules; nothing evaluates it yet.
- New permission `findings:lifecycles:write`, granted to owners and administrators (migration
  `002740_finding_lifecycles_permission`). Reading needs `findings:read`. Publishing needs a recent sign-in
  (step-up) and is audited.
- New plan limits `lifecycle_sub_statuses` (Free: 3) and `lifecycle_schemes` (Free: 0, Pro: 1).
