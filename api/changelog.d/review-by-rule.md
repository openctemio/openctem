### Added: review by rule for the attribution review queue

- `GET /api/v1/easm/candidates/suggestions` groups the pending review items
  into candidate scope rules: wildcards at each label level up to the
  registrable domain (`*.dev.example.com.vn`, `*.example.com.vn`; never a
  public suffix) and /24 or /48 address ranges (never shared, CDN or cloud
  provider space, which is listed for one-by-one review), with the items each
  covers, the items exclusions or rejections keep out, ownership hints and a
  strength (RFC-054 §6.7).
- `POST /api/v1/easm/candidates/rules/preview` shows exactly what an action
  would change; `POST /api/v1/easm/candidates/rules` applies it:
  `accept_rule` creates a scope entry through the normal path (guardrails,
  step-up, approvals, notification) and confirms the covered items once it is
  in effect; `accept_selected` confirms only the chosen items; `reject_rule`
  requests an exclusion and rejects the covered items. Every change is
  audited.
