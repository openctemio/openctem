### Behaviour change: asset risk scores use a likelihood-impact model

- The default risk model is now risk = findings score × exposure factor ×
  criticality factor × (1 − compensating-control reduction). The worst
  severity tier sets the findings score with diminishing returns per extra
  finding (500 low findings stay below one high); a finding in CISA KEV, with
  EPSS ≥ 0.5 or a known exploit counts one severity up. Unknown exposure and
  "not rated" criticality are not treated as safe; a crown jewel counts as
  critical. An asset with no open finding scores 0.
- Organizations on the built-in settings (legacy or default preset) move to the
  new default preset; an organization that chose another preset keeps it and
  can switch under Settings > Risk scoring. Every asset is rescored after the
  migration (`asset_risk_model`).
- Compensating controls now lower the score, and linking, unlinking, failing
  or expiring a control rescores its assets.
- Business units and asset groups refresh their average risk score after every
  rescore of a member asset; a business unit's finding counts now count open
  findings only (they included resolved ones).

### Added: why an asset's risk score is what it is

- `GET /api/v1/assets/{id}/risk` returns the stored score, its level and
  freshness, the model's factors (findings per severity tier with exploitable
  counts, exposure, effective criticality, control reduction) and the five
  open findings that drive it. Permission `assets:read`, the asset's data
  scope applies (out of scope answers 404).
