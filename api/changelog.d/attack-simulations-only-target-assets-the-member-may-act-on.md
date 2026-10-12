### Security: attack simulations only target assets the member may act on

- Creating, updating and running an attack simulation now applies the scan
  act-scope rule to its target assets: an asset-id target must be a live
  asset of the organization that the acting member may act on, and a
  free-text target goes through the act-scope check. Anything else answers
  404. A run is re-checked, so a saved simulation stops running for a member
  who lost the asset. Before, any member with `validation:write` could point
  a live safe-check probe at an out-of-scope or another tenant's asset
  (research 21b H4, RFC-050 W3).
