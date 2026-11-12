### Security: scan approval rules read the effective criticality
- A rule on high-criticality assets now sees an asset raised by its business unit (and the unit's parents), a business service or the assets it is a control plane for, with the same resolver finding priority uses. Before, it read only the asset's own criticality, so such an asset escaped the rule.
- Deleted assets are no longer counted as scan targets in approval facts.
- Coverage candidates are ordered by criticality rank (critical, high, medium, low), not by the text of the level.
