### Changed: the asset header names its state and says whether scans can reach the asset

- The asset drawer's header shows the scan-scope answer next to the lifecycle state ("In scope", "Not in scope · passive only", "Excluded", "Not ours" …), the same answer the inventory's Scope column and the scan gate give. It used to appear only in the Details tab.
- Criticality, exposure and the network zone are named in the header ("Criticality: Medium", "Exposure: Public", "Zone: Internal"). The zone (the asset field `scope`: internal, external, cloud …) is not the scan scope; its tooltip says so. Without names, "Internal" next to "Public" read as a contradiction.
- The drawer's tabs, menu and the badge labels and descriptions are translated (en, vi).
