### Added: "Scope and scanning" on the asset overview

- The asset drawer's Overview says whether scans can reach the asset and why ("In scope through the scope entry *.example.com", "Not in scope: passive only …"), with the actions that change it: Scan now, Add to scope, Mark out of scope, and Confirm and allow scanning for a name that resolves only through a wildcard. Each action uses the existing endpoint and gate (`scans:write` and `scans:execute`; scope write; `assets:write`) and is hidden without the permission. "Why" opens the full ownership panel.
