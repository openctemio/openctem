### Fixed: the Exposures type pages cover the right findings and say when they fail

- The Vulnerabilities page now counts every finding source except SAST, IaC, secret and cloud posture, so network and host scans, containers, external attack surface and imports are no longer missing. Misconfigurations counts IaC and cloud posture findings. The web `FindingSource` type matches the API enum.
- "View N findings" opens the Findings list with the same sources and all states, so the list total equals N.
- A failed statistics request shows an error with retry on all four pages instead of "No data yet".
- Removed tiles and cards that were not about the page's findings (repositories with findings, assets by type on Code, asset coverage and priority fixes on Misconfigurations, repositories affected and remediation priority on Secrets). The misconfigurations chart has no outer labels and loads on demand.
- The four pages' text is translated (en, vi).
