### Added: continuous coverage collects info-level template results

- `vuln.templates` coverage now also runs an info pass (severity info only) on web services, next to the regular low to critical pass, so no template runs twice. It runs on the asset's first coverage, when its technologies or web surface change (at most once per 7 days) and otherwise every 30 days. Info matches are filed as info exposures, not findings.
- Console: Scoping > Settings has "Info checks" (on by default) and an interval of 7 to 90 days. The asset coverage list shows the info pass as its own capability, with its own state and gaps.
- The regular pass now sets its severities explicitly (low to critical). No migration; the setting is part of the scope settings.
