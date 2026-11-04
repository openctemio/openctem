### Fixed: New scan adds the recorded addresses and uses the preview column
- The coverage level "Host, subdomains and their IPs" now reads the addresses an inventory name records under `ip_addresses` (and its older synonyms), so they are added to the scan instead of "no recorded addresses". The note tells apart "no names below the domain" from "names without a recorded address".
- The Targets step preview column lists the ready targets and what a wildcard or coverage level includes (inventory names below it, added addresses); the options use the full width.
- The Review step's run plan shows why a step is skipped (no tool provides its capability, tool off, no sensor) and that steps needing a skipped step are skipped too (`DEPENDENCY_SKIPPED`).
