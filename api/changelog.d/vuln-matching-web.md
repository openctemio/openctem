### Added: Software tab, why-this-finding and vulnerability matching settings in the console

- Every asset drawer has a Software tab: products and versions, distribution builds, unrecognised names, last seen, and per product the CVEs that match it with severity, KEV, EPSS, confidence (likely or potential), the affected range, why the confidence was lowered, and whether it is a finding or below the policy; each CVE links to the asset's findings for it.
- A finding the vulnerability matcher created shows "Why this finding" (observed version, range, evidence, confidence) and "Version match" as what found it.
- Settings › Policies › Vulnerability matching (owners and admins): on/off, minimum confidence and severity, distribution builds, internet-facing only, muted products; saves are refused over a concurrent change.
