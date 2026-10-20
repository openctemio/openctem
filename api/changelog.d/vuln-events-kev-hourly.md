### Added: vulnerability event log and hourly KEV refresh

- The platform records material vulnerability changes in a global log (`vuln_events`, migration `003114`): a new CVE with affected products, ranges that widened, a severity rise, a CISA KEV addition (with the ransomware flag), an EPSS crossing (0.1, 0.5) and a rejection. Description edits, CVSS moves inside a band and narrowed ranges are not recorded. The log holds public facts only, no organization data, and feeds the emerging-threat alerts (RFC-117).
- The first run after the upgrade records the current corpus, KEV catalog and EPSS bands and reports nothing.
- The KEV catalog is now refreshed every hour with a conditional request (an unchanged catalog costs a 304 and rewrites nothing), so a KEV addition reaches findings within the hour instead of within a day. EPSS stays daily.
